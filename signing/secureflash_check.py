#!/usr/bin/env python3
"""
SecureFlash NVRAM Vulnerability Scanner
========================================
Checks whether an Insyde H2O device (e.g. Steam Deck) is vulnerable to
CVE-2025-4275 (Hydroph0bia) — certificate injection via the unprotected
SecureFlashCertData NVRAM variable.

This script must be run on the target device (Steam Deck running SteamOS/Linux)
with root privileges (sudo).

What it checks:
  1. efivarfs is mounted and accessible
  2. SecureFlashCertData NVRAM variable exists / is writable
  3. SecureFlashSetupMode trigger variable status
  4. Insyde firmware version info from DMI/SMBIOS
  5. h2offt flash tool presence
  6. Overall vulnerability assessment

Reference:
  CVE-2025-4275 — https://www.kb.cert.org/vuls/id/211341
  Hydroph0bia  — https://coderush.me/hydroph0bia-part1/
  PoC          — https://github.com/NikolajSchlej/Hydroph0bia

Usage:
  sudo python3 secureflash_check.py
"""

import os
import sys
import struct
import hashlib
import glob
from pathlib import Path

# ============================================================================
# Constants
# ============================================================================

# SecureFlash NVRAM variable GUID (from Hydroph0bia PoC)
SECUREFLASH_GUID = "382af2bb-ffff-abcd-aaee-cce099338877"

# Variable names
CERT_VAR_NAME = "SecureFlashCertData"
MODE_VAR_NAME = "SecureFlashSetupMode"

# Full efivarfs paths
EFIVARFS_PATH = "/sys/firmware/efi/efivars"
CERT_VAR_PATH = f"{EFIVARFS_PATH}/{CERT_VAR_NAME}-{SECUREFLASH_GUID}"
MODE_VAR_PATH = f"{EFIVARFS_PATH}/{MODE_VAR_NAME}-{SECUREFLASH_GUID}"

# UEFI variable attributes (bitmask)
EFI_VARIABLE_NON_VOLATILE = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020

# Standard attributes for non-volatile runtime variable
NV_BS_RT = (EFI_VARIABLE_NON_VOLATILE |
            EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS)

# EFI_CERT_X509_GUID for EFI_SIGNATURE_LIST
EFI_CERT_X509_GUID = bytes([
    0xa1, 0x59, 0xc0, 0xa5,  # Data1 (LE)
    0xe4, 0x94,              # Data2 (LE)
    0xa7, 0x4a,              # Data3 (LE)
    0x87, 0xb5,              # Data4[0:2] (BE)
    0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72  # Data4[2:8] (BE)
])

# h2offt known locations
H2OFFT_PATHS = [
    "/usr/share/jupiter_bios_updater/h2offt",
    "/usr/local/bin/h2offt",
    "/usr/bin/h2offt",
]

# DMI/SMBIOS paths
DMI_BIOS_VENDOR = "/sys/class/dmi/id/bios_vendor"
DMI_BIOS_VERSION = "/sys/class/dmi/id/bios_version"
DMI_BIOS_DATE = "/sys/class/dmi/id/bios_date"
DMI_BOARD_VENDOR = "/sys/class/dmi/id/board_vendor"
DMI_BOARD_NAME = "/sys/class/dmi/id/board_name"
DMI_PRODUCT_NAME = "/sys/class/dmi/id/product_name"


# ============================================================================
# Helper Functions
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


def _attrs_to_str(attrs: int) -> str:
    """Convert UEFI variable attributes to human-readable string."""
    flags = []
    if attrs & EFI_VARIABLE_NON_VOLATILE:
        flags.append("NV")
    if attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS:
        flags.append("BS")
    if attrs & EFI_VARIABLE_RUNTIME_ACCESS:
        flags.append("RT")
    if attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS:
        flags.append("AW")
    if attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS:
        flags.append("TSAW")
    return " | ".join(flags) if flags else f"0x{attrs:08X}"


def _decode_esl(data: bytes) -> list:
    """Decode an EFI_SIGNATURE_LIST structure.

    EFI_SIGNATURE_LIST layout (28 bytes):
      SignatureType    GUID (16 bytes)
      SignatureListSize  uint32
      SignatureHeaderSize  uint32
      SignatureSize    uint32
    Followed by SignatureHeader (variable) + N * EFI_SIGNATURE_DATA:
      SignatureOwner   GUID (16 bytes)
      SignatureData    (certificate DER bytes)
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

        # Parse signature entries
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

            # Try to extract CN from X.509 certificate
            if entry['is_x509']:
                cn = _extract_cn_from_der(cert_data)
                if cn:
                    entry['cn'] = cn

            entries.append(entry)
            entry_offset += sig_size

        offset += list_size

    return entries


def _extract_cn_from_der(cert_der: bytes) -> str:
    """Extract Common Name from a DER-encoded X.509 certificate.

    Minimal ASN.1 parser — walks the structure to find CN OID (2.5.4.3)
    and extracts the following UTF8String/PrintableString value.
    """
    cn_oid = bytes([0x55, 0x04, 0x03])  # OID 2.5.4.3 (commonName)

    pos = 0
    while pos < len(cert_der) - 5:
        # Look for OID tag (0x06) followed by length 3 and the CN OID bytes
        if (cert_der[pos] == 0x06 and
                cert_der[pos + 1] == 0x03 and
                cert_der[pos + 2:pos + 5] == cn_oid):
            # CN value follows: typically a UTF8String (0x0C) or PrintableString (0x13)
            val_pos = pos + 5
            if val_pos < len(cert_der):
                val_tag = cert_der[val_pos]
                if val_tag in (0x0C, 0x13, 0x16):  # UTF8, Printable, IA5
                    val_len = cert_der[val_pos + 1]
                    if val_len < 0x80:  # Short form length
                        val_start = val_pos + 2
                        try:
                            return cert_der[val_start:val_start + val_len].decode('utf-8')
                        except UnicodeDecodeError:
                            return cert_der[val_start:val_start + val_len].decode('latin-1')
        pos += 1
    return None


def _guid_to_str(guid_bytes: bytes) -> str:
    """Format 16-byte mixed-endian UEFI GUID as string."""
    if len(guid_bytes) != 16:
        return guid_bytes.hex()
    d1 = struct.unpack_from('<I', guid_bytes, 0)[0]
    d2 = struct.unpack_from('<H', guid_bytes, 4)[0]
    d3 = struct.unpack_from('<H', guid_bytes, 6)[0]
    d4 = guid_bytes[8:10].hex()
    d5 = guid_bytes[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


def _hex_dump(data: bytes, max_bytes: int = 64) -> str:
    """Format a hex dump of data."""
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i + 16]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:04X}: {hex_str:<48s} {ascii_str}")
    if len(data) > max_bytes:
        lines.append(f"  ... ({len(data) - max_bytes} more bytes)")
    return '\n'.join(lines)


# ============================================================================
# Check Functions
# ============================================================================

def check_efivarfs() -> dict:
    """Check 1: Verify efivarfs is mounted and accessible."""
    result = {
        'name': 'efivarfs Access',
        'status': 'UNKNOWN',
        'details': [],
    }

    if not os.path.isdir(EFIVARFS_PATH):
        result['status'] = 'FAIL'
        result['details'].append(f"efivarfs not found at {EFIVARFS_PATH}")
        result['details'].append("This device may not support UEFI or efivarfs is not mounted")
        result['details'].append("Try: mount -t efivarfs efivarfs /sys/firmware/efi/efivars")
        return result

    # Count variables
    try:
        var_files = os.listdir(EFIVARFS_PATH)
        num_vars = len(var_files)
        result['details'].append(f"efivarfs mounted at {EFIVARFS_PATH}")
        result['details'].append(f"Total UEFI variables: {num_vars}")

        # Check if we can read any variable
        if num_vars > 0:
            test_var = os.path.join(EFIVARFS_PATH, var_files[0])
            try:
                with open(test_var, 'rb') as f:
                    _ = f.read(4)
                result['details'].append("Read access: OK")
                result['status'] = 'PASS'
            except PermissionError:
                result['details'].append("Read access: DENIED (need sudo)")
                result['status'] = 'FAIL'
        else:
            result['details'].append("WARNING: No UEFI variables found")
            result['status'] = 'WARN'

    except PermissionError:
        result['status'] = 'FAIL'
        result['details'].append(f"Cannot list {EFIVARFS_PATH} (permission denied, need sudo)")

    return result


def check_secureflash_vars() -> dict:
    """Check 2: Look for SecureFlash NVRAM variables."""
    result = {
        'name': 'SecureFlash Variables',
        'status': 'UNKNOWN',
        'details': [],
    }

    # Search for any variables with the SecureFlash GUID
    pattern = os.path.join(EFIVARFS_PATH, f"*-{SECUREFLASH_GUID}")
    matches = glob.glob(pattern)

    if matches:
        result['details'].append(f"Found {len(matches)} SecureFlash variable(s):")
        for m in matches:
            var_name = os.path.basename(m).split('-')[0]
            attrs, data = _read_efivar(m)
            if attrs is not None:
                result['details'].append(f"  {var_name}: attrs={_attrs_to_str(attrs)}, size={len(data)} bytes")
            else:
                result['details'].append(f"  {var_name}: (cannot read)")
    else:
        result['details'].append("No existing SecureFlash variables found")
        result['details'].append("This is expected - they get created during injection")

    # Check SecureFlashCertData specifically
    attrs, data = _read_efivar(CERT_VAR_PATH)
    if attrs is not None:
        result['details'].append(f"\nSecureFlashCertData exists:")
        result['details'].append(f"  Attributes: {_attrs_to_str(attrs)} (0x{attrs:08X})")
        result['details'].append(f"  Data size: {len(data)} bytes")

        # Decode ESL
        entries = _decode_esl(data)
        if entries:
            result['details'].append(f"  Certificates in ESL: {len(entries)}")
            for i, entry in enumerate(entries):
                cn = entry.get('cn', '(unknown)')
                result['details'].append(f"    [{i}] CN={cn}, type={'X.509' if entry['is_x509'] else 'other'}, "
                                         f"size={entry['cert_size']} bytes")
                result['details'].append(f"        Owner: {_guid_to_str(entry['owner_guid'])}")
        else:
            result['details'].append("  Could not decode ESL structure")
            result['details'].append(f"  Raw hex:\n{_hex_dump(data)}")

        result['status'] = 'EXISTS'
    else:
        result['details'].append("SecureFlashCertData does not exist (expected for uninjected state)")

    # Check SecureFlashSetupMode
    attrs, data = _read_efivar(MODE_VAR_PATH)
    if attrs is not None:
        value = data[0] if len(data) >= 1 else None
        result['details'].append(f"\nSecureFlashSetupMode exists:")
        result['details'].append(f"  Attributes: {_attrs_to_str(attrs)} (0x{attrs:08X})")
        result['details'].append(f"  Value: {value} ({'TRIGGERED' if value == 1 else 'INACTIVE'})")
        result['status'] = 'EXISTS'
    else:
        result['details'].append("SecureFlashSetupMode does not exist (expected for uninjected state)")

    if result['status'] == 'UNKNOWN':
        result['status'] = 'CLEAN'

    return result


def check_write_access() -> dict:
    """Check 3: Test if we can write NVRAM variables (vulnerability test).

    Uses a throwaway test variable with the SecureFlash GUID.
    If write succeeds, the device is vulnerable to CVE-2025-4275.
    """
    result = {
        'name': 'NVRAM Write Access (CVE-2025-4275)',
        'status': 'UNKNOWN',
        'details': [],
    }

    test_var_name = "SecureFlashTestProbe"
    test_var_path = f"{EFIVARFS_PATH}/{test_var_name}-{SECUREFLASH_GUID}"
    test_data = b'\x07\x00\x00\x00\x42'  # attrs=NV|BS|RT, data=0x42

    result['details'].append(f"Testing write to: {test_var_name}-{SECUREFLASH_GUID}")

    try:
        # Attempt to write the test variable
        with open(test_var_path, 'wb') as f:
            f.write(test_data)

        result['details'].append("Write: SUCCESS")

        # Verify by reading back
        attrs, data = _read_efivar(test_var_path)
        if attrs is not None and data == b'\x42':
            result['details'].append("Read-back verification: MATCH")
        else:
            result['details'].append("Read-back verification: MISMATCH (unexpected)")

        # Clean up: remove the test variable
        try:
            # efivarfs requires removing the immutable flag before deletion
            import subprocess
            subprocess.run(['chattr', '-i', test_var_path],
                           capture_output=True, timeout=5)
            os.unlink(test_var_path)
            result['details'].append("Cleanup: removed test variable")
        except Exception as e:
            result['details'].append(f"Cleanup warning: could not remove test variable ({e})")
            result['details'].append(f"  You may want to manually remove: {test_var_path}")

        result['status'] = 'VULNERABLE'
        result['details'].append("")
        result['details'].append("** DEVICE IS VULNERABLE TO CVE-2025-4275 **")
        result['details'].append("SecureFlash NVRAM variables can be written from the OS.")
        result['details'].append("Certificate injection is possible.")

    except PermissionError:
        result['status'] = 'DENIED'
        result['details'].append("Write: PERMISSION DENIED")
        result['details'].append("Run this script with sudo/root privileges")

    except OSError as e:
        if e.errno == 1:  # EPERM — operation not permitted (variable locked)
            result['status'] = 'PATCHED'
            result['details'].append("Write: BLOCKED (EPERM)")
            result['details'].append("The firmware appears to have VariablePolicy locking enabled.")
            result['details'].append("This device may be patched against CVE-2025-4275.")
        elif e.errno == 22:  # EINVAL — invalid argument (bad attributes or GUID not allowed)
            result['status'] = 'BLOCKED'
            result['details'].append(f"Write: REJECTED (EINVAL - errno {e.errno})")
            result['details'].append("The firmware rejected the variable write.")
            result['details'].append("The GUID may be filtered or the variable format invalid.")
        else:
            result['status'] = 'ERROR'
            result['details'].append(f"Write: OS ERROR (errno {e.errno}: {e.strerror})")

    except Exception as e:
        result['status'] = 'ERROR'
        result['details'].append(f"Write: UNEXPECTED ERROR ({type(e).__name__}: {e})")

    return result


def check_firmware_info() -> dict:
    """Check 4: Read firmware/device info from DMI/SMBIOS."""
    result = {
        'name': 'Firmware Information',
        'status': 'INFO',
        'details': [],
    }

    vendor = _read_dmi_field(DMI_BIOS_VENDOR)
    version = _read_dmi_field(DMI_BIOS_VERSION)
    date = _read_dmi_field(DMI_BIOS_DATE)
    board_vendor = _read_dmi_field(DMI_BOARD_VENDOR)
    board_name = _read_dmi_field(DMI_BOARD_NAME)
    product = _read_dmi_field(DMI_PRODUCT_NAME)

    result['details'].append(f"Product:      {product}")
    result['details'].append(f"Board:        {board_vendor} {board_name}")
    result['details'].append(f"BIOS Vendor:  {vendor}")
    result['details'].append(f"BIOS Version: {version}")
    result['details'].append(f"BIOS Date:    {date}")

    # Check if it's Insyde firmware (multiple detection signals)
    # Valve reports BIOS vendor as "Valve" not "Insyde", so we use additional
    # indicators: h2offt presence, SecureFlash NVRAM variables, BIOS version prefix
    insyde_signals = []
    if 'insyde' in vendor.lower():
        insyde_signals.append("BIOS vendor contains 'Insyde'")
    if version.upper().startswith('F7'):
        insyde_signals.append(f"BIOS version '{version}' uses Insyde F7 naming")
    # Check for h2offt (strong Insyde indicator)
    for hp in H2OFFT_PATHS:
        if os.path.isfile(hp):
            insyde_signals.append(f"h2offt found at {hp}")
            break
    # Check for SecureFlash NVRAM variables (Insyde-specific)
    sf_pattern = os.path.join(EFIVARFS_PATH, f"*-{SECUREFLASH_GUID}")
    try:
        if glob.glob(sf_pattern):
            insyde_signals.append("SecureFlash NVRAM variables present")
    except OSError:
        pass

    if insyde_signals:
        result['details'].append("")
        result['details'].append("Firmware vendor: Insyde (H2O)")
        for sig in insyde_signals:
            result['details'].append(f"  Detected via: {sig}")
        result['details'].append("This firmware may be affected by CVE-2025-4275")
        result['is_insyde'] = True
    else:
        result['details'].append("")
        result['details'].append(f"Firmware vendor: {vendor}")
        result['details'].append("NOTE: CVE-2025-4275 only affects Insyde H2O firmware")
        result['is_insyde'] = False

    # Check for known device types
    # Jupiter = Steam Deck LCD, Galileo = Steam Deck OLED
    product_lower = product.lower()
    if 'jupiter' in product_lower or 'galileo' in product_lower or 'steam deck' in product_lower:
        variant = 'OLED (Galileo)' if 'galileo' in product_lower else 'LCD (Jupiter)'
        result['details'].append(f"Device type: Steam Deck {variant}")
        result['device'] = 'steam_deck'
    elif 'ally' in product_lower and 'rog' in product_lower:
        result['details'].append("Device type: ASUS ROG Ally")
        result['device'] = 'rog_ally'
    else:
        result['details'].append(f"Device type: Unknown ({product})")
        result['device'] = 'unknown'

    return result


def check_h2offt() -> dict:
    """Check 5: Look for h2offt flash tool."""
    result = {
        'name': 'h2offt Flash Tool',
        'status': 'UNKNOWN',
        'details': [],
    }

    found = None
    for path in H2OFFT_PATHS:
        if os.path.isfile(path):
            found = path
            break

    # Also search common locations
    if found is None:
        for search_dir in ['/usr/share', '/usr/local', '/opt']:
            if os.path.isdir(search_dir):
                for root, dirs, files in os.walk(search_dir):
                    for f in files:
                        if f == 'h2offt':
                            found = os.path.join(root, f)
                            break
                    if found:
                        break
            if found:
                break

    if found:
        result['status'] = 'FOUND'
        result['details'].append(f"h2offt found at: {found}")

        # Check if executable
        if os.access(found, os.X_OK):
            result['details'].append("Executable: YES")
        else:
            result['details'].append("Executable: NO (may need chmod +x)")

        # Get file size
        size = os.path.getsize(found)
        result['details'].append(f"Size: {size:,} bytes")

        # Check for associated config files
        h2offt_dir = os.path.dirname(found)
        config_files = []
        if os.path.isdir(h2offt_dir):
            for f in os.listdir(h2offt_dir):
                if f != 'h2offt':
                    config_files.append(f)
        if config_files:
            result['details'].append(f"Associated files in {h2offt_dir}:")
            for cf in sorted(config_files):
                result['details'].append(f"  {cf}")
    else:
        result['status'] = 'NOT_FOUND'
        result['details'].append("h2offt not found in standard locations")
        result['details'].append("Searched: " + ', '.join(H2OFFT_PATHS))

    return result


# ============================================================================
# Main
# ============================================================================

def main():
    """Run all diagnostic checks and print summary."""
    print("=" * 72)
    print("SecureFlash NVRAM Vulnerability Scanner")
    print("CVE-2025-4275 (Hydroph0bia) Diagnostic Tool")
    print("=" * 72)
    print()

    # Check if running on Linux
    if sys.platform != 'linux':
        print(f"ERROR: This script must run on Linux (SteamOS).")
        print(f"       Current platform: {sys.platform}")
        print(f"       Copy this script to your Steam Deck and run with: sudo python3 secureflash_check.py")
        sys.exit(1)

    # Check if running as root
    if os.geteuid() != 0:
        print("WARNING: Not running as root. Some checks may fail.")
        print("         Run with: sudo python3 secureflash_check.py")
        print()

    # Run all checks
    checks = [
        check_firmware_info,
        check_efivarfs,
        check_secureflash_vars,
        check_h2offt,
        check_write_access,
    ]

    results = []
    for check_fn in checks:
        print(f"--- {check_fn.__doc__.strip().split(chr(10))[0]} ---")
        result = check_fn()
        results.append(result)
        for detail in result['details']:
            print(f"  {detail}")
        print(f"  Status: [{result['status']}]")
        print()

    # Summary
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    fw_info = results[0]
    efivarfs = results[1]
    secvars = results[2]
    h2offt = results[3]
    write_test = results[4]

    # Determine overall assessment
    is_insyde = fw_info.get('is_insyde', False)
    device = fw_info.get('device', 'unknown')
    can_write = write_test['status'] == 'VULNERABLE'
    is_patched = write_test['status'] == 'PATCHED'
    efi_ok = efivarfs['status'] == 'PASS'
    has_h2offt = h2offt['status'] == 'FOUND'

    print(f"  Device:          {device}")
    print(f"  Insyde H2O:      {'Yes' if is_insyde else 'No'}")
    print(f"  efivarfs:        {'Accessible' if efi_ok else 'Not accessible'}")
    print(f"  h2offt:          {'Found' if has_h2offt else 'Not found'}")
    print(f"  NVRAM writable:  {'Yes' if can_write else 'No'}")
    print()

    if can_write and is_insyde:
        print("  ASSESSMENT: VULNERABLE")
        print("  This device is vulnerable to CVE-2025-4275.")
        print("  Certificate injection via SecureFlashCertData is possible.")
        print("  You can proceed with secureflash_esl.py to generate signing materials.")
    elif is_patched:
        print("  ASSESSMENT: PATCHED")
        print("  This device appears to have VariablePolicy protection.")
        print("  SecureFlash NVRAM variables are locked against OS-level writes.")
        print("  Certificate injection is NOT possible on this firmware version.")
    elif not efi_ok:
        print("  ASSESSMENT: UNABLE TO TEST")
        print("  Cannot access efivarfs. Run with sudo or verify UEFI boot mode.")
    elif not is_insyde:
        print("  ASSESSMENT: NOT APPLICABLE")
        print("  CVE-2025-4275 only affects Insyde H2O firmware.")
    else:
        print("  ASSESSMENT: INCONCLUSIVE")
        print("  Could not determine vulnerability status.")
        print("  Check the detailed output above for more information.")

    print()
    print("=" * 72)


if __name__ == '__main__':
    main()
