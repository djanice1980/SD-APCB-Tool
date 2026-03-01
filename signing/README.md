# SecureFlash Signing Research Tools

Research tools for investigating Insyde H2O firmware signing via CVE-2025-4275 (Hydroph0bia) certificate injection.

## Background

Steam Deck firmware uses Insyde H2O with PE Authenticode signing. The h2offt flash tool validates firmware signatures before flashing. CVE-2025-4275 revealed that the `SecureFlashCertData` NVRAM variable (used to store trusted signing certificates) is unprotected and can be written from the OS, allowing injection of custom certificates.

## Tools

### `secureflash_check.py` — NVRAM Vulnerability Scanner

Checks whether a device is vulnerable to CVE-2025-4275. Must run on the target device (Steam Deck / SteamOS) with root access.

```bash
sudo python3 secureflash_check.py
```

Checks:
- efivarfs access
- SecureFlash NVRAM variable status
- Write access test (uses throwaway variable, auto-cleaned)
- Firmware vendor/version info
- h2offt presence

### `secureflash_esl.py` — Key Pair + ESL Generator

Generates RSA-2048 signing materials for certificate injection. Can run on any system with Python 3.8+.

```bash
python3 secureflash_esl.py [--output-dir DIR] [--cn NAME] [--days N]
```

Produces:
- `signing_key.pem` — RSA-2048 private key
- `signing_cert.pem` — Self-signed X.509 certificate (PEM)
- `signing_cert.der` — Self-signed X.509 certificate (DER)
- `signing_cert.esl` — EFI_SIGNATURE_LIST blob (ready for NVRAM injection)

Uses the `cryptography` library if available, falls back to pure Python RSA.

## Requirements

- Python 3.8+
- `cryptography` library (optional, recommended for key generation speed)
- Root access on target device (for secureflash_check.py)
- Linux with efivarfs (SteamOS)

## References

- [CVE-2025-4275 (CERT/CC)](https://www.kb.cert.org/vuls/id/211341)
- [Hydroph0bia Part 1](https://coderush.me/hydroph0bia-part1/)
- [Hydroph0bia Part 2](https://coderush.me/hydroph0bia-part2/)
- [Hydroph0bia Part 3](https://coderush.me/hydroph0bia-part3/)
- [Hydroph0bia PoC](https://github.com/NikolajSchlej/Hydroph0bia)

## Status

**Phase 1: Research** — These are diagnostic tools to validate whether the approach is viable on Steam Deck before building a full signing pipeline.
