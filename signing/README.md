# SecureFlash Signing & Flash Tools

Tools for firmware signing and flashing on Steam Deck via CVE-2025-4275 (Hydroph0bia) certificate injection.

## Background

Steam Deck firmware uses Insyde H2O with PE Authenticode signing. The h2offt flash tool validates firmware signatures before flashing. CVE-2025-4275 revealed that the `SecureFlashCertData` NVRAM variable (used to store trusted signing certificates) is unprotected and can be written from the OS, allowing injection of custom certificates.

## Tools

### `secureflash_flash.py` — Guided Flash Utility

**The main tool.** Interactive, guided firmware flashing for Steam Deck. Handles certificate injection and h2offt flashing in a step-by-step flow. Copy this alongside your signed `.fd` and `.esl` files to the Steam Deck.

```bash
# Auto-detect .fd and .esl files in current directory
sudo python3 secureflash_flash.py

# Specify files explicitly
sudo python3 secureflash_flash.py firmware.fd cert.esl

# Remove injected certificate from NVRAM (revert)
sudo python3 secureflash_flash.py --revert
```

What it does:
1. Pre-flight checks (root, efivarfs, h2offt, device detection)
2. Auto-detects `.fd` and `.esl` files in the current directory
3. Checks if the certificate is already in NVRAM (skips injection if so)
4. Injects certificate into NVRAM if needed (with confirmation)
5. Flashes firmware via h2offt (with confirmation + power warning)
6. h2offt auto-reboots the system on success

Options:
- `--revert` — Remove the injected certificate from NVRAM (no flash)
- `--h2offt PATH` — Override h2offt binary path
- `--skip-cert` — Skip certificate injection (assume already done)

### `secureflash_check.py` — NVRAM Vulnerability Scanner

Checks whether a device is vulnerable to CVE-2025-4275. Run this first to confirm your device is exploitable before attempting to flash.

```bash
sudo python3 secureflash_check.py
```

Checks:
- efivarfs access
- SecureFlash NVRAM variable status
- Write access test (uses throwaway variable, auto-cleaned)
- Firmware vendor/version info (detects Jupiter/LCD and Galileo/OLED)
- h2offt presence

### `secureflash_esl.py` — Key Pair + ESL Generator

Generates RSA-2048 signing materials for certificate injection. Can run on any system with Python 3.8+. Not needed if you use `sd_apcb_tool.py` to sign (it generates key + ESL automatically).

```bash
python3 secureflash_esl.py [--output-dir DIR] [--cn NAME] [--days N]
```

Produces:
- `signing_key.pem` — RSA-2048 private key
- `signing_cert.pem` — Self-signed X.509 certificate (PEM)
- `signing_cert.der` — Self-signed X.509 certificate (DER)
- `signing_cert.esl` — EFI_SIGNATURE_LIST blob (ready for NVRAM injection)

Uses the `cryptography` library if available, falls back to pure Python RSA.

## Typical Workflow

```
PC:         python sd_apcb_tool.py modify input.fd output.fd --target 32
              → output.fd + output_key.pem + output_cert.esl

Transfer:   Copy output.fd, output_cert.esl, and secureflash_flash.py to Steam Deck

Steam Deck: sudo python3 secureflash_flash.py
              → Detects files → Injects cert → Flashes → Auto-reboots
```

## Requirements

- Python 3.8+
- `cryptography` library (optional, for secureflash_esl.py key generation speed)
- Root access on target device (for all on-device tools)
- Linux with efivarfs (SteamOS)

## References

- [CVE-2025-4275 (CERT/CC)](https://www.kb.cert.org/vuls/id/211341)
- [Hydroph0bia Part 1](https://coderush.me/hydroph0bia-part1/)
- [Hydroph0bia Part 2](https://coderush.me/hydroph0bia-part2/)
- [Hydroph0bia Part 3](https://coderush.me/hydroph0bia-part3/)
- [Hydroph0bia PoC](https://github.com/NikolajSchlej/Hydroph0bia)
