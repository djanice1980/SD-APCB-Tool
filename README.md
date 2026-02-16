# Steam Deck APCB Memory Mod Tool

Automated BIOS modification tool for upgrading Steam Deck LCD and OLED models from 16GB to 32GB RAM.

Patches the APCB (AMD Platform Configuration Block) SPD entries in Steam Deck firmware to recognize 32GB LPDDR5/LPDDR5X memory modules after a hardware RAM swap.

## Features

- **Analyze** — Scan any Steam Deck BIOS and display all APCB blocks, SPD entries, and memory configuration
- **Modify** — Patch SPD density bytes for 32GB memory recognition with automatic checksum recalculation
- **Sign** — Built-in PE Authenticode re-signing for h2offt software flash (no external tools required)
- **Restore** — Revert a modified BIOS back to stock 16GB configuration
- **Cross-platform** — Works on Windows, Linux, macOS, and Steam Deck itself
- **Both interfaces** — CLI tool for scripting/automation, GUI for point-and-click operation

## Quick Start

### CLI

```bash
# Analyze a BIOS file
python sd_apcb_tool.py analyze F7G0112_sign.fd

# Modify for 32GB + sign for h2offt (one command)
python sd_apcb_tool.py modify F7G0112_sign.fd F7G0112_32GB.fd --target 32 --sign

# Restore to stock 16GB
python sd_apcb_tool.py modify F7G0112_32GB.fd F7G0112_stock.fd --target 16 --sign
```

### GUI

```bash
python sd_apcb_gui.py
```

Open your BIOS file, select 32GB, click "Apply Modification". Signing is enabled by default.

## Requirements

- **Python 3.8+**
- **For signing** (optional, Steam Deck only): `pip install cryptography`
- Signing is needed for h2offt software flash. Not needed for SPI programmer flash.

### SteamOS Setup (Steam Deck)

SteamOS is Arch-based with a read-only filesystem — avoid `sudo pip install`.

```bash
# 1. Switch to Desktop Mode and open Konsole (Terminal)

# 2. Create a virtual environment with system site-packages
python -m venv --system-site-packages ~/sd-apcb-venv

# 3. Activate it
source ~/sd-apcb-venv/bin/activate

# 4. Upgrade pip and install cryptography
pip install -U pip
pip install cryptography

# 5. Run the tool (while venv is active)
python sd_apcb_tool.py modify <input> <output> --target 32 --sign
```

You must activate the venv (`source ~/sd-apcb-venv/bin/activate`) each time before running the tool with `--sign`.

## How It Works

### What it modifies

The tool patches two bytes in the first SPD (Serial Presence Detect) entry of each APCB MEMG block:

| Byte | Offset | Stock (16GB) | Modified (32GB) | Purpose |
|------|--------|-------------|-----------------|---------|
| byte[6] | SPD+6 | `0x95` | `0xB5` | Density / package type |
| byte[12] | SPD+12 | `0x02` | `0x0A` | Configuration |

After patching, the APCB block checksum is recalculated to maintain validity.

Steam Deck firmware contains two identical APCB MEMG blocks (primary + backup). Both are patched.

### Signing

Steam Deck firmware files (`.fd`) are PE executables with Authenticode signatures. The `h2offt` flash tool validates this signature before writing.

When you use `--sign` (CLI) or check the signing box (GUI), the tool:

1. Strips the existing Valve Authenticode signature
2. Generates a fresh self-signed RSA-2048 / SHA-256 certificate
3. Computes the PE Authenticode hash of the modified firmware
4. Builds a PKCS#7 SignedData structure and attaches it as a WIN_CERTIFICATE

This is implemented entirely in Python using the `cryptography` library — no external tools like `osslsigncode` or `signtool` needed.

> **Verified on hardware:** h2offt accepts custom-signed firmware. It validates internal signature consistency but does not check specific certificate identities or trust chains.

## Flashing

### Software flash (h2offt) — recommended for OLED

Use a signed output file:

```bash
# On the Steam Deck itself
sudo /usr/share/jupiter_bios_updater/h2offt F7G0112_32GB.fd
```

The Deck will reboot and apply the firmware update.

### SPI programmer (CH341A) — typical for LCD

For SPI flash, signing is not required. The output can be written directly:

```bash
# Modify without signing
python sd_apcb_tool.py modify dump.bin dump_32gb.bin --target 32

# Flash with your SPI programmer tool (e.g., flashrom)
flashrom -p ch341a_spi -w dump_32gb.bin
```

### Crisis recovery

InsydeH2O crisis mode bypasses signature verification entirely. Useful as a recovery path if something goes wrong.

## Supported Firmware

Validated on:

| Platform | Firmware | Status |
|----------|----------|--------|
| LCD | F7A0110 | ✅ Tested |
| LCD | F7A0113 | ✅ Tested |
| LCD | F7A0131 | ✅ Tested |
| OLED | F7G0005 | ✅ Tested |
| OLED | F7G0112 | ✅ Tested (hardware verified) |

Should work on any Steam Deck LCD or OLED firmware that uses the standard APCB/MEMG structure with LPDDR5 SPD entries.

## Supported Memory Modules

The mod has been confirmed working with:

- **Micron MT62F2G64D8AJ-023 WT:B** — 16GB/pkg LPDDR5X, 8-die (OLED)
- **Samsung K3LKCKC0BM** — 8GB/pkg LPDDR5X (LCD)

Any LPDDR5/LPDDR5X module with 16GB per package (32GB total) should work with these SPD values.

## CLI Reference

```
usage: sd_apcb_tool.py {analyze,modify} ...

Commands:
  analyze              Scan BIOS and display APCB/SPD information
  modify               Patch BIOS for target memory configuration

Modify options:
  --target {16,32}     Target memory size (required)
  --sign               Re-sign firmware for h2offt software flash
  --magic              Modify APCB magic byte (cosmetic, not required)
  --all-entries        Modify all SPD entries, not just the first
  --entry N            Modify specific entry index (0-based, repeatable)
```

## Project Structure

```
sd_apcb_tool.py    — CLI tool (analysis, modification, signing)
sd_apcb_gui.py     — GUI application (same engine, graphical interface)
README.md          — This file
CHANGELOG.md       — Version history
```

## Technical Details

### APCB Structure

The AMD Platform Configuration Block (APCB) contains memory training parameters stored in the BIOS. Each APCB block has:

- 32-byte header with magic (`APCB`), sizes, and checksum
- Content type marker at offset 0x80 (`MEMG` for memory, `TOKN` for tokens)
- For MEMG blocks: multiple SPD entries each starting with magic `23 11 13 0E` (LPDDR5)

### Signing Architecture

Steam Deck firmware has a two-layer signing structure:

- **Layer 1 (_BIOSCER)** — InsydeH2O internal signature embedded in the PE body. This tool preserves it from the original firmware.
- **Layer 2 (Authenticode)** — Standard PE WIN_CERTIFICATE at the security directory. This tool replaces it with a fresh signature.

h2offt validates Layer 2 for structural integrity but accepts any certificate identity.

## Safety

- The tool never modifies the input file — always writes to a separate output
- All APCB checksums are recalculated and verified after modification
- The output file is re-scanned to confirm correct byte values
- Signing failures fall back gracefully to unsigned output
- Stock configuration can be restored at any time with `--target 16`

## License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool modifies BIOS firmware. Incorrect use can brick your Steam Deck. Always:

1. **Back up your original BIOS** before any modification
2. **Verify the output** using the analyze command before flashing
3. **Have a recovery plan** (SPI programmer or crisis mode USB)
4. This tool is provided as-is with no warranty

## Acknowledgments

- The Steam Deck modding community for documenting the 32GB RAM upgrade process
- DeckHD for demonstrating that h2offt accepts non-Valve certificates
- InsydeH2O documentation for the APCB and signing architecture details
