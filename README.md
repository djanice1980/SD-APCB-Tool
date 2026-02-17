# APCB Memory Mod Tool

Automated BIOS modification tool for upgrading RAM on Steam Deck (LCD & OLED) and ASUS ROG Ally / Ally X handhelds.

Patches the APCB (AMD Platform Configuration Block) SPD entries in firmware to recognize upgraded LPDDR5/LPDDR5X memory modules (32GB or 64GB) after a hardware RAM swap.

## Features

- **Analyze** — Scan any supported BIOS and display all APCB blocks, SPD entries, and memory configuration
- **Modify** — Patch SPD density bytes for 32GB/64GB memory recognition with automatic checksum recalculation
- **Sign** — Built-in PE Authenticode re-signing for Steam Deck h2offt software flash (no external tools required)
- **Restore** — Revert a modified BIOS back to stock configuration
- **Multi-device** — Auto-detects Steam Deck, ROG Ally, and ROG Ally X from firmware contents
- **All chip brands** — Patches all SPD entries by default (Micron, Samsung, SK Hynix, etc.)
- **Cross-platform** — Works on Windows, Linux, macOS, and Steam Deck itself
- **Both interfaces** — CLI tool for scripting/automation, GUI with per-entry checkboxes

## Quick Start

### CLI

```bash
# Analyze a BIOS file (auto-detects device)
python sd_apcb_tool.py analyze F7G0112_sign.fd

# Steam Deck: Modify for 32GB + sign for h2offt
python sd_apcb_tool.py modify F7G0112_sign.fd F7G0112_32GB.fd --target 32 --sign

# ROG Ally / Ally X: Modify for 32GB (no signing needed)
python sd_apcb_tool.py modify RC71L.342 RC71L_32GB.342 --target 32

# ROG Ally X: Modify for 64GB
python sd_apcb_tool.py modify RC72LA.312 RC72LA_64GB.312 --target 64

# Restore to stock
python sd_apcb_tool.py modify modified.fd stock.fd --target 16 --sign
```

### GUI

```bash
python sd_apcb_gui.py
```

Open your BIOS file, select your target memory size, review the SPD entry checkboxes, and click "Apply Modification".

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

# or
python sd_apcb_gui.py
```

You must activate the venv (`source ~/sd-apcb-venv/bin/activate`) each time before running the tool.

## How It Works

### What it modifies

The tool patches two bytes in each SPD (Serial Presence Detect) entry of every APCB MEMG block:

| Byte | Offset | 16GB (stock) | 32GB | 64GB | Purpose |
|------|--------|-------------|------|------|---------|
| byte[6] | SPD+6 | `0x95` | `0xB5` | `0xF5` | Density / package type |
| byte[12] | SPD+12 | `0x02` | `0x0A` | `0x49` | Configuration |

All SPD entries are patched by default, covering every memory manufacturer (Micron, Samsung, SK Hynix, etc.). The GUI provides per-entry checkboxes if you want to be selective.

After patching, the APCB block checksum is recalculated to maintain validity.

Firmware typically contains two identical APCB MEMG blocks (primary + backup). Both are patched.

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

### Steam Deck — Software flash (h2offt)

Use a signed output file:

```bash
# On the Steam Deck itself
sudo /usr/share/jupiter_bios_updater/h2offt F7G0112_32GB.fd
```

The Deck will reboot and apply the firmware update.

### Steam Deck — SPI programmer (CH341A)

For SPI flash, signing is not required. The output can be written directly:

```bash
# Modify without signing
python sd_apcb_tool.py modify dump.bin dump_32gb.bin --target 32

# Flash with your SPI programmer tool (e.g., flashrom)
flashrom -p ch341a_spi -w dump_32gb.bin
```

### ROG Ally / Ally X — SPI programmer

ROG Ally devices require an SPI programmer (CH341A + SOIC8 clip) to flash modified firmware. ASUS uses UEFI capsule updates which validate signatures — signing is not supported for these devices.

### Crisis recovery

InsydeH2O crisis mode bypasses signature verification entirely. Useful as a recovery path if something goes wrong.

## Supported Devices & Firmware

| Device | Firmware | RAM Targets | Signing | Status |
|--------|----------|-------------|---------|--------|
| Steam Deck LCD | F7A0110, F7A0113, F7A0131 | 16/32GB | ✅ Supported | ✅ Tested |
| Steam Deck OLED | F7G0005, F7G0112 | 16/32GB | ✅ Supported | ✅ Hardware verified |
| ROG Ally | RC71L series | 16/32/64GB | N/A (SPI only) | ✅ Tested |
| ROG Ally X | RC72LA series | 16/32/64GB | N/A (SPI only) | ✅ Tested |

Should work on any firmware using the standard APCB/MEMG structure with LPDDR5/LPDDR5X SPD entries. Device type is auto-detected from firmware contents.

## Supported Memory Modules

The mod has been confirmed working with:

- **Micron MT62F2G64D8AJ-023 WT:B** — 16GB/pkg LPDDR5X, 8-die (Steam Deck OLED)
- **Samsung K3LKCKC0BM** — 8GB/pkg LPDDR5X (Steam Deck LCD)

Any LPDDR5/LPDDR5X module with the appropriate density should work with these SPD values.

## CLI Reference

```
usage: sd_apcb_tool.py {analyze,modify} ...

Commands:
  analyze              Scan BIOS and display APCB/SPD information
  modify               Patch BIOS for target memory configuration

Modify options:
  --target {16,32,64}  Target memory size (required; 64GB for Ally/Ally X only)
  --sign               Re-sign firmware for h2offt software flash (Steam Deck only)
  --device TYPE        Force device type: auto, steam_deck, rog_ally, rog_ally_x
  --magic              Modify APCB magic byte (cosmetic, not required)
  --all-entries        Modify all SPD entries (this is now the default)
  --entry N            Modify only specific entry index (0-based, repeatable)
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
- Content type marker: `MEMG` for memory (Steam Deck at offset 0x80; ROG Ally at 0xC0; Ally X at 0xC8), `TOKN` for tokens
- For MEMG blocks: multiple SPD entries each starting with magic `23 11 13 0E` (LPDDR5) or `23 11 15 0E` (LPDDR5X)

### Signing Architecture

Steam Deck firmware has a two-layer signing structure:

- **Layer 1 (_BIOSCER)** — InsydeH2O internal signature embedded in the PE body. This tool preserves it from the original firmware.
- **Layer 2 (Authenticode)** — Standard PE WIN_CERTIFICATE at the security directory. This tool replaces it with a fresh signature.

h2offt validates Layer 2 for structural integrity but accepts any certificate identity.

## Safety

- The tool never modifies the input file — always writes to a separate output
- All SPD entries patched by default for broad chip compatibility
- All APCB checksums are recalculated and verified after modification
- The output file is re-scanned to confirm correct byte values per entry
- Signing failures fall back gracefully to unsigned output
- Stock configuration can be restored at any time with `--target 16`

## License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool modifies BIOS firmware. Incorrect use can brick your device. Always:

1. **Back up your original BIOS** before any modification
2. **Verify the output** using the analyze command before flashing
3. **Have a recovery plan** (SPI programmer or crisis mode USB)
4. This tool is provided as-is with no warranty

## Acknowledgments

- The Steam Deck modding community for documenting the 32GB RAM upgrade process
- DeckHD for demonstrating that h2offt accepts non-Valve certificates
- InsydeH2O documentation for the APCB and signing architecture details
