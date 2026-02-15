# CLAUDE.md

## Project Overview

SD-APCB-Tool is a Python tool for patching handheld gaming device BIOS firmware to support RAM upgrades (32GB/64GB). It modifies APCB (AMD Platform Configuration Block) SPD entries in firmware files. Includes both a CLI (`sd_apcb_tool.py`) and a Tkinter GUI (`sd_apcb_gui.py`).

**Supported devices:** Steam Deck (LCD & OLED), ASUS ROG Ally, ASUS ROG Ally X

## Tech Stack

- **Language:** Python 3.8+ (standard library only, `cryptography` optional for PE signing)
- **GUI:** Tkinter with custom dark theme
- **No build system / no package manager** — single-file scripts, run directly

## File Structure

```
sd_apcb_tool.py   # CLI tool — main engine (APCB scanning, modification, PE signing)
sd_apcb_gui.py    # GUI wrapper using Tkinter
README.md          # User documentation
CHANGELOG.md       # Version history
```

## Code Conventions

- **Functions:** `snake_case` (public), `_snake_case` (private/internal)
- **Constants:** `UPPER_SNAKE_CASE`, defined at module top
- **Classes:** `PascalCase`, use `@dataclass` for data structures
- **Type hints** used throughout (`List[APCBBlock]`, `Optional[Tuple]`, etc.)
- **CLI args:** `--kebab-case`
- Code sections separated by comment block headers
- Comprehensive docstrings on all major functions

## Key Architecture

- CLI tool is the core engine; GUI reimplements the same logic inline
- APCB blocks found by scanning for magic bytes (`APCB`/`QPCB`)
- SPD entries identified by two magics:
  - LPDDR5: `23 11 13 0E`
  - LPDDR5X: `23 11 15 0E`
- Modification changes two bytes per SPD entry: byte[6] (density) and byte[12] (config)
- Memory configurations: 16GB (0x95/0x02), 32GB (0xB5/0x0A), 64GB (0xF5/0x49)
- PE Authenticode signing is a pure-Python implementation (DER/PKCS#7/RSA-2048/SHA-256)
- Input files are never modified — output always written to a separate file
- **Device auto-detection** from firmware contents via `detect_device()`
  - Steam Deck: MEMG at offset 0x80
  - ROG Ally: PSPG at 0x80, MEMG at 0xC0
  - ROG Ally X: PSPG at 0x80, MEMG at 0xC8
- Device profiles in `DEVICE_PROFILES` dict control per-device behavior (`steam_deck`, `rog_ally`, `rog_ally_x`)

## Device-Specific Notes

| Device | Device Key | MEMG Offset | Signing | Stock RAM | Memory Targets | SPD Types | Notes |
|--------|-----------|-------------|---------|-----------|----------------|-----------|-------|
| Steam Deck | `steam_deck` | 0x80 | Supported (h2offt) | 16GB | 16/32GB | LPDDR5 | MEMG directly at offset 0x80 |
| ROG Ally | `rog_ally` | 0xC0 | Not supported | 16GB | 16/32/64GB | LPDDR5 + LPDDR5X | PSPG at 0x80, MEMG at 0xC0 |
| ROG Ally X | `rog_ally_x` | 0xC8 | Not supported | 24GB | 16/32/64GB | LPDDR5 + LPDDR5X | PSPG at 0x80, MEMG at 0xC8 |

## Safety Rules

- **Never modify the input file** — always require distinct input/output paths
- Verify APCB checksums before and after modification
- Re-scan output file to confirm correct byte values
- Only modify the first SPD entry by default (conservative, matches known-good mods)
- Signing failures fall back gracefully to unsigned output
- Round-trip safe: 16GB → 32GB → 16GB produces byte-identical output

## Common Commands

```bash
# Analyze a BIOS file (auto-detects device)
python sd_apcb_tool.py analyze <bios_file>

# Analyze with explicit device type
python sd_apcb_tool.py analyze <bios_file> --device rog_ally

# Modify for 32GB with signing (Steam Deck)
python sd_apcb_tool.py modify <input> <output> --target 32 --sign

# Modify for 32GB (ROG Ally, no signing)
python sd_apcb_tool.py modify <input> <output> --target 32

# Modify for 64GB (ROG Ally X, all entries)
python sd_apcb_tool.py modify <input> <output> --target 64 --all-entries

# Restore to 16GB
python sd_apcb_tool.py modify <input> <output> --target 16

# Run the GUI
python sd_apcb_gui.py
```
