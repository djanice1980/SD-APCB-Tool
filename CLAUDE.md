# CLAUDE.md

## Project Overview

SD-APCB-Tool is a Python tool for patching Steam Deck BIOS firmware to support 32GB RAM upgrades. It modifies APCB (AMD Platform Configuration Block) SPD entries in Steam Deck LCD and OLED firmware files. Includes both a CLI (`sd_apcb_tool.py`) and a Tkinter GUI (`sd_apcb_gui.py`).

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
- SPD entries identified by magic `23 11 13 0E`, separated by `12 34 56 78`
- Modification changes two bytes per SPD entry: byte[6] (density) and byte[12] (config)
- PE Authenticode signing is a pure-Python implementation (DER/PKCS#7/RSA-2048/SHA-256)
- Input files are never modified — output always written to a separate file

## Safety Rules

- **Never modify the input file** — always require distinct input/output paths
- Verify APCB checksums before and after modification
- Re-scan output file to confirm correct byte values
- Only modify the first SPD entry by default (conservative, matches known-good mods)
- Signing failures fall back gracefully to unsigned output
- Round-trip safe: 16GB → 32GB → 16GB produces byte-identical output

## Common Commands

```bash
# Analyze a BIOS file
python sd_apcb_tool.py analyze <bios_file>

# Modify for 32GB with signing
python sd_apcb_tool.py modify <input> <output> --target 32 --sign

# Restore to 16GB
python sd_apcb_tool.py modify <input> <output> --target 16 --sign

# Run the GUI
python sd_apcb_gui.py
```
