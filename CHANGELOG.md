# Changelog

All notable changes to the APCB Memory Mod Tool.

## [1.6.0] - 2025-02-17

### Added
- **Interactive CLI (DiskPart-style)** -- Run `modify` without `--target` to enter a nested REPL with per-entry control. Main menu, SPD submenu, and Screen submenu with context-sensitive prompts (e.g. `APCB [Steam Deck] SPD [Entry 3] >`).
- **Per-entry SPD editing in CLI** -- `SELECT`, `SET DENSITY`, `SET NAME`, `DESELECT` commands for individual SPD entries with full manufacturer prefix validation.
- **Screen replacement patching** -- New `SCREEN` submenu (CLI) and dropdown (GUI) for aftermarket screen support on Steam Deck LCD:
  - **DeckHD 1200p** -- IPS LCD, 1200x1920 @ 60Hz (16:10)
  - **DeckSight OLED** -- AMOLED, 1080x1920 @ 60/80Hz (16:9)
  - Replaces EDID block and tags `$BVDT$` version strings (same process as vendors)
- **CLI `--screen` flag** -- Batch mode screen patching: `--screen deckhd` or `--screen decksight`
- **CLI `--deckhd` shortcut** -- Convenience alias for `--screen deckhd`
- **No-args launch** -- Running `sd_apcb_tool.py` with no arguments prompts for file paths and enters interactive mode
- **`run.bat` launcher** -- Windows batch file for double-click launch (window stays open)
- **Windows transient window detection** -- Uses `GetConsoleProcessList` to detect double-clicked windows and pause before exit so output is readable
- **`?` help shortcut** -- Type `?` at any interactive prompt to show context-sensitive help
- **K3LK7K70BM density mapping** -- Samsung LPDDR5 16GB module now shows correct density instead of `?`

### Changed
- CLI `--target` is now optional for `modify` command (omit for interactive mode, include for batch mode)
- GUI: DeckHD checkbox replaced with screen replacement dropdown (None / DeckHD 1200p / DeckSight OLED)
- GUI: `patch_deckhd()` refactored to generic `patch_screen(data, screen_key)` using `SCREEN_PROFILES` dict
- README.md overhauled with full interactive CLI documentation, command tables, session walkthrough, and screen patching guide

### Technical Notes
- Interactive mode implemented as ~450 lines of new code: `InteractiveState` and `PendingEntryMod` dataclasses, command parser, display functions, and menu handlers
- `modify_bios_data()` ported from GUI to CLI for per-entry density and module name modification
- ANSI color output with `_C` class and Windows VT100 enablement via `_enable_ansi_colors()`
- All Unicode box-drawing characters replaced with ASCII for Windows cp1252 console compatibility
- `SCREEN_PROFILES` dict architecture supports adding new screens with just a new dict entry (EDID, mfr_id, version_tag, name, description)

## [1.5.0] - 2025-02-16

### Added
- **Patch all SPD entries by default** -- covers Micron, Samsung, SK Hynix, and all other manufacturers present in firmware. Fixes issue where only the first entry (typically Micron) was patched.
- **GUI: Per-entry checkboxes** -- scrollable "SPD Entries to Modify" section shows each entry with manufacturer, module name, density, and memory type. All checked by default with "Select All" toggle.
- **Per-entry verification** -- both CLI and GUI now verify each patched entry individually with per-entry status output

### Changed
- CLI default behavior: patches all SPD entries (was first-only). `--all-entries` flag kept for backward compatibility.
- CLI `--entry N` can still be used to patch specific entries only
- GUI verification output shows per-entry results instead of just the first entry

## [1.4.0] - 2025-02-15

### Added
- **64GB memory support** -- new `--target 64` option for ROG Ally and Ally X (SPD values: byte6=0xF5, byte12=0x49)
- **LPDDR5X SPD detection** -- recognizes `23 11 15 0E` magic alongside LPDDR5 `23 11 13 0E`
- 64GB radio button in GUI (greyed out for Steam Deck, enabled for Ally/Ally X)

## [1.3.0] - 2025-02-14

### Added
- **ASUS ROG Ally support** -- auto-detected via PSPG at offset 0x80, MEMG at 0xC0
- **ASUS ROG Ally X support** -- auto-detected via PSPG at offset 0x80, MEMG at 0xC8
- **Device auto-detection** from firmware contents (`detect_device()`) -- no filename dependency
- `--device` CLI flag to force device type: `auto`, `steam_deck`, `rog_ally`, `rog_ally_x`
- GUI: Signing checkbox automatically disabled for ROG Ally/Ally X (uses SPI programmer, not h2offt)
- GUI: File dialog defaults to "All files" (ROG firmware uses version-number extensions like `.342`, `.312`)
- GUI: Clear Log and Copy Log buttons
- SteamOS venv setup instructions in CLI error messages and GUI warnings

### Changed
- File dialog default changed from "BIOS Files" to "All files" first
- Warning label updated for SteamOS cryptography venv requirement

## [1.2.0] - 2025-02-13

### Added
- **Built-in PE Authenticode signing** (`--sign` flag) -- modified firmware can now be flashed directly via h2offt without any external signing tools
- Pure Python signing engine using the `cryptography` library (RSA-2048 / SHA-256)
- Generates a fresh self-signed certificate per signing operation (CN=SD APCB Tool)
- Handles full Authenticode workflow: strip existing signature -> compute PE hash -> build PKCS#7 -> attach WIN_CERTIFICATE
- GUI: "Sign firmware for h2offt" checkbox (enabled by default)
- GUI: Auto-detects `cryptography` library availability and shows status
- GUI: PE vs raw SPI dump detection with appropriate signing behavior
- Hardware-verified: h2offt on OLED Steam Deck accepts custom-signed firmware

### Changed
- CLI help text updated with signing examples and h2offt flash command
- GUI success dialog now shows appropriate flash instructions based on signing state
- Footer text simplified

### Technical Notes
- Signing adds ~1,456 bytes to the firmware file (WIN_CERTIFICATE with PKCS#7 blob)
- Layer 1 (_BIOSCER) signature from original firmware is preserved intact
- Layer 2 (PE Authenticode) is replaced with the new custom signature
- h2offt validates signature structure but not certificate identity -- any self-signed cert works

## [1.1.0] - 2025-02-12

### Added
- OLED (F7G) firmware support -- validated on F7G0005 and F7G0112
- `--magic` flag for optional APCB magic byte modification (0x41->0x51)
- Magic byte modification is now opt-in (not applied by default)
- `--all-entries` and `--entry N` flags for targeting specific SPD entries
- Round-trip verification: original -> 32GB -> restore produces byte-identical output
- Flashing documentation in tool help text

### Changed
- Default behavior was first SPD entry only (changed to all entries in v1.5.0)
- Platform scope expanded: "Steam Deck APCB Memory Mod Tool (LCD & OLED)"

## [1.0.0] - 2025-02-11

### Added
- Initial release
- CLI tool (`sd_apcb_tool.py`) with analyze and modify commands
- GUI tool (`sd_apcb_gui.py`) with dark theme
- APCB block scanning with MEMG/TOKN classification
- LPDDR5 SPD entry parsing with module name and manufacturer detection
- Automatic APCB checksum recalculation and verification
- 16GB stock and 32GB upgrade memory configurations
- Support for both raw SPI dumps and .fd firmware files
- Known module database (Micron, Samsung)
- Post-modification output verification
