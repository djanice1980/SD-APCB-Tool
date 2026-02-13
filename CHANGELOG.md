# Changelog

All notable changes to the Steam Deck APCB Memory Mod Tool.

## [1.2.0] - 2025-02-13

### Added
- **Built-in PE Authenticode signing** (`--sign` flag) — modified firmware can now be flashed directly via h2offt without any external signing tools
- Pure Python signing engine using the `cryptography` library (RSA-2048 / SHA-256)
- Generates a fresh self-signed certificate per signing operation (CN=SD APCB Tool)
- Handles full Authenticode workflow: strip existing signature → compute PE hash → build PKCS#7 → attach WIN_CERTIFICATE
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
- h2offt validates signature structure but not certificate identity — any self-signed cert works

## [1.1.0] - 2025-02-12

### Added
- OLED (F7G) firmware support — validated on F7G0005 and F7G0112
- `--magic` flag for optional APCB magic byte modification (0x41→0x51)
- Magic byte modification is now opt-in (not applied by default)
- `--all-entries` and `--entry N` flags for targeting specific SPD entries
- Round-trip verification: original → 32GB → restore produces byte-identical output
- Flashing documentation in tool help text

### Changed
- Default behavior: only first SPD entry modified (matches LCD known-good mods)
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
