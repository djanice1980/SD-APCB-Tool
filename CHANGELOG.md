# Changelog

All notable changes to the APCB Memory Mod Tool.

## [1.6.1] - 2025-02-19

### Fixed
- **3-layer firmware signing for h2offt** -- Steam Deck firmware has three integrity layers that all must be updated for h2offt to accept modified firmware. Previous versions only handled layer 3 (PE Authenticode). Analysis of DeckHD's firmware (CN="QA Certificate.") confirmed h2offt does not check certificate identity:
  - **`_IFLASH` flags bytes** -- All 6 `_IFLASH` structures in the firmware have a flags byte at offset `+0x0F` that controls h2offt's validation mode. DeckHD modifies 5 of 6 flags (verified across 3 firmware versions). Our code now applies the same per-structure transformations: `_IFLASH_DRV_IMG` (`0x80→0x88`), `_IFLASH_BIOSIMG` 2nd (`0x20→0x08`), `_IFLASH_INI_IMG` (`0x80→0x68`), `_IFLASH_BIOSCER` (`0x20→0x08`), `_IFLASH_BIOSCR2` (`0x20→0x08`). The 1st `_IFLASH_BIOSIMG` (`0x00`) is left unchanged.
  - **`_IFLASH_BIOSCER` (layer 1)** -- Internal hash at firmware body offset. Hash algorithm is proprietary and unknown; hash is now preserved from stock firmware instead of being recomputed (diagnostic testing confirmed no SHA-256 candidate matched DeckHD's stored hash).
  - **`_IFLASH_BIOSCR2` (layer 2)** -- Internal Authenticode signature (WIN_CERTIFICATE/PKCS#7) embedded in firmware body. Now re-signed with our self-signed certificate. Firmware body resized to maintain layout invariant: `SizeOfImage == SecDir VA == BIOSCR2 WC end` (zero gap between BIOSCR2 and PE cert). Uses the full BIOSCR2 slot size (cert offset to SizeOfImage) rather than the WIN_CERTIFICATE `dwLength` field, which correctly handles OLED firmware that has zero-padding between the BIOSCR2 WC and the PE cert. DeckHD follows the same zero-gap invariant.
  - **PE Security Directory (layer 3)** -- Standard PE Authenticode. Recomputed last so it covers the updated layers 1 and 2.
- **PE Authenticode signing rewritten** -- Fixed 4 bugs that caused h2offt to reject custom-signed firmware:
  - **messageDigest hash** -- Was hashing the full DER encoding (with SEQUENCE tag/length) instead of the content octets only per RFC 2315 Section 9.3. This produced a completely wrong hash, causing signature verification to fail.
  - **SpcSpOpusInfo encoding** -- Was putting an OID inside the structure; should be an empty SEQUENCE per Authenticode spec.
  - **SPC value EXPLICIT tag** -- Missing `[0] EXPLICIT` wrapper on `SpcAttributeTypeAndOptionalValue.value` field.
  - **PE hash algorithm** -- Replaced linear hash with proper section-based Authenticode hashing (headers, sections sorted by PointerToRawData, trailing data). Produces identical results for contiguous firmware but is now spec-compliant for all PE layouts.
- **PKCS#7 structure matched to DeckHD** -- ASN.1 comparison of our PKCS#7 output vs DeckHD's revealed structural encoding differences causing h2offt rejection:
  - **SPC_PE_IMAGE_DATA encoding** -- Our BIT STRING had 2 bytes (`00 00`), DeckHD uses 1 byte (`00`). Our SpcLink was 28 zero bytes, DeckHD uses an empty `[0] PRIMITIVE`. We also had an extra `[0] EXPLICIT` wrapper around the SPC value that DeckHD omits.
  - **Authenticated attributes** -- We included 4 attributes (contentType, signingTime, opusInfo, messageDigest) in arbitrary order. DeckHD uses only 3 (opusInfo, contentType, messageDigest — no signingTime), DER-sorted by raw byte value as required for SET OF encoding.
  - **BIOSCER hash preserved** -- Diagnostic testing of 15+ SHA-256 candidates (various regions, zeroing strategies) found zero matches with DeckHD's stored BIOSCER hash. The algorithm is proprietary, so we now preserve the original hash bytes instead of overwriting them.
- **Signing self-check** -- After signing, the tool re-computes the Authenticode hash on the output and verifies it matches, catching any future regressions.

### Technical Notes
- The v1.2.0 "hardware-verified" claim was a false positive: flashing the same BIOS version provided no visible way to confirm the flash actually took effect. Testing with a different version (F7G0110 onto F7G0112) confirmed the old signing never worked.
- Signing order of operations: strip old PE cert → generate RSA-2048 self-signed cert → set flags → preserve BIOSCER hash → re-sign BIOSCR2 → compute PE Authenticode hash → build PE PKCS#7 → append WIN_CERTIFICATE → PE checksum → self-check.
- `_find_iflash_structures()` scans for `_IFLASH_BIOSCER` and `_IFLASH_BIOSCR2` magic bytes. Only Steam Deck `.fd` files have these; ROG Ally firmware uses SPI flash (no signing needed).
- `_build_win_certificate()` extracted as helper for building 8-byte-aligned WIN_CERTIFICATE from PKCS#7 blob (used for both BIOSCR2 and PE cert).
- `_build_pkcs7()` extracted as reusable PKCS#7 builder (used for both BIOSCR2 and PE cert).
- Both CLI and GUI signing implementations updated (GUI has minified copy with identical 3-layer logic).
- The messageDigest bug alone was sufficient to cause rejection -- stripping the 2-byte SEQUENCE tag/length from the hash input produces a completely different SHA-256 digest.
- OLED stock firmware (F7G) has 16 bytes of zero padding between the BIOSCR2 WIN_CERTIFICATE and SizeOfImage. LCD stock (F7A) has no padding. The resize logic uses `len(data) - bioscr2_cert_off` (the full slot) instead of the WC `dwLength` to ensure both formats collapse to zero-gap after re-signing.

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
- ~~Hardware-verified: h2offt on OLED Steam Deck accepts custom-signed firmware~~ (corrected in v1.6.1 -- original signing had bugs, see v1.6.1 notes)

### Changed
- CLI help text updated with signing examples and h2offt flash command
- GUI success dialog now shows appropriate flash instructions based on signing state
- Footer text simplified

### Technical Notes
- Signing adds ~1,456 bytes to the firmware file (WIN_CERTIFICATE with PKCS#7 blob)
- Layer 1 (_BIOSCER) signature from original firmware is preserved intact
- Layer 2 (PE Authenticode) is replaced with the new custom signature
- h2offt validates signature structure but not certificate identity -- any self-signed cert works (confirmed in v1.6.1 after signing bugs were fixed)

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
