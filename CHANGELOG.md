# Changelog

All notable changes to the APCB Memory Mod Tool.

## [1.7.1] - 2025-02-19

### Fixed
- **DMI import now works with stock `.fd` firmware files** -- Stock firmware ships with an empty `$DMI` store (all 0xFF after magic). `find_dmi_store()` now accepts blank stores when importing, so users can import DMI data directly into a stock `.fd` file without needing a second SPI dump.
- **GUI DMI export** fixed key references (`dmi_region_offset` → `dmi_store_offset`, `tables` → `records`)

### Improved
- CLI `dmi-export` now shows guidance: "Store this file safely" and "Use dmi-import to restore"
- CLI `dmi-import` now says "Flash this file via SPI programmer" and "UEFI settings recreate on first boot"
- GUI export/import messages improved with same guidance
- README DMI section rewritten with clear unbricking workflow, preventive backup guide, and supported file type table
- Error messages now clarify that both `.bin` and `.fd` files work as import targets

## [1.7.0] - 2025-02-19

### Added
- **DMI/SMBIOS backup & restore** -- New `dmi-export` and `dmi-import` CLI commands for brick recovery. Exports device identity (serial number, board serial, OEM calibration strings) from an SPI flash dump to JSON, and imports it back into a clean BIOS image. Automates the hex-editor recovery process documented at stanto.com.
  - Parses AMI DmiEdit `$DMI` store format (the actual format used in Steam Deck SPI flash)
  - Decodes SMBIOS Type 1 (System Serial), Type 2 (Board Serial), Type 11 (OEM Strings/calibration data)
  - Human-readable JSON export with raw hex for exact byte-level restoration
  - GUI: "Export DMI" and "Import DMI" buttons in the file toolbar
- **GUI two-column layout** -- Settings (file selection, target config, SPD entries, action buttons) on the left, log output on the right. Resizable divider between columns. Fixes issue where Apply/Analyze buttons were hidden below the visible window on smaller screens.
- **GUI dark theme combobox fix** -- Screen patch, density, and module prefix dropdowns now render correctly in dark theme on Windows (readonly and disabled states show proper dark background with light text)

### Removed
- **`--sign` CLI flag removed** -- PE Authenticode signing is no longer available as a user-facing feature. Hardware testing on OLED Steam Deck (F7G0110 onto F7G0112) conclusively proved that h2offt performs full cryptographic validation against Insyde's QA Certificate. Four test variants were flashed:
  - **T4 (unmodified stock):** Passed -- confirms the test methodology works
  - **T3 (only _IFLASH flags changed):** Failed -- even single-byte flag changes break validation
  - **T1 (re-signed with self-signed cert):** Failed -- h2offt rejects unknown certificate identities
  - **T2 (re-signed with DeckHD's QA cert, mismatched RSA key):** Failed -- h2offt verifies the actual RSA signature, not just cert identity
- **GUI signing checkbox removed** -- No longer shown in the interface
- **`supports_signing` removed from device profiles** -- All devices now show SPI programmer as the flash method
- **`cryptography` package no longer required** -- The tool runs on Python standard library only

### Changed
- **Default output extension is now `.bin`** -- since signing is removed and all flashing is via SPI programmer, output files default to `.bin` instead of preserving the input extension. File dialogs accept both `.bin` and `.fd` for input.
- GUI window default size: 1100x720 (was 920x800), minimum 900x550 (was 700x600)
- GUI mouse wheel scrolling scoped to SPD canvas only (was global, interfered with log scrolling)
- All devices (including Steam Deck) now show "Flash via SPI programmer" as the flash method
- Success messages say "Ready for SPI flash" instead of showing h2offt commands
- README updated: removed all signing references, added "Why no h2offt signing?" and "DMI Backup & Restore" sections
- SteamOS setup simplified (no venv or pip install needed)

### Technical Notes
- DMI functions (`find_dmi_store`, `parse_dmi_records`, `export_dmi`, `import_dmi`) added to both CLI and GUI files (following the existing single-file-script pattern)
- `DmiRecord` dataclass stores smbios_type, field_offset, flag (current/default), data bytes, and file offset per record
- Steam Deck firmware uses AMI DmiEdit `$DMI` store format (NOT standard SMBIOS entry points). Standard `_SM_`/`_SM3_`/`_DMI_` entry points don't exist in SPI flash — SMBIOS tables are generated at runtime by UEFI. The `$DMI` store at ~0x6A4000 holds the per-field overrides that DXE drivers read to populate runtime tables.
- DMI record format: type(1) + field_offset(1) + flag(1, 0x00=current, 0xFF=factory_default) + length(2, little-endian) + data(variable). Each field stored twice (current + default).
- DMI export requires raw SPI flash dump (16MB), not `.fd` update files
- All signing functions (`sign_firmware`, `_build_pkcs7`, `_update_iflash_flags`, etc.) are **preserved in the codebase** for future use if a QA.pfx becomes available. They work correctly -- the problem is the key, not the code.
- DeckHD succeeds with h2offt because they possess Insyde's QA private key (`QA.pfx`), used with `iEFIFlashSigner.exe`. This key is not publicly available.
- The QA Certificate: CN="QA Certificate.", RSA-2048, sha256WithRSA, self-signed, created 2012-04-13, valid until 2039-12-31.

## [1.6.1] - 2025-02-19

### Fixed
- **3-layer firmware signing for h2offt** -- Steam Deck firmware has three integrity layers that all must be updated for h2offt to accept modified firmware. Previous versions only handled layer 3 (PE Authenticode). Analysis of DeckHD's firmware revealed that it uses Insyde's QA Certificate (CN="QA Certificate."), a pre-trusted key in h2offt's validation chain:
  - **`_IFLASH` flags bytes** -- All 6 `_IFLASH` structures in the firmware have a flags byte at offset `+0x0F` that controls h2offt's validation mode. DeckHD modifies 5 of 6 flags (verified across 3 firmware versions). Our code now applies the same per-structure transformations: `_IFLASH_DRV_IMG` (`0x80→0x88`), `_IFLASH_BIOSIMG` 2nd (`0x20→0x08`), `_IFLASH_INI_IMG` (`0x80→0x68`), `_IFLASH_BIOSCER` (`0x20→0x08`), `_IFLASH_BIOSCR2` (`0x20→0x08`). The 1st `_IFLASH_BIOSIMG` (`0x00`) is left unchanged. Additionally, `_IFLASH_DRV_IMG` has a **second flag byte at `+0x13`** that DeckHD also sets to match the new `+0x0F` value (`0x68→0x88` on LCD, `0x78→0xA8` on OLED). Byte-level comparison confirmed this is the only non-signing difference between our output and DeckHD in `_IFLASH` headers.
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
- ~~Hardware-verified: h2offt on OLED Steam Deck accepts custom-signed firmware~~ (disproved -- h2offt requires a trusted certificate, not just structural correctness; see v1.6.1 notes)

### Changed
- CLI help text updated with signing examples and h2offt flash command
- GUI success dialog now shows appropriate flash instructions based on signing state
- Footer text simplified

### Technical Notes
- Signing adds ~1,456 bytes to the firmware file (WIN_CERTIFICATE with PKCS#7 blob)
- Layer 1 (_BIOSCER) signature from original firmware is preserved intact
- Layer 2 (PE Authenticode) is replaced with the new custom signature
- ~~h2offt validates signature structure but not certificate identity -- any self-signed cert works~~ (disproved -- h2offt appears to require a specific trusted certificate; DeckHD uses Insyde's QA Certificate)

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
