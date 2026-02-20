# APCB Memory Mod Tool

Automated BIOS modification tool for upgrading RAM on Steam Deck (LCD & OLED) and ASUS ROG Ally / Ally X handhelds.

Patches the APCB (AMD Platform Configuration Block) SPD entries in firmware to recognize upgraded LPDDR5/LPDDR5X memory modules (32GB or 64GB) after a hardware RAM swap. Also supports screen replacement patching for Steam Deck LCD (DeckHD and DeckSight).

## Features

- **Analyze** -- Scan any supported BIOS and display all APCB blocks, SPD entries, and memory configuration
- **Interactive CLI** -- DiskPart-style nested menus for per-entry SPD editing, module renaming, and screen patching
- **Batch Mode** -- One-command patching with `--target` for scripting and automation
- **Per-Entry Control** -- Select individual SPD entries to modify with custom density and module names
- **Screen Patching** -- Replace EDID and version tag for aftermarket screens (DeckHD 1200p, DeckSight OLED)
- **Restore** -- Revert a modified BIOS back to stock configuration
- **Multi-device** -- Auto-detects Steam Deck, ROG Ally, and ROG Ally X from firmware contents
- **All Chip Brands** -- Patches all SPD entries by default (Micron, Samsung, SK Hynix, etc.)
- **DMI Backup & Restore** -- Export/import device identity (serial, UUID) for brick recovery
- **Cross-platform** -- Works on Windows, Linux, macOS, and Steam Deck itself
- **GUI** -- Two-column layout with per-entry checkboxes, density dropdowns, screen patch selector, DMI tools, and dark theme

## Quick Start

### CLI -- Interactive Mode

The recommended way to use the CLI. Run `modify` without `--target` to enter the interactive editor:

```bash
python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin
```

This opens a DiskPart-style REPL where you can inspect entries, select which ones to modify, set densities, rename modules, configure screen patches, and apply all changes at once.

You can also run with no arguments at all -- the tool will prompt you for file paths:

```bash
python sd_apcb_tool.py
```


### CLI -- Batch Mode

For scripting or one-shot modifications, use `--target` to skip interactive mode:

```bash
# Analyze a BIOS file (auto-detects device)
python sd_apcb_tool.py analyze my_bios_dump.bin

# Steam Deck: Modify for 32GB
python sd_apcb_tool.py modify my_bios_dump.bin my_bios_32GB.bin --target 32

# Steam Deck: Modify for 32GB + DeckHD screen patch
python sd_apcb_tool.py modify my_bios_dump.bin my_bios_32GB.bin --target 32 --screen deckhd

# ROG Ally / Ally X: Modify for 32GB
python sd_apcb_tool.py modify RC71L.342 RC71L_32GB.342 --target 32

# ROG Ally X: Modify for 64GB
python sd_apcb_tool.py modify RC72LA.312 RC72LA_64GB.312 --target 64

# Restore to stock
python sd_apcb_tool.py modify modified.bin stock.bin --target 16
```

### GUI

```bash
python sd_apcb_gui.py
```

Open your BIOS file, select your target memory size per entry via density dropdowns, optionally select a screen replacement from the dropdown, and click "Apply Modification".

## Interactive CLI Guide

The interactive mode uses nested menus inspired by Windows DiskPart. Type `HELP` or `?` at any prompt to see available commands.

### Main Menu

When you enter interactive mode, you'll see a summary of the loaded firmware:

```
  ========================================================================
    APCB Memory Configuration Tool v1.7.0 -- Interactive Mode
  ========================================================================

  Device:  Steam Deck (auto-detected)
  Input:   my_bios_dump.bin (16,777,216 bytes)
  Output:  my_bios_dump_modified.bin

  APCB Blocks: 6 total (2 MEMG, 4 TOKN)
  SPD Entries:  12 (12 LPDDR5)
  Current:     16GB/24GB (stock)

  Type HELP for available commands.

APCB [Steam Deck] >
```

Main menu commands:

| Command     | Description                                           |
|-------------|-------------------------------------------------------|
| `LIST`      | Show all SPD entries with current density and type     |
| `SPD`       | Enter the SPD entry editor submenu                     |
| `SCREEN`    | Enter the screen patch selector (Steam Deck LCD only)  |
| `MAGIC`     | Toggle APCB magic byte modification                    |
| `STATUS`    | Show all pending changes before applying               |
| `APPLY`     | Write all changes to the output file                   |
| `HELP` / `?`| Show available commands                               |
| `EXIT`      | Quit without writing                                   |

### SPD Submenu

Enter with `SPD` from the main menu. The prompt changes to show context:

```
APCB [Steam Deck] SPD >
```

After selecting an entry, it shows which one:

```
APCB [Steam Deck] SPD [Entry 3] >
```

SPD commands:

| Command                     | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `LIST`                      | Show all entries with pending changes highlighted          |
| `SELECT <N>`               | Select entry N (1-based) for modification                   |
| `SELECT ALL`               | Mark all entries for modification                           |
| `SET DENSITY <16/32/64>`   | Set target density for the selected entry                   |
| `SET NAME <prefix> <rest>` | Set module name (e.g. `SET NAME MT6 2F1G32D4DR`)           |
| `DESELECT`                 | Remove the selected entry from pending modifications        |
| `DESELECT ALL`             | Clear all pending modifications                             |
| `HELP` / `?`               | Show available commands and valid name prefixes             |
| `BACK`                     | Return to main menu                                         |

**Valid module name prefixes:**

| Prefix | Manufacturer          |
|--------|-----------------------|
| `MT6`  | Micron LPDDR5/5X      |
| `K3K`  | Samsung LPDDR5        |
| `K3L`  | Samsung LPDDR5X       |
| `H58`  | SK Hynix LPDDR5/5X    |
| `H9H`  | SK Hynix LPDDR5/5X    |
| `SEC`  | Samsung (alt)         |
| `SAM`  | Samsung (alt)         |

### Screen Submenu

Enter with `SCREEN` from the main menu (Steam Deck LCD only). The prompt changes:

```
APCB [Steam Deck] SCREEN >
```

Screen commands:

| Command          | Description                          |
|------------------|--------------------------------------|
| `LIST`           | Show available screen profiles       |
| `SELECT <key>`   | Select a screen profile              |
| `CLEAR`          | Remove screen patch selection        |
| `HELP` / `?`     | Show available commands              |
| `BACK`           | Return to main menu                  |

Available screen profiles:

| Key          | Screen             | Description                           |
|--------------|--------------------|---------------------------------------|
| `deckhd`     | DeckHD 1200p       | IPS LCD, 1200x1920 @ 60Hz (16:10)    |
| `decksight`  | DeckSight OLED     | AMOLED, 1080x1920 @ 60/80Hz (16:9)   |

### Example: Full Interactive Session

Here's a complete walkthrough modifying a Steam Deck BIOS for 32GB with a DeckHD screen patch:

```
$ python sd_apcb_tool.py modify my_bios_dump.bin my_bios_mod.bin

  [Welcome banner with device info...]

APCB [Steam Deck] > spd

  # | Type    | Module Name               | Density | Pending
  --+---------|---------------------------+---------+--------
  1 | LPDDR5  | MT62F768M32D2DR-031W      | 16GB    |
  2 | LPDDR5  | K3LKCKC0BM                | 16GB    |
  ...

APCB [Steam Deck] SPD > select all
  All 12 entries marked for 32GB modification.

APCB [Steam Deck] SPD > list

  # | Type    | Module Name               | Density | Pending
  --+---------|---------------------------+---------+--------
  1 | LPDDR5  | MT62F768M32D2DR-031W      | 16GB    | -> 32GB
  2 | LPDDR5  | K3LKCKC0BM                | 16GB    | -> 32GB
  ...

APCB [Steam Deck] SPD > select 1
  Selected entry 1: MT62F768M32D2DR-031W (LPDDR5, 16GB)

APCB [Steam Deck] SPD [Entry 1] > set name MT6 2F1G32D4DR-046WT
  Module name: MT62F1G32D4DR-046WT

APCB [Steam Deck] SPD [Entry 1] > back

APCB [Steam Deck] > screen

APCB [Steam Deck] SCREEN > list

  Available screen profiles:
    deckhd      DeckHD 1200p    IPS LCD, 1200x1920 @ 60Hz (16:10)
    decksight   DeckSight OLED  AMOLED, 1080x1920 @ 60/80Hz (16:9)

APCB [Steam Deck] SCREEN > select deckhd
  Selected: DeckHD 1200p

APCB [Steam Deck] SCREEN > back

APCB [Steam Deck] > status

  Pending SPD modifications:
    [1] MT62F1G32D4DR-046WT    16GB -> 32GB (name changed)
    [2] K3LKCKC0BM             16GB -> 32GB
    ...
  Screen patch: DeckHD 1200p

APCB [Steam Deck] > apply

  Ready to apply:
    12 SPD entry modification(s) (32GB)
    Screen: DeckHD 1200p
    Output: my_bios_mod.bin

  Proceed? [y/N]: y

  Applying DeckHD 1200p screen patch...
  Modifying 12 SPD entries...
  Writing output...
  Verifying...

  *** MODIFICATION SUCCESSFUL ***
  Output written to: my_bios_mod.bin
  Ready for SPI flash.
```

## Screen Replacement Patching

The tool supports patching Steam Deck LCD firmware for aftermarket screen replacements. This is the same process the screen vendors use -- replacing the EDID (Extended Display Identification Data) block and tagging the `$BVDT$` version string.

### How It Works

1. **EDID Replacement** -- Locates the stock BOE EDID block (identified by manufacturer ID) and replaces it with the aftermarket screen's EDID. This tells the system the display resolution, timing, and capabilities.
2. **Version Tag** -- Appends a tag (e.g. "DeckHD" or "DeckSight") to every `$BVDT$` version string in the firmware so you can identify a patched BIOS.
3. **Same Process as Vendors** -- The patching process is identical to what the screen vendors do.

### Supported Screens

| Screen        | Type   | Resolution       | Refresh    | Profile Key  |
|---------------|--------|------------------|------------|--------------|
| DeckHD 1200p  | IPS LCD | 1200x1920 (16:10)| 60Hz       | `deckhd`     |
| DeckSight     | AMOLED  | 1080x1920 (16:9) | 60/80Hz    | `decksight`  |

### CLI Usage

**Interactive mode** (recommended):

```bash
python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin
# Then: SCREEN > SELECT deckhd > BACK > APPLY
```

**Batch mode:**

```bash
# DeckHD screen patch + 32GB
python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin --target 32 --screen deckhd

# DeckSight screen patch + 32GB
python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin --target 32 --screen decksight

# Shortcut: --deckhd is an alias for --screen deckhd
python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin --target 32 --deckhd
```

### GUI Usage

1. Open a Steam Deck LCD BIOS file
2. The "Screen Replacement" dropdown becomes available (greyed out for non-Steam Deck devices)
3. Select "DeckHD 1200p" or "DeckSight OLED" from the dropdown (or "None" for no screen patch)
4. Configure memory settings as usual
5. Click "Apply Modification"

## DMI Backup & Restore

When a Steam Deck is bricked and recovered with a clean BIOS image via SPI programmer, the device-specific identity data (serial number, board info, calibration data) is lost. This tool automates the recovery process -- export DMI from your dump, import it into a clean firmware, and flash.

### Unbricking Your Device

```bash
# Step 1: Export DMI from your SPI flash dump (works on bricked or working dumps)
python sd_apcb_tool.py dmi-export my_spi_dump.bin my_dmi_backup.json

# Step 2: Import DMI into a stock firmware file (.fd or .bin)
python sd_apcb_tool.py dmi-import F7G0112_sign.fd restored.bin my_dmi_backup.json

# Step 3: Flash the restored firmware via SPI programmer
flashrom -p ch341a_spi -w restored.bin
```

### Preventive Backup (Before You Need It)

If your device is still working, back up your DMI data now:

```bash
# Dump your SPI flash (16MB)
flashrom -p ch341a_spi -r my_backup.bin

# Export DMI to a JSON file -- store this safely!
python sd_apcb_tool.py dmi-export my_backup.bin my_dmi_backup.json
```

### GUI Usage

**Export:** Open your SPI flash dump → click **"Export DMI"** → save the JSON file safely

**Import:** Open the target firmware (stock `.fd` or dump `.bin`) → click **"Import DMI"** → select the JSON → save the output

### What Gets Restored

- **System serial number** -- needed for Steam/Valve account association
- **Board serial number** -- hardware identifier
- **OEM calibration strings** -- display and joystick calibration data

### What Rebuilds Automatically

UEFI settings (boot order, Secure Boot state, etc.) are stored in NVRAM, which recreates with defaults on first boot. Wi-Fi and Bluetooth re-pair on first connection. You don't need to worry about these.

### Supported Target Files

| File Type | Export From | Import Into |
|-----------|-----------|-------------|
| Raw SPI dump (`.bin`, 16MB) | ✅ | ✅ |
| Firmware update (`.fd`) | ❌ (no DMI data) | ✅ (blank $DMI store) |

Stock `.fd` files ship with an empty `$DMI` store -- the tool writes your DMI data into it.

## Requirements

- **Python 3.8+** (standard library only, no additional packages needed)

### SteamOS Setup (Steam Deck)

SteamOS is Arch-based with a read-only filesystem. Switch to Desktop Mode and open Konsole (Terminal):

```bash
# Run the tool directly -- no venv or pip install needed
python sd_apcb_tool.py modify <input> <output> --target 32

# or
python sd_apcb_gui.py
```

### Windows

No special setup required. Run from PowerShell or Command Prompt:

```powershell
python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin
```


## How It Works

### What It Modifies

The tool patches two bytes in each SPD (Serial Presence Detect) entry of every APCB MEMG block:

| Byte | Offset | 16GB (stock) | 32GB | 64GB | Purpose |
|------|--------|-------------|------|------|---------|
| byte[6] | SPD+6 | `0x95` | `0xB5` | `0xF5` | Density / package type |
| byte[12] | SPD+12 | `0x02` | `0x0A` | `0x49` | Configuration |

All SPD entries are patched by default, covering every memory manufacturer (Micron, Samsung, SK Hynix, etc.). Both the CLI (interactive and batch) and GUI provide per-entry control if you want to be selective.

After patching, the APCB block checksum is recalculated to maintain validity.

Firmware typically contains two identical APCB MEMG blocks (primary + backup). Both are patched.

### Why no h2offt signing?

Steam Deck firmware files (`.fd`) are PE executables with Authenticode signatures. The `h2offt` flash tool performs full cryptographic validation -- it verifies the RSA signature against Insyde's QA Certificate (CN="QA Certificate."), a pre-trusted key in h2offt's validation chain. Hardware testing confirmed that even single-byte changes to the firmware break validation without the QA private key (`QA.pfx`). Self-signed certificates are rejected regardless of structural correctness. DeckHD succeeds because they possess this key; it is not publicly available.

## Flashing

### Steam Deck -- SPI programmer (CH341A)

Steam Deck requires an SPI programmer to flash modified firmware (h2offt rejects unsigned modifications):

```bash
# Modify the BIOS
python sd_apcb_tool.py modify dump.bin dump_32gb.bin --target 32

# Flash with your SPI programmer tool (e.g., flashrom)
flashrom -p ch341a_spi -w dump_32gb.bin
```

### ROG Ally / Ally X -- SPI programmer

ROG Ally devices also require an SPI programmer (CH341A + SOIC8 clip) to flash modified firmware.

## Supported Devices & Firmware

| Device | Firmware | RAM Targets | Screen Patches | Flash Method | Status |
|--------|----------|-------------|----------------|--------------|--------|
| Steam Deck LCD | F7A0110, F7A0113, F7A0131 | 16/32GB | DeckHD, DeckSight | SPI programmer | Tested |
| Steam Deck OLED | F7G0005, F7G0112 | 16/32GB | -- | SPI programmer | Tested |
| ROG Ally | RC71L series | 16/32/64GB | -- | SPI programmer | Tested |
| ROG Ally X | RC72LA series | 16/32/64GB | -- | SPI programmer | Tested |

Should work on any firmware using the standard APCB/MEMG structure with LPDDR5/LPDDR5X SPD entries. Device type is auto-detected from firmware contents.

## Supported Memory Modules

The mod has been confirmed working with:

- **Micron MT62F2G64D8AJ-023 WT:B** -- 16GB/pkg LPDDR5X, 8-die (Steam Deck OLED)
- **Samsung K3LKCKC0BM** -- 8GB/pkg LPDDR5X (Steam Deck LCD)

Any LPDDR5/LPDDR5X module with the appropriate density should work with these SPD values.

## CLI Reference

### Commands

```
usage: sd_apcb_tool.py {analyze,modify,dmi-export,dmi-import} ...

Commands:
  analyze              Scan BIOS and display APCB/SPD information
  modify               Patch BIOS for target memory configuration
  dmi-export           Export DMI/SMBIOS data to JSON file (brick recovery)
  dmi-import           Import DMI/SMBIOS data from JSON into firmware
  (no command)         Prompt for file paths and enter interactive mode
```

### Analyze Options

```
  bios_file            BIOS file to analyze
  --device TYPE        Force device type: auto, steam_deck, rog_ally, rog_ally_x
```

### Modify Options

```
  bios_in              Input BIOS file
  bios_out             Output BIOS file (must be different from input)
  --target {16,32,64}  Target memory size in GB (omit for interactive mode)
  --screen PROFILE     Apply screen replacement patch: deckhd, decksight (Steam Deck LCD only)
  --deckhd             Shortcut for --screen deckhd
  --device TYPE        Force device type: auto, steam_deck, rog_ally, rog_ally_x
  --magic              Modify APCB magic byte (cosmetic, not required)
  --all-entries        Modify all SPD entries (this is now the default)
  --entry N            Modify only specific entry index (0-based, repeatable)
```

### DMI Export Options

```
  bios_file            BIOS/firmware file to read DMI from
  output_json          Output JSON file for DMI data
  --device TYPE        Force device type: auto, steam_deck, rog_ally, rog_ally_x
```

### DMI Import Options

```
  bios_in              Input BIOS/firmware file (clean image)
  bios_out             Output BIOS file with DMI data restored
  dmi_json             DMI JSON file (from dmi-export)
  --device TYPE        Force device type: auto, steam_deck, rog_ally, rog_ally_x
```

### Behavior

- **With `--target`**: Batch mode. Patches all entries (or those specified by `--entry`) and writes output immediately.
- **Without `--target`**: Interactive mode. Opens the DiskPart-style REPL for per-entry control.
- **With no subcommand**: Prompts for input/output file paths, then enters interactive mode.

## GUI Reference

The GUI (`sd_apcb_gui.py`) provides the same capabilities as the CLI with a graphical interface:

- **File Selection** -- Browse for input BIOS file, auto-generates output filename
- **Device Detection** -- Auto-detects device type and displays it
- **Memory Target** -- Radio buttons for 16GB/32GB/64GB (device-appropriate options enabled)
- **SPD Entry List** -- Scrollable list with per-entry checkboxes, density dropdowns, and editable module names
- **Screen Replacement** -- Dropdown selector: None, DeckHD 1200p, DeckSight OLED (enabled for Steam Deck LCD only)
- **DMI Export/Import** -- Backup and restore device identity (serial, UUID) for brick recovery
- **Select All** -- Toggle all SPD entry checkboxes on/off
- **Two-Column Layout** -- Settings on the left, log output on the right (resizable divider)
- **Log Output** -- Scrollable log with Clear and Copy buttons

## Project Structure

```
sd_apcb_tool.py    -- CLI tool (analysis, modification, interactive editor)
sd_apcb_gui.py     -- GUI application (same engine, graphical interface)
README.md          -- This file
CHANGELOG.md       -- Version history
```

## Technical Details

### APCB Structure

The AMD Platform Configuration Block (APCB) contains memory training parameters stored in the BIOS. Each APCB block has:

- 32-byte header with magic (`APCB`), sizes, and checksum
- Content type marker: `MEMG` for memory (Steam Deck at offset 0x80; ROG Ally at 0xC0; Ally X at 0xC8), `TOKN` for tokens
- For MEMG blocks: multiple SPD entries each starting with magic `23 11 13 0E` (LPDDR5) or `23 11 15 0E` (LPDDR5X)

### Screen Patch Architecture

Screen replacement patching modifies two things in the firmware:

- **EDID Block** -- The 128-byte Extended Display Identification Data block is located by scanning for the stock BOE manufacturer ID. It's replaced with the aftermarket screen's EDID, which defines resolution, timing, and display capabilities.
- **$BVDT$ Version Strings** -- Every `$BVDT$` string in the firmware gets appended with a tag (e.g. "DeckHD") so a patched BIOS is identifiable. This is the same tagging approach used by the screen vendors themselves.

## Safety

- The tool never modifies the input file -- always writes to a separate output
- All SPD entries patched by default for broad chip compatibility
- All APCB checksums are recalculated and verified after modification
- The output file is re-scanned to confirm correct byte values per entry
- Stock configuration can be restored at any time with `--target 16`
- Interactive mode requires explicit `APPLY` + confirmation before any file is written

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
- DeckHD for their open-source BiosMaker and firmware analysis reference
- DeckSight for the AMOLED screen replacement
- InsydeH2O documentation for the APCB architecture details
