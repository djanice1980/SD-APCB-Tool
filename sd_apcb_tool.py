#!/usr/bin/env python3
"""
APCB Memory Configuration Tool v1.4.0
======================================
Automated BIOS modification tool for handheld gaming device RAM upgrades.

Supported devices:
  - Steam Deck (LCD & OLED) — 16GB/32GB
  - ASUS ROG Ally / Ally X — 16GB/32GB/64GB

Works on both raw SPI dumps and firmware update (.fd) files.
Auto-detects device type from firmware contents.

Core modification: patches LPDDR5/LPDDR5X SPD density bytes in APCB MEMG blocks
  - 16GB: byte[6]=0x95, byte[12]=0x02  (stock)
  - 32GB: byte[6]=0xB5, byte[12]=0x0A
  - 64GB: byte[6]=0xF5, byte[12]=0x49  (requires LPDDR5X hardware)

Flashing Paths:
  - SPI programmer (CH341A + SOIC8 clip): Writes raw image directly to the
    flash chip. No signing required. Supported by all devices.
  - h2offt (software flash, Steam Deck only): Requires a validly signed PE
    Authenticode capsule. Use --sign to automatically re-sign the modified
    firmware for h2offt. Requires 'cryptography' (pip install cryptography).

Supports:
  - Analysis mode: scans BIOS and reports all APCB blocks and SPD entries
  - Modify mode: patches SPD parameters for target memory configuration
  - Automatic device detection (Steam Deck vs ROG Ally)
  - Automatic PE Authenticode re-signing (--sign) for h2offt software flash
  - Validates checksums before and after modification

Usage:
  python sd_apcb_tool.py analyze <bios_file>
  python sd_apcb_tool.py analyze <bios_file> --device rog_ally
  python sd_apcb_tool.py modify <bios_in> <bios_out> --target 32
  python sd_apcb_tool.py modify <bios_in> <bios_out> --target 32 --sign
  python sd_apcb_tool.py modify <bios_in> <bios_out> --target 16  (restore stock)
"""

import argparse
import struct
import sys
import os
import shutil
import hashlib
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ============================================================================
# Constants
# ============================================================================

TOOL_VERSION = "1.4.0"

APCB_MAGIC = b'APCB'                         # APCB header signature (stock)
APCB_MAGIC_MOD = b'QPCB'                     # APCB header signature (one modder's marker - cosmetic only)
APCB_CHECKSUM_OFFSET = 16                     # Checksum byte position in APCB header
ECB2_MAGIC = b'ECB2'                          # APCB sub-header marker
MEMG_MAGIC = b'MEMG'                          # Memory Group marker
TOKN_MAGIC = b'TOKN'                          # Token marker
BCBA_MAGIC = b'BCBA'                          # Block marker preceding MEMG/TOKN
LP5_SPD_MAGIC  = bytes([0x23, 0x11, 0x13, 0x0E])  # LPDDR5 SPD entry magic
LP5X_SPD_MAGIC = bytes([0x23, 0x11, 0x15, 0x0E])  # LPDDR5X SPD entry magic
LP4_SPD_MAGIC  = bytes([0x23, 0x11, 0x11, 0x0E])  # LPDDR4 SPD entry magic (for reference)
ALL_SPD_MAGICS = [LP5_SPD_MAGIC, LP5X_SPD_MAGIC]  # All supported SPD magic types
SPD_ENTRY_SEPARATOR = bytes([0x12, 0x34, 0x56, 0x78])  # Entry boundary marker
BL2_MAGIC = b'$BL2'                           # BIOS Level 2 directory marker

# SPD modification values for different memory configurations
# These are the bytes at SPD_magic+6 (byte6) and SPD_magic+12 (byte12)
MEMORY_CONFIGS = {
    16: {
        'name': '16GB (Stock)',
        'byte6': 0x95,    # Standard density
        'byte12': 0x02,   # Standard config
        'description': 'Restores stock 16GB memory configuration',
    },
    32: {
        'name': '32GB Upgrade',
        'byte6': 0xB5,    # Higher density
        'byte12': 0x0A,   # 32GB config
        'description': 'Configures APCB for 32GB memory',
    },
    64: {
        'name': '64GB Upgrade',
        'byte6': 0xF5,    # 64GB density (8 die x 16Gb per die)
        'byte12': 0x49,   # 64GB config
        'description': 'Configures APCB for 64GB memory (requires LPDDR5X hardware)',
    },
}

# Known module part numbers and their memory sizes
MODULE_DENSITY_MAP = {
    # Micron LPDDR5
    'MT62F512M32D2DR': '16GB',    # Micron 512Mx32, 2-die (8GB/pkg × 2)
    'MT62F768M32D2DR': '24GB',    # Micron 768Mx32, 2-die (12GB/pkg × 2)
    'MT62F1G64D4BS':   '32GB',    # Micron 1Gx64, 4-die (16GB/pkg × 2)
    'MT62F1G64D4AH':   '32GB',    # Micron 1Gx64, 4-die (16GB/pkg × 2) - newer revision
    'MT62F1G32D4DR':   '32GB',    # Micron 1Gx32, 4-die - reference 32GB APCB entry
    'MT62F2G64D8AJ':   '32GB',    # Micron 2Gx64, 8-die (16GB/pkg × 2) - TESTED for 32GB mod
    'MT62F2G64D8':     '32GB',    # Micron 2Gx64, 8-die generic (16GB/pkg × 2)
    # Micron LPDDR5X
    'MT62F1G32D2DS':   '16GB',    # Micron LPDDR5X 16GB — Ally X
    'MT62F768M32D2DS': '24GB',    # Micron LPDDR5X 24GB — ROG Ally
    'MT62F1536M32D4DS':'32GB',    # Micron LPDDR5X 32GB — Ally X
    'MT62F2G32D4DS':   '32GB',    # Micron LPDDR5X 32GB — Ally X
    'MT62F4G32D8DV':   '64GB',    # Micron LPDDR5X 64GB (16GB/pkg × 4)
    # Samsung LPDDR5
    'K3KL3L30CM':      '32GB',    # Samsung LPDDR5 32GB
    'K3LKCKC0BM':      '32GB',    # Samsung LPDDR5X 8GB/pkg × 4 (LCD) - TESTED for 32GB mod
    'K3LKBKB0BM':      '16GB',    # Samsung LPDDR5 — ROG Ally stock
    'K3LK7K70BM':      '16GB',    # Samsung LPDDR5 16GB — Steam Deck LCD
    # Samsung LPDDR5X
    'K3KL8L80CM':      '16GB',    # Samsung LPDDR5X — Ally X stock
    'K3KLALA0CM':      '64GB',    # Samsung LPDDR5X 64GB (16GB/pkg × 4)
    # SK Hynix LPDDR5X
    'H58G56BK7BX':     '16GB',    # SK Hynix LPDDR5X 16GB — Ally X stock
    'H58GE6AK8BX':     '32GB',    # SK Hynix LPDDR5X 32GB — Ally X
    'H58G66BK8HX':     '16GB',    # SK Hynix LPDDR5 16GB — Steam Deck OLED (16Gb die × 8)
}

MANUFACTURER_IDS = {
    0x2C: 'Micron',
    0xCE: 'Samsung',
    0xAD: 'SK Hynix',
    0x01: 'Samsung (alt)',
}

# Known MEMG content type offsets within APCB blocks (device-dependent)
MEMG_OFFSET_STANDARD = 0x80    # Steam Deck: MEMG directly at 0x80
MEMG_OFFSET_ALLY = [0xC0]      # ROG Ally: PSPG at 0x80, MEMG at 0xC0
MEMG_OFFSET_ALLY_X = [0xC8]    # ROG Ally X: PSPG at 0x80, MEMG at 0xC8
MEMG_OFFSET_PSPG = [0xC0, 0xC8]  # All ROG Ally series offsets (for scanning)
PSPG_MAGIC = b'PSPG'           # PSP Group marker (ROG Ally series)

# Screen replacement EDID data and profiles (Steam Deck LCD only)
EDID_MAGIC = bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
BVDT_MAGIC = b'$BVDT$'

SCREEN_PROFILES = {
    'deckhd': {
        'name': 'DeckHD 1200p',
        'description': 'IPS LCD, 1200x1920 @ 60Hz (16:10)',
        'version_tag': 'DeckHD',
        'mfr_id': bytes([0x11, 0x04]),  # DHD
        'edid': bytes([
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x11, 0x04, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00,
            0x02, 0x21, 0x01, 0x04, 0xA5, 0x0A, 0x0F, 0x78, 0xE2, 0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26,
            0x0F, 0x50, 0x54, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0xB8, 0x3B, 0xB0, 0x64, 0x40, 0x80, 0x28, 0x70, 0x28, 0x14,
            0x22, 0x04, 0x5F, 0x97, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0xFC, 0x00, 0x44, 0x65, 0x63,
            0x6B, 0x48, 0x44, 0x2D, 0x31, 0x32, 0x30, 0x30, 0x70, 0x0A, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD5,
        ]),
    },
    'decksight': {
        'name': 'DeckSight OLED',
        'description': 'AMOLED, 1080x1920 @ 60/80Hz (16:9)',
        'version_tag': 'DeckSight',
        'mfr_id': bytes([0x12, 0x6F]),  # DSO
        'edid': bytes([
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x12, 0x6F, 0x01, 0x50, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x23, 0x01, 0x04, 0xA5, 0x09, 0x10, 0x78, 0x17, 0xB9, 0x74, 0xAE, 0x50, 0x3D, 0xB7, 0x23,
            0x0B, 0x4F, 0x51, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x66, 0x39, 0x38, 0xA0, 0x40, 0x80, 0x37, 0x70, 0x30, 0x20,
            0x3A, 0x00, 0x5A, 0xA0, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0xFC, 0x00, 0x44, 0x65, 0x63,
            0x6B, 0x53, 0x69, 0x67, 0x68, 0x74, 0x0A, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x4D, 0x38, 0xA0,
            0x40, 0x80, 0x4A, 0x70, 0x30, 0x20, 0x3A, 0x00, 0x5A, 0xA0, 0x00, 0x00, 0x00, 0x1E, 0x00, 0xDF,
        ]),
    },
}
# Collect all known screen manufacturer IDs (to skip already-patched EDID blocks)
SCREEN_MFR_IDS = [p['mfr_id'] for p in SCREEN_PROFILES.values()]

# Device profiles for supported handhelds
DEVICE_PROFILES = {
    'steam_deck': {
        'name': 'Steam Deck',
        'memg_offset': MEMG_OFFSET_STANDARD,
        'supports_signing': True,
        'memory_targets': [16, 32],
        'flash_instructions': 'sudo /usr/share/jupiter_bios_updater/h2offt {filename}',
    },
    'rog_ally': {
        'name': 'ROG Ally',
        'memg_offsets': MEMG_OFFSET_ALLY,
        'supports_signing': False,
        'memory_targets': [16, 32, 64],
        'flash_instructions': 'Flash via SPI programmer (CH341A + SOIC8 clip)',
    },
    'rog_ally_x': {
        'name': 'ROG Ally X',
        'memg_offsets': MEMG_OFFSET_ALLY_X,
        'supports_signing': False,
        'memory_targets': [16, 32, 64],
        'flash_instructions': 'Flash via SPI programmer (CH341A + SOIC8 clip)',
    },
}


# ============================================================================
# Data Structures
# ============================================================================

# SPD byte field constants (JEDEC SPD4.1.2.M-2 / LPDDR5 layout)
# MTB = Medium Time Base = 125ps (0.125ns)
SPD_MTB_PS = 125  # picoseconds

# Die density decoding (byte 4 bits 3:0)
_DIE_DENSITY_MAP = {
    0x4: '4Gb', 0xB: '6Gb', 0x5: '8Gb', 0x8: '12Gb',
    0x6: '16Gb', 0x9: '24Gb', 0x7: '32Gb',
}

# Die count decoding (byte 6 bits 6:4)
_DIE_COUNT_MAP = {0: 1, 1: 2, 2: 4, 3: 8}

# Device width decoding (byte 12 bits 2:0)
_DEV_WIDTH_MAP = {0: 'x4', 1: 'x8', 2: 'x16', 3: 'x32'}

# Bank groups decoding (byte 4 bits 5:4)
_BANK_GROUPS_MAP = {0: 1, 1: 2, 2: 4}

# Banks per group decoding (byte 4 bits 7:6)
_BANKS_PER_GROUP_MAP = {0: 4, 1: 8, 2: 16}


def _decode_spd_fields(spd: bytes) -> dict:
    """Decode LPDDR5/LPDDR5X SPD bytes into human-readable fields.

    Args:
        spd: At least 32 bytes of SPD data starting at the magic.

    Returns:
        Dict with decoded field values.
    """
    if len(spd) < 29:
        return {}

    b4 = spd[4]   # SDRAM Density and Banks
    b5 = spd[5]   # SDRAM Addressing (rows/cols)
    b6 = spd[6]   # SDRAM Package Type (die count, density)
    b7 = spd[7]   # Optional Features (tMAW, MAC)
    b12 = spd[12] # Module Organization (ranks, device width)
    b13 = spd[13] # Module Memory Bus Width

    # Die density
    die_density_code = b4 & 0x0F
    die_density = _DIE_DENSITY_MAP.get(die_density_code, f'?({die_density_code})')

    # Bank architecture
    bank_groups = _BANK_GROUPS_MAP.get((b4 >> 4) & 0x03, '?')
    banks_per_group = _BANKS_PER_GROUP_MAP.get((b4 >> 6) & 0x03, '?')

    # Addressing
    col_bits = (b5 & 0x07) + 9
    row_bits = ((b5 >> 3) & 0x07) + 12

    # Package type (byte 6)
    die_count_code = (b6 >> 4) & 0x07
    die_count = _DIE_COUNT_MAP.get(die_count_code, die_count_code)

    # Module organization (byte 12)
    dev_width_code = b12 & 0x07
    dev_width = _DEV_WIDTH_MAP.get(dev_width_code, f'x?({dev_width_code})')
    ranks = ((b12 >> 3) & 0x07) + 1

    # Bus width (byte 13)
    bus_width_code = b13 & 0x07
    bus_width = {0: 8, 1: 16, 2: 32, 3: 64}.get(bus_width_code, '?')

    result = {
        'die_density': die_density,
        'die_count': die_count,
        'ranks': ranks,
        'dev_width': dev_width,
        'bus_width': bus_width,
        'row_bits': row_bits,
        'col_bits': col_bits,
        'bank_groups': bank_groups,
        'banks_per_group': banks_per_group,
    }

    # Timing parameters (require at least 29 bytes)
    b18 = spd[18]  # tCKmin (MTB)
    b24 = spd[24]  # tAAmin (MTB)
    b26 = spd[26]  # tRCDmin (MTB)
    b27 = spd[27]  # tRPABmin (MTB)
    b28 = spd[28]  # tRPPBmin (MTB)

    result['tCK_mtb'] = b18
    result['tAA_ns'] = round(b24 * SPD_MTB_PS / 1000, 2)
    result['tRCD_ns'] = round(b26 * SPD_MTB_PS / 1000, 2)
    result['tRPAB_ns'] = round(b27 * SPD_MTB_PS / 1000, 2)
    result['tRPPB_ns'] = round(b28 * SPD_MTB_PS / 1000, 2)

    return result


@dataclass
class SPDEntry:
    """A single SPD (Serial Presence Detect) entry within an APCB MEMG block."""
    offset_in_apcb: int          # Offset of SPD magic within the APCB block
    offset_in_file: int          # Absolute offset in the BIOS file
    spd_bytes: bytes             # The SPD parameter bytes (magic + config, up to 128)
    module_name: str = ''        # Module part number (e.g., MT62F512M32D2DR-031)
    manufacturer: str = ''       # Manufacturer name
    density_guess: str = ''      # Estimated memory density
    byte6: int = 0               # Key byte: density/package type
    byte12: int = 0              # Key byte: configuration
    config_id: int = 0           # Configuration index from entry header
    mfr_flag: int = 0            # Manufacturer flag from entry header
    mem_type: str = 'LPDDR5'     # Memory type ('LPDDR5' or 'LPDDR5X')
    module_name_offset: int = -1 # Absolute offset in file where module name starts
    module_name_field_len: int = 0  # Byte length of the name field (for null-padding on write)
    # Decoded SPD fields (populated by _decode_spd_fields)
    die_density: str = ''        # Per-die density (e.g., '16Gb')
    die_count: int = 0           # Dies per package (1, 2, 4, 8)
    ranks: int = 0               # Number of ranks (1, 2, 4)
    dev_width: str = ''          # Device I/O width (x8, x16, x32)
    bus_width: int = 0           # Primary bus width in bits (16, 32, 64)
    row_bits: int = 0            # Row address bits (14-18)
    col_bits: int = 0            # Column address bits (9-12)
    bank_groups: int = 0         # Number of bank groups
    banks_per_group: int = 0     # Banks per bank group
    tAA_ns: float = 0.0          # CAS Latency time (ns)
    tRCD_ns: float = 0.0         # RAS-to-CAS delay (ns)
    tRPAB_ns: float = 0.0       # Row precharge all banks (ns)
    tRPPB_ns: float = 0.0       # Row precharge per bank (ns)


@dataclass
class APCBBlock:
    """An APCB block found in the BIOS image."""
    offset: int                  # Absolute offset in file
    data_size: int               # Size from APCB header field
    total_size: int              # Total size from APCB header
    checksum_byte: int           # Current checksum byte value
    checksum_valid: bool         # Whether checksum validates
    content_type: str            # 'MEMG', 'TOKN', or 'UNKNOWN'
    directory_type: int = 0      # BL2 directory entry type (0x60, 0x68, etc.)
    spd_entries: List[SPDEntry] = field(default_factory=list)
    
    @property
    def is_memg(self) -> bool:
        return self.content_type == 'MEMG'


# ============================================================================
# Checksum Functions
# ============================================================================

def calculate_apcb_checksum(block_data: bytes) -> int:
    """
    Calculate APCB checksum.
    Sum all bytes except the byte at APCB_CHECKSUM_OFFSET (16).
    Checksum = (0x100 - sum) & 0xFF
    """
    total = 0
    for i, b in enumerate(block_data):
        if i == APCB_CHECKSUM_OFFSET:
            continue
        total = (total + b) & 0xFF
    return (0x100 - total) & 0xFF


def verify_apcb_checksum(block_data: bytes) -> bool:
    """Verify that the APCB block checksum is valid."""
    expected = calculate_apcb_checksum(block_data)
    actual = block_data[APCB_CHECKSUM_OFFSET]
    return expected == actual


# ============================================================================
# Device Detection
# ============================================================================

def detect_device(data: bytes) -> str:
    """
    Auto-detect the device type from firmware contents.

    Scans APCB blocks and checks content type marker locations:
      - MEMG at offset 0x80 -> Steam Deck
      - PSPG at offset 0x80 + MEMG at offset 0xC0 -> ROG Ally
      - PSPG at offset 0x80 + MEMG at offset 0xC8 -> ROG Ally X

    Returns:
        Device key ('steam_deck', 'rog_ally', 'rog_ally_x') or 'unknown'
    """
    has_memg_at_80 = False
    has_pspg_memg_at_c0 = False
    has_pspg_memg_at_c8 = False

    for magic in [APCB_MAGIC, APCB_MAGIC_MOD]:
        pos = 0
        while pos < len(data) - 32:
            idx = data.find(magic, pos)
            if idx == -1:
                break

            header = data[idx:idx+32]
            data_size = struct.unpack_from('<I', header, 8)[0]
            if data_size > 0x100000 or data_size < 16:
                pos = idx + 1
                continue

            # Check what's at offset 0x80 and fallback offsets
            if idx + 0x84 <= len(data):
                if data[idx+0x80:idx+0x84] == MEMG_MAGIC:
                    has_memg_at_80 = True
                elif data[idx+0x80:idx+0x84] == PSPG_MAGIC:
                    # Distinguish ROG Ally (MEMG at 0xC0) from Ally X (MEMG at 0xC8)
                    if idx + 0xC4 <= len(data) and data[idx+0xC0:idx+0xC4] == MEMG_MAGIC:
                        has_pspg_memg_at_c0 = True
                    if idx + 0xCC <= len(data) and data[idx+0xC8:idx+0xCC] == MEMG_MAGIC:
                        has_pspg_memg_at_c8 = True

            pos = idx + 1

    if has_memg_at_80:
        return 'steam_deck'
    elif has_pspg_memg_at_c8:
        return 'rog_ally_x'
    elif has_pspg_memg_at_c0:
        return 'rog_ally'
    return 'unknown'


# ============================================================================
# APCB Scanning and Parsing
# ============================================================================

def find_apcb_blocks(data: bytes) -> List[APCBBlock]:
    """
    Scan the BIOS image for all APCB blocks.
    Uses both 'APCB' (stock) and 'QPCB' (modified) magic signatures.
    """
    blocks = []
    found_offsets = set()
    
    for magic in [APCB_MAGIC, APCB_MAGIC_MOD]:
        pos = 0
        while pos < len(data) - 32:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            
            if idx in found_offsets:
                pos = idx + 1
                continue
            found_offsets.add(idx)
            
            # Parse APCB header
            header = data[idx:idx+32]
            data_size = struct.unpack_from('<I', header, 8)[0]
            total_size = struct.unpack_from('<I', header, 12)[0]
            checksum_byte = header[16]
            
            # Sanity check sizes
            if data_size > 0x100000 or data_size < 16 or total_size > 0x100000:
                pos = idx + 1
                continue
            
            # Determine content type
            # Check standard offset 0x80 (Steam Deck) and 0xC0 (ROG Ally)
            content_type = 'UNKNOWN'
            if idx + 0x84 < len(data):
                if data[idx+0x80:idx+0x84] == MEMG_MAGIC:
                    content_type = 'MEMG'
                elif data[idx+0x80:idx+0x84] == TOKN_MAGIC:
                    content_type = 'TOKN'
            # ROG Ally series layout: PSPG at 0x80, MEMG/TOKN at 0xC0 or 0xC8
            if content_type == 'UNKNOWN':
                for alt_off in MEMG_OFFSET_PSPG:
                    if idx + alt_off + 4 < len(data):
                        if data[idx+alt_off:idx+alt_off+4] == MEMG_MAGIC:
                            content_type = 'MEMG'
                            break
                        elif data[idx+alt_off:idx+alt_off+4] == TOKN_MAGIC:
                            content_type = 'TOKN'
                            break
            
            # Verify checksum
            if idx + data_size <= len(data):
                block_data = data[idx:idx+data_size]
                cksum_valid = verify_apcb_checksum(block_data)
            else:
                cksum_valid = False
            
            block = APCBBlock(
                offset=idx,
                data_size=data_size,
                total_size=total_size,
                checksum_byte=checksum_byte,
                checksum_valid=cksum_valid,
                content_type=content_type,
            )
            
            # Parse SPD entries if this is a MEMG block
            if content_type == 'MEMG':
                block.spd_entries = parse_spd_entries(data, idx, data_size)
            
            blocks.append(block)
            pos = idx + 1
    
    # Sort by offset for consistent ordering
    blocks.sort(key=lambda b: b.offset)
    return blocks


def parse_spd_entries(data: bytes, apcb_offset: int, apcb_size: int) -> List[SPDEntry]:
    """Parse all LPDDR5/LPDDR5X SPD entries within an APCB MEMG block."""
    entries = []
    apcb = data[apcb_offset:apcb_offset + apcb_size]

    # Find all SPD entries with both LPDDR5 and LPDDR5X magics
    raw_entries = []  # (offset_in_apcb, mem_type)
    for spd_magic, mem_type in [(LP5_SPD_MAGIC, 'LPDDR5'), (LP5X_SPD_MAGIC, 'LPDDR5X')]:
        pos = 0
        while pos < len(apcb):
            idx = apcb.find(spd_magic, pos)
            if idx == -1:
                break
            if idx + 16 <= len(apcb):
                raw_entries.append((idx, mem_type))
            pos = idx + 1

    # Sort by offset for consistent ordering
    raw_entries.sort(key=lambda x: x[0])

    for idx, mem_type in raw_entries:
        # Read up to 128 bytes of SPD data for field decoding
        spd_len = min(128, len(apcb) - idx)
        spd_bytes = apcb[idx:idx + spd_len]

        entry = SPDEntry(
            offset_in_apcb=idx,
            offset_in_file=apcb_offset + idx,
            spd_bytes=spd_bytes,
            byte6=spd_bytes[6] if len(spd_bytes) > 6 else 0,
            byte12=spd_bytes[12] if len(spd_bytes) > 12 else 0,
            mem_type=mem_type,
        )

        # Decode detailed SPD fields
        fields = _decode_spd_fields(spd_bytes)
        if fields:
            entry.die_density = fields.get('die_density', '')
            entry.die_count = fields.get('die_count', 0)
            entry.ranks = fields.get('ranks', 0)
            entry.dev_width = fields.get('dev_width', '')
            entry.bus_width = fields.get('bus_width', 0)
            entry.row_bits = fields.get('row_bits', 0)
            entry.col_bits = fields.get('col_bits', 0)
            entry.bank_groups = fields.get('bank_groups', 0)
            entry.banks_per_group = fields.get('banks_per_group', 0)
            entry.tAA_ns = fields.get('tAA_ns', 0.0)
            entry.tRCD_ns = fields.get('tRCD_ns', 0.0)
            entry.tRPAB_ns = fields.get('tRPAB_ns', 0.0)
            entry.tRPPB_ns = fields.get('tRPPB_ns', 0.0)

        # Find module part number (search forward for ASCII strings)
        for j in range(idx, min(idx + 0x200, len(apcb) - 20)):
            prefix = apcb[j:j+3]
            if prefix in [b'MT6', b'K3K', b'K3L', b'SEC', b'SAM', b'H9H', b'H58']:
                end = j
                while end < min(j + 30, len(apcb)) and 0x20 <= apcb[end] < 0x7F:
                    end += 1
                entry.module_name = apcb[j:end].decode('ascii', errors='replace').strip()
                entry.module_name_offset = apcb_offset + j
                entry.module_name_field_len = end - j

                # Manufacturer ID is typically 2 bytes after name null terminator
                mfr_off = end + 2
                if mfr_off < len(apcb):
                    mfr_byte = apcb[mfr_off]
                    entry.manufacturer = MANUFACTURER_IDS.get(mfr_byte, f'0x{mfr_byte:02X}')
                break

        # Guess density from module name
        for prefix, density in MODULE_DENSITY_MAP.items():
            if prefix in entry.module_name:
                entry.density_guess = density
                break

        # Parse entry header (look for separator before SPD magic)
        sep_search_start = max(0, idx - 48)
        pre = apcb[sep_search_start:idx]
        sep_idx = pre.find(SPD_ENTRY_SEPARATOR)
        if sep_idx >= 0:
            hdr_abs = sep_search_start + sep_idx
            hdr = apcb[hdr_abs:idx]
            if len(hdr) >= 12:
                entry.mfr_flag = struct.unpack_from('<H', hdr, 8)[0]
                entry.config_id = struct.unpack_from('<H', hdr, 10)[0]

        entries.append(entry)

    return entries


# ============================================================================
# Analysis / Display
# ============================================================================

def _density_label(byte6: int, byte12: int) -> str:
    """Return a factual density label from SPD byte values (no assumptions)."""
    for gb, cfg in MEMORY_CONFIGS.items():
        if cfg['byte6'] == byte6 and cfg['byte12'] == byte12:
            return f"{gb}GB"
    return f"Unknown (0x{byte6:02X}/0x{byte12:02X})"


def analyze_bios(filepath: str, device: str = 'auto') -> List[APCBBlock]:
    """Analyze a BIOS file and display all APCB blocks and SPD entries.

    Args:
        filepath: Path to the BIOS file to analyze
        device: Device type ('auto', 'steam_deck', 'rog_ally', 'rog_ally_x')
    """

    if not os.path.exists(filepath):
        print(f"\n  ERROR: File not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'rb') as f:
        data = f.read()

    # Device detection
    if device == 'auto':
        device = detect_device(data)
    device_profile = DEVICE_PROFILES.get(device)
    device_name = device_profile['name'] if device_profile else 'Unknown Device'

    print(f"\n{'='*78}")
    print(f"  APCB Memory Configuration Analyzer v{TOOL_VERSION}")
    print(f"{'='*78}")

    file_size = len(data)
    print(f"\n  File:   {os.path.basename(filepath)}")
    print(f"  Size:   {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
    print(f"  Device: {device_name}")
    
    # Detect file type
    if file_size == 16 * 1024 * 1024:
        print(f"  Type: Raw SPI dump (128Mbit / 16MB)")
    elif file_size == 32 * 1024 * 1024:
        print(f"  Type: Raw SPI dump (256Mbit / 32MB)")
    elif file_size == 64 * 1024 * 1024:
        print(f"  Type: Raw SPI dump (512Mbit / 64MB)")
    else:
        print(f"  Type: Firmware update file (.fd) or non-standard dump")
    
    # Scan for APCB blocks
    blocks = find_apcb_blocks(data)
    
    print(f"\n  Found {len(blocks)} APCB block(s)")
    
    memg_count = sum(1 for b in blocks if b.is_memg)
    tokn_count = sum(1 for b in blocks if b.content_type == 'TOKN')
    print(f"    MEMG (SPD database): {memg_count}")
    print(f"    TOKN (tokens):       {tokn_count}")
    
    # Display each block
    for i, block in enumerate(blocks):
        print(f"\n  {'-'*74}")
        print(f"  APCB Block {i+1}: {block.content_type}")
        print(f"  {'-'*74}")
        print(f"    Offset:     0x{block.offset:08X}")
        print(f"    Data size:  0x{block.data_size:04X} ({block.data_size} bytes)")
        print(f"    Total size: 0x{block.total_size:04X} ({block.total_size} bytes)")
        print(f"    Checksum:   0x{block.checksum_byte:02X} ({'VALID' if block.checksum_valid else 'INVALID'})")
        
        if block.is_memg and block.spd_entries:
            # Count entries by memory type
            lp5_count = sum(1 for e in block.spd_entries if e.mem_type == 'LPDDR5')
            lp5x_count = sum(1 for e in block.spd_entries if e.mem_type == 'LPDDR5X')
            type_summary = []
            if lp5_count:
                type_summary.append(f"{lp5_count} LPDDR5")
            if lp5x_count:
                type_summary.append(f"{lp5x_count} LPDDR5X")

            print(f"\n    SPD Entries ({len(block.spd_entries)}: {', '.join(type_summary)}):")
            print(f"    {'-'*110}")
            print(f"    {'#':<3} {'Type':<8} {'Module':<24} {'Mfr':<9} {'Density':<7} "
                  f"{'Dies':<5} {'Width':<6} {'Ranks':<6} "
                  f"{'tAA':<7} {'tRCD':<7} {'tRP':<7}")
            print(f"    {'-'*110}")

            for j, entry in enumerate(block.spd_entries):
                entry_den = _density_label(entry.byte6, entry.byte12)
                die_info = f"{entry.die_count}x{entry.die_density}" if entry.die_count and entry.die_density else '?'
                tAA = f"{entry.tAA_ns}ns" if entry.tAA_ns else '?'
                tRCD = f"{entry.tRCD_ns}ns" if entry.tRCD_ns else '?'
                tRP = f"{entry.tRPPB_ns}ns" if entry.tRPPB_ns else '?'

                print(f"    {j+1:<3} {entry.mem_type:<8} {entry.module_name:<24} "
                      f"{entry.manufacturer:<9} {entry_den:<7} "
                      f"{die_info:<5} {entry.dev_width:<6} {entry.ranks}R    "
                      f"{tAA:<7} {tRCD:<7} {tRP:<7}")

            # Show first-entry SPD config (factual, no assumptions)
            first = block.spd_entries[0]
            first_den = _density_label(first.byte6, first.byte12)
            print(f"\n    First entry SPD config: {first_den}")
    
    return blocks


# ============================================================================
# PE Authenticode Signing (Pure Python, no external tools)
# ============================================================================

def _check_signing_available():
    """Check if the cryptography library is available for signing."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.x509 import CertificateBuilder, Name, NameAttribute, NameOID
        from cryptography import x509
        return True
    except ImportError:
        return False


# --- DER Encoding Helpers ---

def _der_length(length):
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif length < 0x1000000:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x84, (length >> 24) & 0xFF, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])

def _der_tag(tag, content):
    return bytes([tag]) + _der_length(len(content)) + content

def _der_sequence(content):
    return _der_tag(0x30, content)

def _der_set(content):
    return _der_tag(0x31, content)

def _der_oid(oid_str):
    """Encode a dotted OID string to DER."""
    parts = [int(x) for x in oid_str.split('.')]
    encoded = bytes([40 * parts[0] + parts[1]])
    for val in parts[2:]:
        if val < 0x80:
            encoded += bytes([val])
        elif val < 0x4000:
            encoded += bytes([(val >> 7) | 0x80, val & 0x7F])
        elif val < 0x200000:
            encoded += bytes([(val >> 14) | 0x80, ((val >> 7) & 0x7F) | 0x80, val & 0x7F])
        else:
            encoded += bytes([(val >> 21) | 0x80, ((val >> 14) & 0x7F) | 0x80,
                            ((val >> 7) & 0x7F) | 0x80, val & 0x7F])
    return _der_tag(0x06, encoded)

def _der_integer(value):
    if isinstance(value, int):
        if value == 0:
            return _der_tag(0x02, b'\x00')
        result = []
        v = value
        while v > 0:
            result.insert(0, v & 0xFF)
            v >>= 8
        if result[0] & 0x80:
            result.insert(0, 0)
        return _der_tag(0x02, bytes(result))
    return _der_tag(0x02, value)

def _der_octet_string(data):
    return _der_tag(0x04, data)

def _der_null():
    return bytes([0x05, 0x00])

def _der_context(tag_num, content, constructed=True):
    tag = (0xA0 if constructed else 0x80) | tag_num
    return _der_tag(tag, content)

def _der_utctime(dt):
    return _der_tag(0x17, dt.strftime('%y%m%d%H%M%SZ').encode('ascii'))


# --- Authenticode OIDs ---

_OID_PKCS7_SIGNED_DATA = '1.2.840.113549.1.7.2'
_OID_SPC_INDIRECT_DATA = '1.3.6.1.4.1.311.2.1.4'
_OID_SPC_PE_IMAGE_DATA = '1.3.6.1.4.1.311.2.1.15'
_OID_SPC_SP_OPUS_INFO  = '1.3.6.1.4.1.311.2.1.12'
_OID_MS_IND_CODE_SIGN  = '1.3.6.1.4.1.311.2.1.21'
_OID_SHA256            = '2.16.840.1.101.3.4.2.1'
_OID_RSA_ENCRYPTION    = '1.2.840.113549.1.1.1'
_OID_CONTENT_TYPE      = '1.2.840.113549.1.9.3'
_OID_SIGNING_TIME      = '1.2.840.113549.1.9.5'
_OID_MESSAGE_DIGEST    = '1.2.840.113549.1.9.4'


def _compute_pe_checksum(data):
    """Compute PE checksum (same algorithm as Windows MapFileAndCheckSum)."""
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    checksum_offset = pe_offset + 4 + 20 + 64

    checksum = 0
    remainder = len(data) % 4
    for i in range(0, len(data) - remainder, 4):
        if i == checksum_offset:
            continue
        val = struct.unpack_from('<I', data, i)[0]
        checksum = (checksum & 0xFFFFFFFF) + val + (checksum >> 32)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    if remainder:
        val = int.from_bytes(data[-(remainder):] + b'\x00' * (4 - remainder), 'little')
        checksum = (checksum & 0xFFFFFFFF) + val + (checksum >> 32)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return (checksum + len(data)) & 0xFFFFFFFF


def _compute_authenticode_hash(data):
    """Compute the Authenticode PE hash per Microsoft's specification.

    The Authenticode hash covers the PE file in a specific order:
    1. Headers from 0 to SizeOfHeaders, skipping checksum and security dir entry
    2. Each PE section body, sorted by PointerToRawData
    3. Any trailing data between the last section and the certificate table

    Args:
        data: PE file bytes (with security directory already cleared to zero
              and checksum field zeroed).

    Returns:
        SHA-256 digest bytes.
    """
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    coff_start = pe_offset + 4
    num_sections = struct.unpack_from('<H', data, coff_start + 2)[0]
    opt_header_size = struct.unpack_from('<H', data, coff_start + 16)[0]

    opt_start = coff_start + 20
    magic = struct.unpack_from('<H', data, opt_start)[0]
    checksum_offset = opt_start + 64
    dd_start = opt_start + (112 if magic == 0x20B else 96)
    secdir_offset = dd_start + 32  # Security directory is data directory index 4

    # SizeOfHeaders from optional header (offset 60 for both PE32 and PE32+)
    size_of_headers = struct.unpack_from('<I', data, opt_start + 60)[0]

    # Section table starts immediately after the optional header
    section_table_offset = opt_start + opt_header_size

    h = hashlib.sha256()

    # Step 1: Hash headers from 0 to SizeOfHeaders, skipping checksum (4 bytes)
    # and security directory entry (8 bytes)
    h.update(data[:checksum_offset])
    h.update(data[checksum_offset + 4:secdir_offset])
    h.update(data[secdir_offset + 8:size_of_headers])

    # Step 2: Hash PE sections sorted by PointerToRawData
    sections = []
    for i in range(num_sections):
        sec_off = section_table_offset + i * 40
        raw_size = struct.unpack_from('<I', data, sec_off + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, sec_off + 20)[0]
        if raw_size > 0:
            sections.append((raw_ptr, raw_size))
    sections.sort(key=lambda s: s[0])

    sum_of_bytes_hashed = size_of_headers
    for ptr, size in sections:
        h.update(data[ptr:ptr + size])
        end = ptr + size
        if end > sum_of_bytes_hashed:
            sum_of_bytes_hashed = end

    # Step 3: Hash any trailing data after the last section
    # (between sum_of_bytes_hashed and the certificate table / end of file)
    file_end = len(data)
    if sum_of_bytes_hashed < file_end:
        h.update(data[sum_of_bytes_hashed:file_end])

    return h.digest()


# --- Insyde _IFLASH Structure Helpers ---

_IFLASH_BIOSCER_MAGIC = b'_IFLASH_BIOSCER'
_IFLASH_BIOSCR2_MAGIC = b'_IFLASH_BIOSCR2'
_IFLASH_FLAGS_OFFSET = 0x0F           # Validation mode flag byte
_IFLASH_BIOSCER_HASH_OFFSET = 0x18   # 32-byte SHA-256 hash starts here
_IFLASH_BIOSCR2_CERT_OFFSET = 0x1F   # WIN_CERTIFICATE starts here


def _find_iflash_structures(data):
    """Find Insyde _IFLASH_BIOSCER and _IFLASH_BIOSCR2 in firmware.

    Steam Deck .fd firmware files contain two internal integrity structures
    in addition to the standard PE Authenticode signature:
    - _IFLASH_BIOSCER: 32-byte SHA-256 hash at structure offset +0x18
    - _IFLASH_BIOSCR2: full WIN_CERTIFICATE (PKCS#7) at structure offset +0x1F

    Returns:
        Tuple of (bioscer_offset, bioscr2_offset) or (None, None) if not found.
    """
    bioscer = data.find(_IFLASH_BIOSCER_MAGIC)
    bioscr2 = data.find(_IFLASH_BIOSCR2_MAGIC)
    if bioscer >= 0 and bioscr2 >= 0:
        return bioscer, bioscr2
    return None, None


# DeckHD-proven flag transformations for h2offt QA mode.
# Each _IFLASH structure has a flags byte at offset +0x0F that controls
# h2offt's validation behavior. Stock firmware uses values that require
# Valve's certificate chain; DeckHD changes them to accept self-signed certs.
# Pattern verified across 3 DeckHD versions (F7A0120, F7A0121, F7A0131).
_IFLASH_FLAG_MAP = {
    b'_IFLASH_DRV_IMG': lambda f: f | 0x08,                    # 0x80→0x88, 0xA0→0xA8
    b'_IFLASH_BIOSIMG': lambda f: 0x08 if f == 0x20 else f,    # 2nd copy (0x20) only
    b'_IFLASH_INI_IMG': lambda f: 0x68,                         # Always 0x68
    b'_IFLASH_BIOSCER': lambda f: 0x08,                         # Always 0x08
    b'_IFLASH_BIOSCR2': lambda f: 0x08,                         # Always 0x08
}


def _update_iflash_flags(data):
    """Update all _IFLASH structure flags for h2offt QA/self-signed mode.

    Steam Deck .fd firmware contains 6 _IFLASH structures. DeckHD sets specific
    flag values on each to tell h2offt to accept self-signed certificates instead
    of requiring Valve's certificate chain. Each structure type has a different
    transformation rule.

    Args:
        data: bytearray of the firmware (modified in place).

    Returns:
        List of (offset, name, old_flag, new_flag) for each updated structure.
    """
    pos = 0
    updated = []
    while pos < len(data):
        idx = data.find(b'_IFLASH_', pos)
        if idx < 0:
            break
        for magic, transform in _IFLASH_FLAG_MAP.items():
            if data[idx:idx + len(magic)] == magic:
                old_flag = data[idx + _IFLASH_FLAGS_OFFSET]
                new_flag = transform(old_flag)
                if old_flag != new_flag:
                    data[idx + _IFLASH_FLAGS_OFFSET] = new_flag
                    updated.append((idx, magic.decode(), old_flag, new_flag))
                break
        pos = idx + 1
    return updated


def _build_spc_indirect_data(pe_hash):
    """Build the SPC_INDIRECT_DATA_CONTENT structure.

    Matches DeckHD's encoding:
      SpcIndirectDataContent ::= SEQUENCE {
        data  SpcAttributeTypeAndOptionalValue,   -- OID + SEQUENCE{BIT STRING, [0]{[2]{[0]}}}
        messageImprint  DigestInfo               -- AlgorithmIdentifier + OCTET STRING
      }

    Returns (full_der, inner_content) where inner_content is the raw content
    octets without the outer SEQUENCE tag/length, needed for messageDigest.
    """
    # SpcPeImageData: BIT STRING (just unused-bits byte) + SpcLink (empty)
    # DeckHD uses: BITS len=1 [00], [0](A0) len=4 { [2](A2) len=2 { [0](80) len=0 } }
    spc_flags = _der_tag(0x03, bytes([0x00]))  # BIT STRING: 0 unused bits, no flags
    spc_link = _der_context(0, b'', constructed=False)  # [0] PRIMITIVE empty
    spc_file = _der_context(2, spc_link)  # [2] CONSTRUCTED { [0] empty }
    spc_pe_data = _der_sequence(spc_flags + _der_context(0, spc_file))
    # DeckHD wraps the value in the SPC_ATTR as a direct SEQUENCE, not [0] EXPLICIT
    spc_attr = _der_sequence(_der_oid(_OID_SPC_PE_IMAGE_DATA) + spc_pe_data)
    digest_algo = _der_sequence(_der_oid(_OID_SHA256) + _der_null())
    digest_info = _der_sequence(digest_algo + _der_octet_string(pe_hash))
    inner_content = spc_attr + digest_info
    return _der_sequence(inner_content), inner_content


def _build_auth_attrs(spc_inner_content, signing_time):
    """Build authenticated attributes for signer info.

    Matches DeckHD's encoding: opusInfo, contentType, messageDigest.
    DeckHD omits signingTime. Attributes are DER-sorted (as required for
    SET OF in DER encoding).

    Args:
        spc_inner_content: The raw content octets of SPC_INDIRECT_DATA_CONTENT
            (without the outer SEQUENCE tag/length). Per RFC 2315 Section 9.3,
            the messageDigest is computed over these content octets only.
        signing_time: UTC datetime (unused — DeckHD omits signingTime).
    """
    # SpcSpOpusInfo: empty SEQUENCE (no programName or moreInfo)
    attr_opus = _der_sequence(
        _der_oid(_OID_SPC_SP_OPUS_INFO) +
        _der_set(_der_sequence(b'')))
    # contentType: SPC_INDIRECT_DATA OID
    attr_ct = _der_sequence(
        _der_oid(_OID_CONTENT_TYPE) + _der_set(_der_oid(_OID_SPC_INDIRECT_DATA)))
    # messageDigest: SHA-256 of SPC content octets only (per RFC 2315 Section 9.3)
    content_hash = hashlib.sha256(spc_inner_content).digest()
    attr_md = _der_sequence(
        _der_oid(_OID_MESSAGE_DIGEST) + _der_set(_der_octet_string(content_hash)))
    # DER SET OF encoding requires elements sorted by their DER encoding.
    # DeckHD's order: opusInfo, contentType, messageDigest
    # Sort by raw DER bytes to ensure correct ordering.
    attrs = sorted([attr_opus, attr_ct, attr_md], key=lambda x: x)
    return b''.join(attrs)


def _build_pkcs7(pe_hash, cert_der, private_key, signing_time):
    """Build complete PKCS#7 SignedData for Authenticode."""
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography import x509 as _x509

    cert = _x509.load_der_x509_certificate(cert_der)
    serial = cert.serial_number
    issuer_der = cert.issuer.public_bytes()

    spc_content, spc_inner = _build_spc_indirect_data(pe_hash)
    content_info = _der_sequence(
        _der_oid(_OID_SPC_INDIRECT_DATA) + _der_context(0, spc_content))
    sha256_algo = _der_sequence(_der_oid(_OID_SHA256) + _der_null())
    digest_algos = _der_set(sha256_algo)
    certificates = _der_context(0, cert_der)

    auth_attrs_content = _build_auth_attrs(spc_inner, signing_time)
    attrs_for_signing = _der_set(auth_attrs_content)
    signature = private_key.sign(attrs_for_signing, _padding.PKCS1v15(), _hashes.SHA256())

    issuer_and_serial = _der_sequence(issuer_der + _der_integer(serial))
    rsa_algo = _der_sequence(_der_oid(_OID_RSA_ENCRYPTION) + _der_null())

    signer_info = _der_sequence(
        _der_integer(1) + issuer_and_serial + sha256_algo +
        _der_context(0, auth_attrs_content) + rsa_algo +
        _der_octet_string(signature))

    signed_data = _der_sequence(
        _der_integer(1) + digest_algos + content_info + certificates + _der_set(signer_info))

    return _der_sequence(
        _der_oid(_OID_PKCS7_SIGNED_DATA) + _der_context(0, signed_data))


def _build_win_certificate(pkcs7_blob):
    """Build a WIN_CERTIFICATE structure (8-byte aligned) from a PKCS#7 blob."""
    wc_len = (8 + len(pkcs7_blob) + 7) & ~7
    win_cert = struct.pack('<IHH', wc_len, 0x0200, 0x0002) + pkcs7_blob
    win_cert += b'\x00' * (wc_len - len(win_cert))
    return win_cert


def sign_firmware(data_in):
    """
    Sign a PE firmware file with a fresh self-signed certificate.

    Handles three integrity layers present in Steam Deck firmware:
    1. _IFLASH_BIOSCER: Internal hash (preserved — algorithm is proprietary)
    2. _IFLASH_BIOSCR2: Internal Authenticode signature (re-signed with our cert)
    3. PE Security Directory: Standard PE Authenticode (re-signed with our cert)

    For non-Steam Deck firmware (no _IFLASH structures), only layer 3 is applied.

    Args:
        data_in: Input file bytes (PE format firmware)

    Returns:
        Signed file bytes ready for h2offt
    """
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509 import CertificateBuilder, Name, NameAttribute, NameOID
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.serialization import Encoding

    data = bytearray(data_in)

    # Locate PE structures
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file (no MZ header)")
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        raise ValueError("Invalid PE signature")

    opt_start = pe_offset + 4 + 20
    magic = struct.unpack_from('<H', data, opt_start)[0]
    checksum_offset = opt_start + 64
    dd_start = opt_start + (112 if magic == 0x20B else 96)
    secdir_offset = dd_start + 32  # Security directory is index 4

    # Step 1: Strip existing PE Authenticode signature
    old_va = struct.unpack_from('<I', data, secdir_offset)[0]
    if old_va > 0 and old_va < len(data):
        data = data[:old_va]

    # Generate self-signed certificate (used for both BIOSCR2 and PE cert)
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, "SD APCB Tool")])
    cert = (CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, _hashes.SHA256()))
    cert_der = cert.public_bytes(Encoding.DER)

    # Step 2: Handle Insyde _IFLASH internal integrity structures
    bioscer_off, bioscr2_off = _find_iflash_structures(bytes(data))

    if bioscer_off is not None and bioscr2_off is not None:
        # Found _IFLASH structures (Steam Deck .fd firmware)

        # 2a: Update ALL _IFLASH flags to QA/self-signed mode
        # DeckHD changes flags on 5 of 6 structures (not just BIOSCER/BIOSCR2)
        _update_iflash_flags(data)

        # 2b: Determine the original BIOSCR2 slot size.
        # The slot extends from the cert offset to SizeOfImage (len(data) after
        # Step 1 stripped the PE cert).  This may include zero padding beyond
        # the WIN_CERTIFICATE's dwLength (OLED stock has 16 bytes of padding).
        # Using the full slot ensures we resize correctly so our new WC ends
        # exactly at SizeOfImage with zero gap, matching DeckHD's layout.
        bioscr2_cert_off = bioscr2_off + _IFLASH_BIOSCR2_CERT_OFFSET
        old_bioscr2_slot = len(data) - bioscr2_cert_off

        # 2c: Preserve _IFLASH_BIOSCER hash — the hash algorithm is proprietary
        # and unknown, so we leave the original hash bytes untouched.  DeckHD
        # also preserves the stock BIOSCER hash when it re-signs firmware.

        # 2d: Re-sign _IFLASH_BIOSCR2 with our self-signed certificate
        # Build a PKCS#7 signature for the BIOSCR2 slot using the same
        # Authenticode hash format. We use the PE hash of the body data
        # (with security dir and checksum zeroed) as the signed content.
        bioscr2_body = bytearray(data)
        struct.pack_into('<I', bioscr2_body, secdir_offset, 0)
        struct.pack_into('<I', bioscr2_body, secdir_offset + 4, 0)
        struct.pack_into('<I', bioscr2_body, checksum_offset, 0)
        bioscr2_hash = _compute_authenticode_hash(bytes(bioscr2_body))
        bioscr2_pkcs7 = _build_pkcs7(bioscr2_hash, cert_der, key, now)
        bioscr2_wc = _build_win_certificate(bioscr2_pkcs7)

        # Write the new BIOSCR2 WIN_CERTIFICATE and maintain layout invariant:
        #   SizeOfImage == SecDir VA == bioscr2_cert_off + len(bioscr2_wc)
        # DeckHD follows this rule: BIOSCR2 WC ends exactly at SizeOfImage,
        # and the PE cert starts right there with zero gap.
        # We compare against the full slot (which may include padding), not
        # just the old WC dwLength, to eliminate any stock padding.
        delta = len(bioscr2_wc) - old_bioscr2_slot
        old_slot_end = bioscr2_cert_off + old_bioscr2_slot

        if delta > 0:
            # New cert is larger than slot — write what fits, insert the rest
            data[bioscr2_cert_off:old_slot_end] = bioscr2_wc[:old_bioscr2_slot]
            data[old_slot_end:old_slot_end] = bioscr2_wc[old_bioscr2_slot:]
        elif delta < 0:
            # New cert is smaller than slot — write it and remove excess bytes
            data[bioscr2_cert_off:bioscr2_cert_off + len(bioscr2_wc)] = bioscr2_wc
            del data[bioscr2_cert_off + len(bioscr2_wc):old_slot_end]
        else:
            # Same size as slot — simple overwrite
            data[bioscr2_cert_off:old_slot_end] = bioscr2_wc

        if delta != 0:
            # Update SizeOfImage in PE Optional Header to maintain layout invariant
            soi_offset = opt_start + 56
            old_soi = struct.unpack_from('<I', data, soi_offset)[0]
            struct.pack_into('<I', data, soi_offset, old_soi + delta)

    # Step 3: Clear header fields for PE hash computation
    struct.pack_into('<I', data, secdir_offset, 0)
    struct.pack_into('<I', data, secdir_offset + 4, 0)
    struct.pack_into('<I', data, checksum_offset, 0)

    # Step 4: Compute PE Authenticode hash (now includes updated BIOSCER + BIOSCR2)
    pe_hash = _compute_authenticode_hash(bytes(data))

    # Step 5: Build PE PKCS#7 SignedData
    pkcs7 = _build_pkcs7(pe_hash, cert_der, key, now)

    # Step 6: Build and append WIN_CERTIFICATE
    win_cert = _build_win_certificate(pkcs7)
    cert_offset = len(data)
    struct.pack_into('<I', data, secdir_offset, cert_offset)
    struct.pack_into('<I', data, secdir_offset + 4, len(win_cert))
    data.extend(win_cert)

    # Step 7: Compute and write PE checksum
    checksum = _compute_pe_checksum(bytes(data))
    struct.pack_into('<I', data, checksum_offset, checksum)

    # Self-check: verify the Authenticode hash matches what we signed
    verify_data = bytearray(data[:cert_offset])
    struct.pack_into('<I', verify_data, secdir_offset, 0)
    struct.pack_into('<I', verify_data, secdir_offset + 4, 0)
    struct.pack_into('<I', verify_data, checksum_offset, 0)
    verify_hash = _compute_authenticode_hash(bytes(verify_data))
    if verify_hash != pe_hash:
        raise RuntimeError(
            "Signing self-check FAILED: Authenticode hash mismatch. "
            f"Expected {pe_hash.hex()}, got {verify_hash.hex()}")

    return bytes(data)


# ============================================================================
# DeckHD Screen Patch
# ============================================================================

def find_edid_blocks(data: bytes) -> List[Tuple[int, bytes]]:
    """Find all EDID blocks in firmware by scanning for EDID magic.

    Returns list of (offset, edid_128_bytes) tuples.
    Only returns blocks with valid EDID checksums.
    """
    blocks = []
    pos = 0
    while pos < len(data) - 128:
        idx = data.find(EDID_MAGIC, pos)
        if idx == -1:
            break
        edid = data[idx:idx + 128]
        # Validate EDID checksum (all 128 bytes must sum to 0 mod 256)
        if len(edid) == 128 and sum(edid) % 256 == 0:
            blocks.append((idx, edid))
        pos = idx + 1
    return blocks


def patch_screen(data: bytearray, screen_key: str) -> List[Tuple[int, str]]:
    """Apply screen replacement patches to Steam Deck LCD firmware.

    Patches:
      1. Replace stock/other EDID blocks with the target screen's EDID
      2. Append screen version tag to $BVDT$ version strings

    Args:
        data: Mutable bytearray of firmware (modified in place)
        screen_key: Key into SCREEN_PROFILES ('deckhd' or 'decksight')

    Returns:
        List of (offset, description) tuples for logging
    """
    profile = SCREEN_PROFILES[screen_key]
    target_edid = profile['edid']
    target_mfr_id = profile['mfr_id']
    version_tag = profile['version_tag']
    screen_name = profile['name']
    patches = []

    # --- Patch EDID blocks ---
    edid_blocks = find_edid_blocks(bytes(data))
    for offset, edid in edid_blocks:
        # Skip if already this screen's EDID
        if edid[8:10] == target_mfr_id:
            continue
        # Skip if it belongs to another known screen replacement
        if any(edid[8:10] == mid for mid in SCREEN_MFR_IDS):
            continue
        # Filter: must look like a Steam Deck panel (small physical size, portrait)
        # EDID bytes 21-22: max H/V size in cm. Steam Deck LCD ~10x15cm
        h_cm, v_cm = edid[21], edid[22]
        if not (5 <= h_cm <= 20 and 5 <= v_cm <= 25):
            continue
        # Replace with target screen EDID
        data[offset:offset + 128] = target_edid
        patches.append((offset, f"EDID replaced with {screen_name}"))

    # --- Patch $BVDT$ version strings ---
    pos = 0
    while pos < len(data) - 64:
        idx = data.find(BVDT_MAGIC, pos)
        if idx == -1:
            break
        # Version string is at offset +0x0E from $BVDT$ magic
        ver_offset = idx + 0x0E
        if ver_offset + 32 > len(data):
            pos = idx + 1
            continue
        # Read current version string (null-terminated within ~32 byte field)
        ver_field = data[ver_offset:ver_offset + 32]
        null_end = ver_field.find(0x00)
        if null_end < 0:
            null_end = 32
        current_ver = ver_field[:null_end].decode('ascii', errors='replace')
        if version_tag not in current_ver:
            new_ver = current_ver + ' ' + version_tag
            # Write back with null padding (don't exceed field)
            new_bytes = new_ver.encode('ascii')[:32]
            new_bytes = new_bytes + b'\x00' * (32 - len(new_bytes))
            data[ver_offset:ver_offset + 32] = new_bytes
            patches.append((ver_offset, f"Version string: '{current_ver}' -> '{new_ver}'"))
        pos = idx + 1

    return patches


# ============================================================================
# Modification Engine
# ============================================================================

def modify_bios(input_path: str, output_path: str, target_gb: int,
                modify_magic_byte: bool = False, entry_indices: Optional[List[int]] = None,
                sign_output: bool = False, device: str = 'auto',
                screen: Optional[str] = None):
    """
    Modify BIOS file for target memory configuration.

    Args:
        input_path: Path to input BIOS file
        output_path: Path for modified output file
        target_gb: Target memory size in GB (16, 32, or 64)
        modify_magic_byte: If True, change APCB byte[0] from 0x41 to 0x51 (cosmetic only)
        entry_indices: Which SPD entries to modify (0-based). None = first entry only.
        sign_output: If True, re-sign the firmware with PE Authenticode for h2offt
        device: Device type ('auto', 'steam_deck', 'rog_ally', 'rog_ally_x')
    """

    if target_gb not in MEMORY_CONFIGS:
        print(f"\n  ERROR: Unsupported target size: {target_gb}GB")
        print(f"  Supported: {', '.join(f'{k}GB' for k in MEMORY_CONFIGS.keys())}")
        sys.exit(1)

    config = MEMORY_CONFIGS[target_gb]

    # Read input file
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    # Device detection
    if device == 'auto':
        device = detect_device(bytes(data))
    device_profile = DEVICE_PROFILES.get(device)
    device_name = device_profile['name'] if device_profile else 'Unknown Device'

    # Check memory target compatibility with device
    if device_profile and target_gb not in device_profile['memory_targets']:
        print(f"\n  WARNING: {target_gb}GB is not a validated target for {device_name}.")
        print(f"  Validated targets: {', '.join(f'{t}GB' for t in device_profile['memory_targets'])}")
        print(f"  Proceeding anyway — use at your own risk.")

    # Check signing compatibility
    if sign_output and device_profile and not device_profile['supports_signing']:
        print(f"\n  WARNING: {device_name} does not support firmware signing.")
        print(f"  The --sign flag will be ignored. Use SPI flash instead.")
        sign_output = False

    print(f"\n{'='*78}")
    print(f"  APCB Memory Modification Tool v{TOOL_VERSION}")
    print(f"{'='*78}")
    print(f"\n  Device: {device_name}")
    print(f"  Input:  {os.path.basename(input_path)}")
    print(f"  Output: {os.path.basename(output_path)}")
    print(f"  Target: {config['name']}")
    print(f"  {config['description']}")
    if sign_output:
        print(f"  Signing: ENABLED (PE Authenticode for h2offt)")

    print(f"\n  File size: {len(data):,} bytes")

    # Apply screen replacement patch if requested
    if screen:
        if device != 'steam_deck':
            screen_name = SCREEN_PROFILES[screen]['name']
            print(f"\n  ERROR: {screen_name} screen patch is only supported for Steam Deck LCD.")
            print(f"  Detected device: {device_name}")
            sys.exit(1)
        screen_profile = SCREEN_PROFILES[screen]
        print(f"\n  {'-'*74}")
        print(f"  SCREEN REPLACEMENT: {screen_profile['name'].upper()}")
        print(f"  {'-'*74}")
        print(f"  {screen_profile['description']}")
        screen_patches = patch_screen(data, screen)
        if screen_patches:
            for offset, desc in screen_patches:
                print(f"    0x{offset:08X}: {desc}")
            print(f"  Screen patches applied: {len(screen_patches)}")
        else:
            print(f"  WARNING: No patchable EDID or version blocks found.")
            print(f"  The firmware may already have {screen_profile['name']} patches applied.")

    # Find APCB blocks
    blocks = find_apcb_blocks(bytes(data))
    memg_blocks = [b for b in blocks if b.is_memg]
    
    if not memg_blocks:
        print(f"\n  ERROR: No APCB MEMG blocks found in the BIOS image!")
        print(f"  This file may not be a supported device BIOS.")
        print(f"  Supported devices: {', '.join(p['name'] for p in DEVICE_PROFILES.values())}")
        sys.exit(1)
    
    print(f"\n  Found {len(memg_blocks)} APCB MEMG block(s) to modify")
    
    modifications = []
    
    for block_idx, block in enumerate(memg_blocks):
        print(f"\n  Processing MEMG block {block_idx + 1} at 0x{block.offset:08X}...")
        
        if not block.spd_entries:
            print(f"    WARNING: No SPD entries found in this block, skipping")
            continue
        
        # Determine which entries to modify (default: all entries)
        if entry_indices == 'all' or entry_indices is None:
            indices = list(range(len(block.spd_entries)))
        else:
            indices = entry_indices
        
        for eidx in indices:
            if eidx >= len(block.spd_entries):
                print(f"    WARNING: Entry index {eidx} out of range (max {len(block.spd_entries)-1})")
                continue
            
            entry = block.spd_entries[eidx]
            
            # Calculate absolute file offsets for the two key bytes
            byte6_offset = entry.offset_in_file + 6
            byte12_offset = entry.offset_in_file + 12
            
            old_byte6 = data[byte6_offset]
            old_byte12 = data[byte12_offset]
            
            print(f"    Entry {eidx+1} ({entry.module_name}):")
            print(f"      byte[6]  @ 0x{byte6_offset:08X}: 0x{old_byte6:02X} -> 0x{config['byte6']:02X}")
            print(f"      byte[12] @ 0x{byte12_offset:08X}: 0x{old_byte12:02X} -> 0x{config['byte12']:02X}")
            
            # Apply modifications
            data[byte6_offset] = config['byte6']
            data[byte12_offset] = config['byte12']
            
            modifications.append((byte6_offset, old_byte6, config['byte6']))
            modifications.append((byte12_offset, old_byte12, config['byte12']))
        
        # Optionally modify APCB magic byte[0]
        if modify_magic_byte and target_gb == 32:
            old_b0 = data[block.offset]
            new_b0 = 0x51
            if old_b0 != new_b0:
                print(f"    APCB byte[0] @ 0x{block.offset:08X}: 0x{old_b0:02X} -> 0x{new_b0:02X}")
                data[block.offset] = new_b0
                modifications.append((block.offset, old_b0, new_b0))
        elif modify_magic_byte and target_gb == 16:
            old_b0 = data[block.offset]
            new_b0 = 0x41  # 'A' for APCB
            if old_b0 != new_b0:
                print(f"    APCB byte[0] @ 0x{block.offset:08X}: 0x{old_b0:02X} -> 0x{new_b0:02X} (restore)")
                data[block.offset] = new_b0
                modifications.append((block.offset, old_b0, new_b0))
        
        # Recalculate checksum for this APCB block
        block_data = data[block.offset:block.offset + block.data_size]
        new_checksum = calculate_apcb_checksum(bytes(block_data))
        old_checksum = data[block.offset + APCB_CHECKSUM_OFFSET]
        
        if old_checksum != new_checksum:
            data[block.offset + APCB_CHECKSUM_OFFSET] = new_checksum
            print(f"    Checksum @ 0x{block.offset + APCB_CHECKSUM_OFFSET:08X}: "
                  f"0x{old_checksum:02X} -> 0x{new_checksum:02X}")
            modifications.append((block.offset + APCB_CHECKSUM_OFFSET, old_checksum, new_checksum))
        
        # Verify checksum
        final_block = data[block.offset:block.offset + block.data_size]
        if verify_apcb_checksum(bytes(final_block)):
            print(f"    Checksum verification: PASS")
        else:
            print(f"    Checksum verification: FAIL - THIS IS A BUG!")
            sys.exit(1)
    
    # Summary
    print(f"\n  {'-'*74}")
    print(f"  MODIFICATION SUMMARY")
    print(f"  {'-'*74}")
    print(f"  Total byte changes: {len(modifications)}")
    print(f"  MEMG blocks modified: {len(memg_blocks)}")
    
    if modifications:
        print(f"\n  All modifications:")
        for offset, old, new in modifications:
            print(f"    0x{offset:08X}: 0x{old:02X} -> 0x{new:02X}")
    
    # Sign if requested
    output_data = bytes(data)
    
    if sign_output:
        print(f"\n  {'-'*74}")
        print(f"  PE AUTHENTICODE SIGNING")
        print(f"  {'-'*74}")
        
        if not _check_signing_available():
            print(f"\n  ERROR: Signing requires the 'cryptography' Python package.")
            print(f"  Install it with: pip install cryptography")
            print(f"\n  On SteamOS, use a virtual environment:")
            print(f"    python -m venv --system-site-packages ~/sd-apcb-venv")
            print(f"    source ~/sd-apcb-venv/bin/activate")
            print(f"    pip install cryptography")
            print(f"    python sd_apcb_tool.py modify ...")
            sys.exit(1)
        
        # Check if this is actually a PE file
        if data[:2] != b'MZ':
            print(f"\n  WARNING: File does not appear to be a PE firmware file.")
            print(f"  Signing is only applicable to .fd firmware update files,")
            print(f"  not raw SPI dumps. Skipping signing.")
        else:
            print(f"  Stripping existing Authenticode signature...")
            print(f"  Generating self-signed RSA-2048 certificate (CN=SD APCB Tool)...")
            print(f"  Computing PE Authenticode SHA-256 hash...")
            print(f"  Building PKCS#7 SignedData...")
            
            try:
                output_data = sign_firmware(bytes(data))
                print(f"  Signing complete [OK]")
                print(f"  Signed file size: {len(output_data):,} bytes")
            except Exception as e:
                print(f"\n  ERROR: Signing failed: {e}")
                print(f"  The unsigned modified file will still be written.")
                print(f"  You can use it with SPI flash, or sign manually with osslsigncode.")
                output_data = bytes(data)
                sign_output = False
    
    # Write output
    with open(output_path, 'wb') as f:
        f.write(output_data)
    
    output_size = os.path.getsize(output_path)
    print(f"\n  Output written: {output_path}")
    print(f"  Output size: {output_size:,} bytes")
    
    # Verify output
    print(f"\n  Verifying output file...")
    with open(output_path, 'rb') as f:
        verify_data = f.read()
    
    verify_blocks = find_apcb_blocks(verify_data)
    verify_memg = [b for b in verify_blocks if b.is_memg]
    
    all_ok = True
    for vb in verify_memg:
        if not vb.checksum_valid:
            print(f"    FAIL: MEMG block at 0x{vb.offset:08X} has invalid checksum!")
            all_ok = False
        elif vb.spd_entries:
            # Verify the same entries that were modified
            if entry_indices == 'all' or entry_indices is None:
                check_indices = list(range(len(vb.spd_entries)))
            else:
                check_indices = entry_indices
            print(f"    Block 0x{vb.offset:08X}: checksum VALID")
            for eidx in check_indices:
                if eidx >= len(vb.spd_entries): continue
                e = vb.spd_entries[eidx]
                status = "OK" if e.byte6 == config['byte6'] and e.byte12 == config['byte12'] else "MISMATCH"
                if status == "MISMATCH": all_ok = False
                print(f"      [{eidx+1}] byte6=0x{e.byte6:02X} byte12=0x{e.byte12:02X} [{status}]")
    
    if all_ok:
        print(f"\n  *** MODIFICATION SUCCESSFUL ***")
        if sign_output:
            print(f"  Output is signed and ready for h2offt software flash.")
            flash_cmd = device_profile['flash_instructions'].format(filename=os.path.basename(output_path)) if device_profile else ''
            if flash_cmd:
                print(f"  Flash with: {flash_cmd}")
        else:
            if device_profile and device_profile['supports_signing']:
                print(f"  Output file is ready for SPI flash.")
                print(f"  NOTE: For h2offt software flash, re-run with --sign flag.")
            else:
                print(f"  Output file is ready for SPI flash.")
                flash_instr = device_profile['flash_instructions'] if device_profile else 'Flash via SPI programmer'
                print(f"  {flash_instr}")
    else:
        print(f"\n  *** VERIFICATION FAILED ***")
        print(f"  DO NOT flash this file! Check for errors above.")
    
    return modifications


# ============================================================================
# Interactive Mode — DiskPart-style REPL
# ============================================================================

# ANSI color helpers (Windows 10+ supports VT100 natively)
class _C:
    """Terminal color codes for interactive output."""
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    GRAY    = '\033[90m'

    # Semantic aliases
    HEADER  = BOLD + CYAN
    OK      = GREEN
    WARN    = YELLOW
    ERR     = RED
    PROMPT  = BOLD + WHITE
    VALUE   = CYAN
    PENDING = YELLOW
    LABEL   = GRAY


def _enable_ansi_colors():
    """Enable ANSI escape codes on Windows."""
    if sys.platform == 'win32':
        os.system('')  # Triggers VT100 mode on Windows 10+


# Known module name prefixes — used for SET NAME validation
MODULE_NAME_PREFIXES = [
    ('MT6', 'Micron LPDDR5/5X'),
    ('K3K', 'Samsung LPDDR5'),
    ('K3L', 'Samsung LPDDR5X'),
    ('H58', 'SK Hynix LPDDR5/5X'),
    ('H9H', 'SK Hynix LPDDR5/5X'),
    ('SEC', 'Samsung (alt)'),
    ('SAM', 'Samsung (alt)'),
]
VALID_PREFIXES = [pfx for pfx, _ in MODULE_NAME_PREFIXES]


@dataclass
class PendingEntryMod:
    """A pending modification to a single SPD entry."""
    index: int
    target_gb: int
    new_name: Optional[str] = None


@dataclass
class InteractiveState:
    """Tracks all state for the interactive modify session."""
    input_path: str
    output_path: str
    data: bytearray
    device_key: str
    device_profile: dict
    blocks: List[APCBBlock]
    all_entries: List[SPDEntry]
    entry_mods: dict                       # index -> PendingEntryMod
    sign_enabled: bool = False
    magic_enabled: bool = False
    screen_patch: Optional[str] = None
    selected_entry: Optional[int] = None   # 0-based index, None = no selection
    current_menu: str = 'main'


def modify_bios_data(data: bytearray, entry_modifications: list,
                     modify_magic: bool = False) -> list:
    """Modify BIOS data with per-entry configurations.

    Args:
        data: bytearray of BIOS (modified in place)
        entry_modifications: list of dicts with keys:
            'index': int - SPD entry index
            'target_gb': int - 16, 32, or 64
            'new_name': str|None - new module name or None to keep current
        modify_magic: bool - modify APCB magic byte
    Returns:
        list of (offset, old_byte, new_byte) tuples
    """
    blocks = find_apcb_blocks(bytes(data))
    mods = []
    mod_by_idx = {m['index']: m for m in entry_modifications}
    first_target = entry_modifications[0]['target_gb'] if entry_modifications else 32
    for block in [b for b in blocks if b.is_memg]:
        if not block.spd_entries:
            continue
        for idx, mod in mod_by_idx.items():
            if idx >= len(block.spd_entries):
                continue
            e = block.spd_entries[idx]
            config = MEMORY_CONFIGS[mod['target_gb']]
            b6, b12 = e.offset_in_file + 6, e.offset_in_file + 12
            mods.append((b6, data[b6], config['byte6']))
            mods.append((b12, data[b12], config['byte12']))
            data[b6] = config['byte6']
            data[b12] = config['byte12']
            new_name = mod.get('new_name')
            if new_name is not None and e.module_name_offset >= 0 and e.module_name_field_len > 0:
                name_bytes = new_name.encode('ascii', errors='replace')[:e.module_name_field_len]
                name_bytes = name_bytes + b'\x00' * (e.module_name_field_len - len(name_bytes))
                for i, nb in enumerate(name_bytes):
                    off = e.module_name_offset + i
                    if data[off] != nb:
                        mods.append((off, data[off], nb))
                        data[off] = nb
        if modify_magic:
            nb = 0x51 if first_target == 32 else 0x41
            if data[block.offset] != nb:
                mods.append((block.offset, data[block.offset], nb))
                data[block.offset] = nb
        bb = data[block.offset:block.offset + block.data_size]
        nc = calculate_apcb_checksum(bytes(bb))
        oc = data[block.offset + APCB_CHECKSUM_OFFSET]
        if oc != nc:
            data[block.offset + APCB_CHECKSUM_OFFSET] = nc
            mods.append((block.offset + APCB_CHECKSUM_OFFSET, oc, nc))
        if not verify_apcb_checksum(bytes(data[block.offset:block.offset + block.data_size])):
            raise RuntimeError(f"Checksum failed at 0x{block.offset:08X}")
    return mods


def _parse_command(raw: str):
    """Parse interactive input into (command, args) tuple."""
    parts = raw.strip().split()
    if not parts:
        return ('', [])
    cmd = parts[0].lower()
    args = parts[1:]
    # Compound commands
    if cmd == 'set' and args:
        sub = args[0].lower()
        if sub in ('density', 'name', 'model'):
            return (f'set_{sub}', args[1:])
    if cmd == 'select' and args and args[0].lower() == 'all':
        return ('select_all', args[1:])
    if cmd == 'deselect' and args and args[0].lower() == 'all':
        return ('deselect_all', args[1:])
    return (cmd, args)


def _build_prompt(state: InteractiveState) -> str:
    """Build the context-sensitive prompt string."""
    c = _C
    dev = state.device_profile['name'] if state.device_profile else 'Unknown'
    base = f"{c.PROMPT}APCB [{dev}]"
    if state.current_menu == 'spd':
        if state.selected_entry is not None:
            return f"{base} SPD [Entry {state.selected_entry + 1}] > {c.RESET}"
        return f"{base} SPD > {c.RESET}"
    elif state.current_menu == 'screen':
        return f"{base} SCREEN > {c.RESET}"
    return f"{base} > {c.RESET}"


def _density_from_bytes(byte6: int, byte12: int) -> str:
    """Map byte6/byte12 to a density string."""
    for gb, cfg in MEMORY_CONFIGS.items():
        if cfg['byte6'] == byte6 and cfg['byte12'] == byte12:
            return f"{gb}GB"
    return "??GB"


def _print_welcome(state: InteractiveState):
    """Print the welcome banner on entering interactive mode."""
    c = _C
    dev = state.device_profile['name'] if state.device_profile else 'Unknown'
    mc = sum(1 for b in state.blocks if b.is_memg)
    tc = sum(1 for b in state.blocks if b.content_type == 'TOKN')
    lp5 = sum(1 for e in state.all_entries if e.mem_type == 'LPDDR5')
    lp5x = sum(1 for e in state.all_entries if e.mem_type == 'LPDDR5X')
    types = ', '.join(filter(None, [f"{lp5} LPDDR5" if lp5 else "", f"{lp5x} LPDDR5X" if lp5x else ""]))
    # Detect current config from first entry (factual, no assumptions)
    cur_cfg = "Unknown"
    if state.all_entries:
        cur_cfg = _density_from_bytes(state.all_entries[0].byte6, state.all_entries[0].byte12)

    print(f"\n{c.HEADER}  {'='*72}")
    print(f"    APCB Memory Configuration Tool v{TOOL_VERSION} -- Interactive Mode")
    print(f"  {'='*72}{c.RESET}")
    print(f"\n  {c.LABEL}Device:{c.RESET}  {c.VALUE}{dev}{c.RESET} (auto-detected)")
    print(f"  {c.LABEL}Input:{c.RESET}   {c.VALUE}{os.path.basename(state.input_path)}{c.RESET}"
          f" ({len(state.data):,} bytes)")
    print(f"  {c.LABEL}Output:{c.RESET}  {c.VALUE}{os.path.basename(state.output_path)}{c.RESET}")
    print(f"\n  {c.LABEL}APCB Blocks:{c.RESET} {len(state.blocks)} total ({mc} MEMG, {tc} TOKN)")
    print(f"  {c.LABEL}SPD Entries:{c.RESET}  {len(state.all_entries)} ({types})")
    print(f"  {c.LABEL}Current:{c.RESET}     {cur_cfg}")
    if state.sign_enabled:
        print(f"  {c.LABEL}Signing:{c.RESET}     {c.OK}ENABLED{c.RESET}")
    if state.screen_patch:
        sn = SCREEN_PROFILES[state.screen_patch]['name']
        print(f"  {c.LABEL}Screen:{c.RESET}      {c.VALUE}{sn}{c.RESET}")
    print(f"\n  Type {c.BOLD}HELP{c.RESET} for available commands.\n")


def _print_entry_table(state: InteractiveState):
    """Print the SPD entry table with pending changes."""
    c = _C
    entries = state.all_entries
    if not entries:
        print(f"  {c.WARN}No SPD entries found.{c.RESET}")
        return
    # Header
    print(f"\n  {c.HEADER}{'#':<4} {'Type':<9} {'Module':<24} {'Mfr':<9} {'Density':<7} "
          f"{'Dies':<8} {'Width':<6} {'Ranks':<6} {'Pending'}{c.RESET}")
    print(f"  {c.DIM}{'-'*95}{c.RESET}")
    for i, e in enumerate(entries):
        cur_den = _density_from_bytes(e.byte6, e.byte12)
        die_info = f"{e.die_count}x{e.die_density}" if e.die_count and e.die_density else '?'
        pending = ""
        row_color = ""
        if i in state.entry_mods:
            mod = state.entry_mods[i]
            parts = []
            if mod.target_gb != int(cur_den.replace('GB', '').replace('?', '0')):
                parts.append(f"{mod.target_gb}GB")
            if mod.new_name is not None:
                parts.append(f"name={mod.new_name}")
            if parts:
                pending = f"-> {', '.join(parts)}"
            else:
                pending = "(selected)"
            row_color = c.PENDING
        sel = "*" if state.selected_entry == i else " "
        name = e.module_name or '(unnamed)'
        mfr = e.manufacturer or '?'
        print(f"  {row_color}{sel}{i+1:<3} {e.mem_type:<9} {name:<24} "
              f"{mfr:<9} {cur_den:<7} "
              f"{die_info:<8} {e.dev_width:<6} {e.ranks}R    {pending}{c.RESET}")
    print()


def _print_status(state: InteractiveState):
    """Print full pending changes summary."""
    c = _C
    dev = state.device_profile['name'] if state.device_profile else 'Unknown'
    print(f"\n{c.HEADER}  {'='*72}")
    print(f"  PENDING CHANGES")
    print(f"  {'='*72}{c.RESET}")
    print(f"\n  {c.LABEL}Device:{c.RESET}   {dev}")
    print(f"  {c.LABEL}Input:{c.RESET}    {os.path.basename(state.input_path)}")
    print(f"  {c.LABEL}Output:{c.RESET}   {os.path.basename(state.output_path)}")
    sign_str = f"{c.OK}ENABLED{c.RESET}" if state.sign_enabled else f"{c.DIM}disabled{c.RESET}"
    print(f"  {c.LABEL}Signing:{c.RESET}  {sign_str}")
    magic_str = f"{c.OK}ENABLED{c.RESET}" if state.magic_enabled else f"{c.DIM}disabled{c.RESET}"
    print(f"  {c.LABEL}Magic:{c.RESET}    {magic_str}")
    if state.screen_patch:
        sn = SCREEN_PROFILES[state.screen_patch]['name']
        print(f"  {c.LABEL}Screen:{c.RESET}   {c.VALUE}{sn}{c.RESET}")
    else:
        print(f"  {c.LABEL}Screen:{c.RESET}   {c.DIM}(none){c.RESET}")

    if state.entry_mods:
        print(f"\n  {c.BOLD}SPD Entry Modifications ({len(state.entry_mods)} of {len(state.all_entries)}):{c.RESET}")
        print(f"  {c.DIM}{'-'*68}{c.RESET}")
        print(f"  {c.LABEL}{'#':<4} {'Current Module':<28} {'Current':<9} {'Target':<9} {'New Name'}{c.RESET}")
        print(f"  {c.DIM}{'-'*68}{c.RESET}")
        for idx in sorted(state.entry_mods.keys()):
            mod = state.entry_mods[idx]
            e = state.all_entries[idx]
            cur_den = _density_from_bytes(e.byte6, e.byte12)
            name = e.module_name or '(unnamed)'
            new_name = mod.new_name if mod.new_name is not None else f"{c.DIM}(unchanged){c.RESET}"
            print(f"  {idx+1:<4} {name:<28} {cur_den:<9} {c.PENDING}{mod.target_gb}GB{c.RESET}      {new_name}")
    else:
        print(f"\n  {c.DIM}No pending SPD modifications. Use SPD to select entries.{c.RESET}")
    print()


def _show_help(menu: str, state: InteractiveState):
    """Show context-sensitive help."""
    c = _C
    if menu == 'main':
        print(f"\n  {c.HEADER}Available Commands:{c.RESET}")
        print(f"  {c.BOLD}  LIST{c.RESET}          Show all SPD entries")
        print(f"  {c.BOLD}  SPD{c.RESET}           Enter SPD entry editor")
        print(f"  {c.BOLD}  SCREEN{c.RESET}        Enter screen patch selector (Steam Deck LCD only)")
        print(f"  {c.BOLD}  SIGN{c.RESET}          Toggle PE Authenticode signing")
        print(f"  {c.BOLD}  MAGIC{c.RESET}         Toggle APCB magic byte modification")
        print(f"  {c.BOLD}  STATUS{c.RESET}        Show all pending changes")
        print(f"  {c.BOLD}  APPLY{c.RESET}         Write changes to output file")
        print(f"  {c.BOLD}  HELP / ?{c.RESET}      Show this help")
        print(f"  {c.BOLD}  EXIT{c.RESET}          Quit without writing\n")
    elif menu == 'spd':
        targets = state.device_profile.get('memory_targets', [16, 32]) if state.device_profile else [16, 32]
        target_str = '/'.join(str(t) for t in targets)
        print(f"\n  {c.HEADER}SPD Entry Commands:{c.RESET}")
        print(f"  {c.BOLD}  LIST{c.RESET}                       Show entries with pending changes")
        print(f"  {c.BOLD}  SELECT <N>{c.RESET}                 Select entry N (1-based)")
        print(f"  {c.BOLD}  SELECT ALL{c.RESET}                 Mark all entries for modification")
        print(f"  {c.BOLD}  SET DENSITY <{target_str}>{c.RESET}    Set target density for selected entry")
        print(f"  {c.BOLD}  SET NAME <prefix> <suffix>{c.RESET}  Set module name (e.g. SET NAME MT6 2F1G32D4DR)")
        print(f"  {c.BOLD}  DESELECT{c.RESET}                   Remove selected entry from modifications")
        print(f"  {c.BOLD}  DESELECT ALL{c.RESET}               Clear all pending modifications")
        print(f"  {c.BOLD}  HELP / ?{c.RESET}                   Show this help")
        print(f"  {c.BOLD}  BACK{c.RESET}                       Return to main menu")
        print(f"\n  {c.LABEL}Valid name prefixes:{c.RESET}")
        for pfx, desc in MODULE_NAME_PREFIXES:
            print(f"    {c.VALUE}{pfx}{c.RESET}  {desc}")
        print()
    elif menu == 'screen':
        print(f"\n  {c.HEADER}Screen Patch Commands:{c.RESET}")
        print(f"  {c.BOLD}  LIST{c.RESET}              Show available screen profiles")
        print(f"  {c.BOLD}  SELECT <key>{c.RESET}      Select a screen profile")
        print(f"  {c.BOLD}  CLEAR{c.RESET}             Remove screen patch selection")
        print(f"  {c.BOLD}  HELP / ?{c.RESET}          Show this help")
        print(f"  {c.BOLD}  BACK{c.RESET}              Return to main menu\n")


def _apply_changes(state: InteractiveState) -> bool:
    """Apply all pending changes. Returns True if successful."""
    c = _C
    if not state.entry_mods and not state.screen_patch:
        print(f"  {c.WARN}No changes to apply. Use SPD or SCREEN to configure modifications.{c.RESET}")
        return False

    # Confirmation
    print(f"\n  {c.HEADER}Ready to apply:{c.RESET}")
    if state.entry_mods:
        targets = sorted(set(m.target_gb for m in state.entry_mods.values()))
        target_str = ', '.join(f"{t}GB" for t in targets)
        print(f"    {len(state.entry_mods)} SPD entry modification(s) ({target_str})")
    if state.screen_patch:
        print(f"    Screen: {SCREEN_PROFILES[state.screen_patch]['name']}")
    if state.sign_enabled:
        print(f"    Signing: ENABLED")
    print(f"    Output: {os.path.basename(state.output_path)}")

    try:
        resp = input(f"\n  {c.PROMPT}Proceed? [y/N]: {c.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {c.DIM}Cancelled.{c.RESET}")
        return False
    if resp not in ('y', 'yes'):
        print(f"  {c.DIM}Cancelled.{c.RESET}")
        return False

    # Work on a copy of the data
    data = bytearray(state.data)

    # 1. Apply screen patch
    if state.screen_patch:
        screen_name = SCREEN_PROFILES[state.screen_patch]['name']
        print(f"\n  {c.CYAN}Applying {screen_name} screen patch...{c.RESET}")
        screen_patches = patch_screen(data, state.screen_patch)
        if screen_patches:
            for off, desc in screen_patches:
                print(f"    0x{off:08X}: {desc}")
            print(f"  {c.OK}{screen_name}: {len(screen_patches)} patch(es) applied{c.RESET}")
        else:
            print(f"  {c.WARN}No patchable blocks found (may already be patched){c.RESET}")

    # 2. Apply SPD modifications
    if state.entry_mods:
        entry_mod_list = [
            {'index': mod.index, 'target_gb': mod.target_gb, 'new_name': mod.new_name}
            for mod in state.entry_mods.values()
        ]
        print(f"\n  {c.CYAN}Applying SPD modifications...{c.RESET}")
        try:
            mods = modify_bios_data(data, entry_mod_list, state.magic_enabled)
        except RuntimeError as e:
            print(f"  {c.ERR}ERROR: {e}{c.RESET}")
            return False
        print(f"  {c.OK}Byte changes: {len(mods)}{c.RESET}")
        for off, old, new in mods:
            print(f"    0x{off:08X}: 0x{old:02X} -> 0x{new:02X}")

    # 3. Sign if enabled
    output_data = bytes(data)
    if state.sign_enabled:
        if data[:2] != b'MZ':
            print(f"\n  {c.WARN}Not a PE file -- signing skipped.{c.RESET}")
        elif not _check_signing_available():
            print(f"\n  {c.ERR}Signing requires 'cryptography' package. Skipping.{c.RESET}")
        else:
            print(f"\n  {c.CYAN}Signing firmware (PE Authenticode RSA-2048/SHA-256)...{c.RESET}")
            try:
                output_data = sign_firmware(bytes(data))
                print(f"  {c.OK}Signed ({len(output_data):,} bytes){c.RESET}")
            except Exception as e:
                print(f"  {c.ERR}Sign failed: {e}{c.RESET}")
                output_data = bytes(data)

    # 4. Write output
    with open(state.output_path, 'wb') as f:
        f.write(output_data)
    print(f"\n  {c.OK}Output written:{c.RESET} {state.output_path} ({len(output_data):,} bytes)")

    # 5. Verify
    print(f"\n  {c.CYAN}Verifying output...{c.RESET}")
    with open(state.output_path, 'rb') as f:
        verify_data = f.read()
    verify_blocks = find_apcb_blocks(verify_data)
    all_ok = True
    for vb in verify_blocks:
        if not vb.is_memg:
            continue
        if not vb.checksum_valid:
            print(f"    {c.ERR}FAIL: Block 0x{vb.offset:08X} invalid checksum{c.RESET}")
            all_ok = False
        elif vb.spd_entries and state.entry_mods:
            print(f"    Block 0x{vb.offset:08X}: checksum {c.OK}VALID{c.RESET}")
            for idx, mod in state.entry_mods.items():
                if idx >= len(vb.spd_entries):
                    continue
                e = vb.spd_entries[idx]
                ecfg = MEMORY_CONFIGS[mod.target_gb]
                match = e.byte6 == ecfg['byte6'] and e.byte12 == ecfg['byte12']
                status = f"{c.OK}OK{c.RESET}" if match else f"{c.ERR}MISMATCH{c.RESET}"
                print(f"      [{idx+1}] b6=0x{e.byte6:02X} b12=0x{e.byte12:02X} [{status}]")
                if not match:
                    all_ok = False

    if all_ok:
        print(f"\n  {c.OK}{c.BOLD}*** MODIFICATION SUCCESSFUL ***{c.RESET}")
        if state.sign_enabled and data[:2] == b'MZ':
            flash_cmd = state.device_profile.get('flash_instructions', '').format(
                filename=os.path.basename(state.output_path)) if state.device_profile else ''
            if flash_cmd:
                print(f"  Flash with: {flash_cmd}")
        else:
            print(f"  Ready for SPI flash.")
    else:
        print(f"\n  {c.ERR}{c.BOLD}*** VERIFICATION FAILED ***{c.RESET}")
        print(f"  {c.ERR}DO NOT flash this file!{c.RESET}")
    print()
    return all_ok


def _handle_main_command(state: InteractiveState, cmd: str, args: list) -> Optional[str]:
    """Handle a main menu command. Returns 'exit' to quit."""
    c = _C
    if cmd == 'list':
        _print_entry_table(state)
    elif cmd == 'spd':
        state.current_menu = 'spd'
        _print_entry_table(state)
    elif cmd == 'screen':
        if state.device_key != 'steam_deck':
            dev = state.device_profile['name'] if state.device_profile else 'Unknown'
            print(f"  {c.WARN}Screen patches are only available for Steam Deck LCD.{c.RESET}")
            print(f"  {c.LABEL}Detected device: {dev}{c.RESET}")
            return None
        state.current_menu = 'screen'
        # Show current selection
        if state.screen_patch:
            sn = SCREEN_PROFILES[state.screen_patch]['name']
            print(f"  {c.LABEL}Current selection:{c.RESET} {c.VALUE}{sn}{c.RESET}")
        else:
            print(f"  {c.LABEL}Current selection:{c.RESET} {c.DIM}(none){c.RESET}")
    elif cmd == 'sign':
        if state.device_profile and not state.device_profile['supports_signing']:
            dev = state.device_profile['name'] if state.device_profile else 'Unknown'
            print(f"  {c.WARN}{dev} does not support firmware signing.{c.RESET}")
            print(f"  {c.LABEL}Use SPI flash for this device.{c.RESET}")
            return None
        state.sign_enabled = not state.sign_enabled
        status = f"{c.OK}ENABLED{c.RESET}" if state.sign_enabled else f"{c.DIM}DISABLED{c.RESET}"
        print(f"  PE Authenticode signing: {status}")
    elif cmd == 'magic':
        state.magic_enabled = not state.magic_enabled
        status = f"{c.OK}ENABLED{c.RESET}" if state.magic_enabled else f"{c.DIM}DISABLED{c.RESET}"
        print(f"  APCB magic byte modification: {status}")
    elif cmd == 'status':
        _print_status(state)
    elif cmd == 'apply':
        _apply_changes(state)
    elif cmd in ('help', '?'):
        _show_help('main', state)
    elif cmd in ('exit', 'quit', 'q'):
        return 'exit'
    elif cmd == '':
        pass
    else:
        print(f"  {c.WARN}Unknown command: {cmd}{c.RESET}")
        print(f"  Type {c.BOLD}HELP{c.RESET} for available commands.")
    return None


def _handle_spd_command(state: InteractiveState, cmd: str, args: list):
    """Handle an SPD submenu command."""
    c = _C
    entries = state.all_entries
    targets = state.device_profile.get('memory_targets', [16, 32]) if state.device_profile else [16, 32]
    default_target = max(t for t in targets if t <= 32) if any(t <= 32 for t in targets) else targets[0]

    if cmd == 'list':
        _print_entry_table(state)

    elif cmd == 'select':
        if not args:
            print(f"  {c.WARN}Usage: SELECT <N> (1-based entry number){c.RESET}")
            return
        try:
            n = int(args[0])
        except ValueError:
            print(f"  {c.ERR}Invalid entry number: {args[0]}{c.RESET}")
            return
        if n < 1 or n > len(entries):
            print(f"  {c.ERR}Entry {n} out of range (1-{len(entries)}){c.RESET}")
            return
        idx = n - 1
        state.selected_entry = idx
        # Add to mods if not already there
        if idx not in state.entry_mods:
            state.entry_mods[idx] = PendingEntryMod(index=idx, target_gb=default_target)
        e = entries[idx]
        mod = state.entry_mods[idx]
        name = e.module_name or '(unnamed)'
        cur = _density_from_bytes(e.byte6, e.byte12)
        die_info = f"{e.die_count}x{e.die_density}" if e.die_count and e.die_density else '?'
        print(f"\n  {c.OK}Entry {n} selected:{c.RESET} {c.VALUE}{name}{c.RESET}")
        print(f"    {c.LABEL}Type:{c.RESET}     {e.mem_type}  ({e.manufacturer or '?'})")
        print(f"    {c.LABEL}Density:{c.RESET}  {cur}  (b6=0x{e.byte6:02X}, b12=0x{e.byte12:02X})")
        print(f"    {c.LABEL}Package:{c.RESET}  {die_info} dies, {e.dev_width}, {e.ranks}R")
        if e.tAA_ns:
            print(f"    {c.LABEL}Timings:{c.RESET}  tAA={e.tAA_ns}ns  tRCD={e.tRCD_ns}ns  "
                  f"tRPab={e.tRPAB_ns}ns  tRPpb={e.tRPPB_ns}ns")
        if e.row_bits:
            print(f"    {c.LABEL}Address:{c.RESET}  {e.row_bits} rows, {e.col_bits} cols, "
                  f"{e.bank_groups}BG x {e.banks_per_group} banks")
        print(f"    {c.LABEL}Target:{c.RESET}   {c.PENDING}{mod.target_gb}GB{c.RESET}")
        print(f"  {c.DIM}Use SET DENSITY, SET NAME, or DESELECT.{c.RESET}")

    elif cmd == 'select_all':
        for i in range(len(entries)):
            if i not in state.entry_mods:
                state.entry_mods[i] = PendingEntryMod(index=i, target_gb=default_target)
        state.selected_entry = None
        print(f"  {c.OK}{len(entries)} entries selected for modification -> {default_target}GB{c.RESET}")

    elif cmd == 'set_density':
        if state.selected_entry is None:
            print(f"  {c.ERR}No entry selected. Use SELECT <N> first.{c.RESET}")
            return
        if not args:
            print(f"  {c.WARN}Usage: SET DENSITY <{'/'.join(str(t) for t in targets)}>{c.RESET}")
            return
        try:
            gb = int(args[0])
        except ValueError:
            print(f"  {c.ERR}Invalid density: {args[0]}{c.RESET}")
            return
        if gb not in targets:
            print(f"  {c.ERR}{gb}GB is not a valid target for this device.{c.RESET}")
            print(f"  {c.LABEL}Valid targets: {', '.join(f'{t}GB' for t in targets)}{c.RESET}")
            return
        idx = state.selected_entry
        if idx not in state.entry_mods:
            state.entry_mods[idx] = PendingEntryMod(index=idx, target_gb=gb)
        else:
            state.entry_mods[idx].target_gb = gb
        cfg = MEMORY_CONFIGS[gb]
        print(f"  {c.OK}Entry {idx+1} density set to {gb}GB{c.RESET}"
              f" (byte6=0x{cfg['byte6']:02X}, byte12=0x{cfg['byte12']:02X})")

    elif cmd in ('set_name', 'set_model'):
        if state.selected_entry is None:
            print(f"  {c.ERR}No entry selected. Use SELECT <N> first.{c.RESET}")
            return
        if not args:
            print(f"  {c.WARN}Usage: SET NAME <prefix> <suffix>{c.RESET}")
            print(f"  {c.LABEL}Example: SET NAME MT6 2F1G32D4DR-031{c.RESET}")
            print(f"  {c.LABEL}Valid prefixes: {', '.join(VALID_PREFIXES)}{c.RESET}")
            return
        prefix = args[0]
        # Match prefix case-insensitively
        matched_prefix = None
        for vp in VALID_PREFIXES:
            if prefix.upper() == vp.upper():
                matched_prefix = vp
                break
        if matched_prefix is None:
            print(f"  {c.ERR}Unknown prefix: {prefix}{c.RESET}")
            print(f"  {c.LABEL}Valid prefixes:{c.RESET}")
            for pfx, desc in MODULE_NAME_PREFIXES:
                print(f"    {c.VALUE}{pfx}{c.RESET}  {desc}")
            return
        suffix = ''.join(args[1:]) if len(args) > 1 else ''
        new_name = matched_prefix + suffix
        # Validate length
        idx = state.selected_entry
        e = entries[idx]
        if e.module_name_offset < 0 or e.module_name_field_len == 0:
            print(f"  {c.ERR}Entry {idx+1} has no editable name field.{c.RESET}")
            return
        if len(new_name) > e.module_name_field_len:
            print(f"  {c.ERR}Name too long: {len(new_name)} chars (max {e.module_name_field_len}){c.RESET}")
            return
        # Validate printable ASCII
        if not all(0x20 <= ord(ch) < 0x7F for ch in new_name):
            print(f"  {c.ERR}Name contains invalid characters (ASCII printable only){c.RESET}")
            return
        old_name = e.module_name or '(unnamed)'
        if idx not in state.entry_mods:
            state.entry_mods[idx] = PendingEntryMod(index=idx, target_gb=32, new_name=new_name)
        else:
            state.entry_mods[idx].new_name = new_name
        print(f"  {c.OK}Entry {idx+1} module name set to:{c.RESET} {c.VALUE}{new_name}{c.RESET}")
        print(f"  {c.DIM}(was: {old_name}){c.RESET}")

    elif cmd == 'deselect':
        if state.selected_entry is None:
            print(f"  {c.WARN}No entry selected.{c.RESET}")
            return
        idx = state.selected_entry
        if idx in state.entry_mods:
            del state.entry_mods[idx]
            print(f"  {c.OK}Entry {idx+1} removed from pending modifications.{c.RESET}")
        else:
            print(f"  {c.DIM}Entry {idx+1} was not in pending modifications.{c.RESET}")
        state.selected_entry = None

    elif cmd == 'deselect_all':
        count = len(state.entry_mods)
        state.entry_mods.clear()
        state.selected_entry = None
        print(f"  {c.OK}Cleared {count} pending modification(s).{c.RESET}")

    elif cmd == 'status':
        _print_status(state)

    elif cmd in ('help', '?'):
        _show_help('spd', state)

    elif cmd in ('back', 'exit', 'quit', 'q'):
        state.current_menu = 'main'
        state.selected_entry = None

    elif cmd == '':
        pass

    else:
        print(f"  {c.WARN}Unknown SPD command: {cmd}{c.RESET}")
        print(f"  Type {c.BOLD}HELP{c.RESET} for available commands.")


def _handle_screen_command(state: InteractiveState, cmd: str, args: list):
    """Handle a screen submenu command."""
    c = _C

    if cmd == 'list':
        print(f"\n  {c.HEADER}Available Screen Profiles:{c.RESET}")
        print(f"  {c.DIM}{'-'*60}{c.RESET}")
        for key, prof in SCREEN_PROFILES.items():
            sel = " *" if state.screen_patch == key else ""
            print(f"    {c.VALUE}{key:<12}{c.RESET} {prof['name']:<18} {c.LABEL}{prof['description']}{c.RESET}{c.OK}{sel}{c.RESET}")
        print(f"\n  {c.LABEL}Current:{c.RESET} "
              f"{c.VALUE}{SCREEN_PROFILES[state.screen_patch]['name']}{c.RESET}" if state.screen_patch
              else f"\n  {c.LABEL}Current:{c.RESET} {c.DIM}(none){c.RESET}")
        print()

    elif cmd == 'select':
        if not args:
            print(f"  {c.WARN}Usage: SELECT <key>{c.RESET}")
            print(f"  {c.LABEL}Keys: {', '.join(SCREEN_PROFILES.keys())}{c.RESET}")
            return
        key = args[0].lower()
        if key not in SCREEN_PROFILES:
            print(f"  {c.ERR}Unknown screen: {key}{c.RESET}")
            print(f"  {c.LABEL}Available: {', '.join(SCREEN_PROFILES.keys())}{c.RESET}")
            return
        state.screen_patch = key
        sn = SCREEN_PROFILES[key]['name']
        print(f"  {c.OK}Screen patch selected: {sn}{c.RESET}")
        print(f"  {c.DIM}EDID blocks and $BVDT$ version strings will be patched on APPLY.{c.RESET}")

    elif cmd == 'clear':
        state.screen_patch = None
        print(f"  {c.OK}Screen patch cleared.{c.RESET}")

    elif cmd == 'status':
        if state.screen_patch:
            sn = SCREEN_PROFILES[state.screen_patch]['name']
            desc = SCREEN_PROFILES[state.screen_patch]['description']
            print(f"  {c.LABEL}Selected:{c.RESET} {c.VALUE}{sn}{c.RESET} ({desc})")
        else:
            print(f"  {c.DIM}No screen patch selected.{c.RESET}")

    elif cmd in ('help', '?'):
        _show_help('screen', state)

    elif cmd in ('back', 'exit', 'quit', 'q'):
        state.current_menu = 'main'

    elif cmd == '':
        pass

    else:
        print(f"  {c.WARN}Unknown SCREEN command: {cmd}{c.RESET}")
        print(f"  Type {c.BOLD}HELP{c.RESET} for available commands.")


def interactive_modify(input_path: str, output_path: str, device: str = 'auto',
                       sign_output: bool = False, magic: bool = False,
                       screen: Optional[str] = None):
    """Launch interactive DiskPart-style REPL for BIOS modification."""
    _enable_ansi_colors()
    c = _C

    # Load and analyze
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    if device == 'auto':
        device = detect_device(bytes(data))
    device_profile = DEVICE_PROFILES.get(device)

    blocks = find_apcb_blocks(bytes(data))
    memg_blocks = [b for b in blocks if b.is_memg]
    if not memg_blocks:
        print(f"  {c.ERR}No APCB MEMG blocks found. Not a supported BIOS file.{c.RESET}")
        return

    # Flatten entries from first MEMG block with SPD entries
    first_memg = next((b for b in memg_blocks if b.spd_entries), None)
    all_entries = first_memg.spd_entries if first_memg else []

    state = InteractiveState(
        input_path=input_path,
        output_path=output_path,
        data=data,
        device_key=device,
        device_profile=device_profile,
        blocks=blocks,
        all_entries=all_entries,
        entry_mods={},
        sign_enabled=sign_output,
        magic_enabled=magic,
        screen_patch=screen,
    )

    _print_welcome(state)

    # REPL
    while True:
        prompt = _build_prompt(state)
        try:
            raw = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {c.DIM}Aborted.{c.RESET}")
            return

        cmd, cmd_args = _parse_command(raw)

        if state.current_menu == 'main':
            result = _handle_main_command(state, cmd, cmd_args)
            if result == 'exit':
                return
        elif state.current_menu == 'spd':
            _handle_spd_command(state, cmd, cmd_args)
        elif state.current_menu == 'screen':
            _handle_screen_command(state, cmd, cmd_args)


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f'APCB Memory Configuration Tool v{TOOL_VERSION} (Steam Deck, ROG Ally)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze a BIOS file (auto-detects device):
    python sd_apcb_tool.py analyze my_bios_dump.bin

  Interactive mode (DiskPart-style per-entry editor):
    python sd_apcb_tool.py modify my_bios.fd my_bios_mod.fd

  Interactive with signing and screen patch pre-set:
    python sd_apcb_tool.py modify my_bios.fd my_bios_mod.fd --sign --screen deckhd

  Batch: modify for 32GB (SPI flash ready, no signing):
    python sd_apcb_tool.py modify my_bios.fd my_bios_32gb.fd --target 32

  Batch: modify for 32GB with signing (Steam Deck h2offt):
    python sd_apcb_tool.py modify my_bios.fd my_bios_32gb.fd --target 32 --sign

  Batch: modify for 64GB (ROG Ally X):
    python sd_apcb_tool.py modify my_bios.bin my_bios_64gb.bin --target 64

  Batch: restore to stock 16GB:
    python sd_apcb_tool.py modify my_bios_32gb.fd my_bios_stock.fd --target 16

Supported devices:
  Steam Deck (LCD & OLED): 16GB/32GB, SPI flash or h2offt (--sign)
  ROG Ally / Ally X: 16GB/32GB/64GB, SPI flash only (signing not supported)

  Omit --target for interactive mode. The --sign flag requires: pip install cryptography
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze BIOS file')
    analyze_parser.add_argument('bios_file', help='BIOS file to analyze')
    analyze_parser.add_argument('--device', choices=['auto', 'steam_deck', 'rog_ally', 'rog_ally_x'],
                                default='auto', help='Device type (default: auto-detect)')
    
    # Modify command
    modify_parser = subparsers.add_parser('modify', help='Modify BIOS for target memory')
    modify_parser.add_argument('bios_in', help='Input BIOS file')
    modify_parser.add_argument('bios_out', help='Output BIOS file')
    modify_parser.add_argument('--target', type=int, default=None, choices=[16, 32, 64],
                              help='Target memory size in GB (omit for interactive mode)')
    modify_parser.add_argument('--sign', action='store_true',
                              help='Re-sign firmware with PE Authenticode for h2offt software flash. '
                                   'Requires: pip install cryptography')
    modify_parser.add_argument('--magic', action='store_true',
                              help='Modify APCB magic byte[0] (0x41->0x51). Cosmetic marker only, '
                                   'not required for the mod. LCD known-good mods do NOT change this.')
    modify_parser.add_argument('--all-entries', action='store_true',
                              help='Modify ALL SPD entries (this is now the default behavior)')
    modify_parser.add_argument('--entry', type=int, action='append',
                              help='Specific entry index to modify (0-based, can repeat)')
    modify_parser.add_argument('--device', choices=['auto', 'steam_deck', 'rog_ally', 'rog_ally_x'],
                              default='auto', help='Device type (default: auto-detect)')
    modify_parser.add_argument('--screen', choices=list(SCREEN_PROFILES.keys()),
                              default=None, metavar='SCREEN',
                              help='Apply screen replacement patch (Steam Deck LCD only). '
                                   f'Choices: {", ".join(SCREEN_PROFILES.keys())}. '
                                   'Replaces EDID and tags version string.')
    # Keep --deckhd as a convenience alias
    modify_parser.add_argument('--deckhd', action='store_true',
                              help='Shortcut for --screen deckhd')

    args = parser.parse_args()
    
    if args.command == 'analyze':
        analyze_bios(args.bios_file, device=args.device)
        
    elif args.command == 'modify':
        if args.bios_in == args.bios_out:
            print("\n  ERROR: Input and output must be different files (safety measure)")
            sys.exit(1)

        # Resolve screen option (--deckhd is shortcut for --screen deckhd)
        screen = args.screen
        if args.deckhd and not screen:
            screen = 'deckhd'

        if args.target is not None:
            # Batch mode: existing modify_bios() flow
            entry_indices = None
            if args.all_entries:
                entry_indices = 'all'
            elif args.entry:
                entry_indices = args.entry

            modify_bios(
                args.bios_in,
                args.bios_out,
                args.target,
                modify_magic_byte=args.magic,
                entry_indices=entry_indices,
                sign_output=args.sign,
                device=args.device,
                screen=screen,
            )
        else:
            # Interactive mode
            interactive_modify(
                args.bios_in,
                args.bios_out,
                device=args.device,
                sign_output=args.sign,
                magic=args.magic,
                screen=screen,
            )
    else:
        # No subcommand — prompt for file paths and enter interactive mode
        _enable_ansi_colors()
        c = _C
        print(f"\n{c.HEADER}  APCB Memory Configuration Tool v{TOOL_VERSION}{c.RESET}")
        print(f"  {c.DIM}No command specified -- entering interactive mode.{c.RESET}\n")
        try:
            input_path = input(f"  {c.PROMPT}Input BIOS file path: {c.RESET}").strip().strip('"').strip("'")
            if not input_path:
                print(f"  {c.ERR}No file specified.{c.RESET}")
                sys.exit(1)
            if not os.path.isfile(input_path):
                print(f"  {c.ERR}File not found: {input_path}{c.RESET}")
                sys.exit(1)
            # Generate default output name
            from pathlib import Path
            p = Path(input_path)
            default_out = str(p.parent / f"{p.stem}_modified{p.suffix}")
            output_path = input(f"  {c.PROMPT}Output file path [{os.path.basename(default_out)}]: {c.RESET}").strip().strip('"').strip("'")
            if not output_path:
                output_path = default_out
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {c.DIM}Aborted.{c.RESET}")
            sys.exit(0)
        if os.path.abspath(input_path) == os.path.abspath(output_path):
            print(f"  {c.ERR}Input and output must be different files.{c.RESET}")
            sys.exit(1)
        interactive_modify(input_path, output_path)


def _is_transient_window() -> bool:
    """Detect if we're in a transient console window that will close on exit.

    On Windows, double-clicking a .py file (or running via 'start python ...')
    opens a new console window that disappears the moment the process exits.
    We detect this by checking whether our console process is the root of its
    console session -- if so, the window was created just for us.
    """
    if sys.platform != 'win32':
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # GetConsoleProcessList returns the number of processes attached
        # to the current console.  If we're the only one, this is a
        # transient window that will vanish when we exit.
        pid_array = (ctypes.c_uint32 * 16)()
        count = kernel32.GetConsoleProcessList(pid_array, 16)
        return count <= 1
    except Exception:
        # If anything goes wrong, be safe and assume it's transient
        # when running on Windows with no explicit subcommand
        return len(sys.argv) <= 1


def _pause_before_exit():
    """Pause so the user can read output before a transient window closes."""
    try:
        input("\n  Press Enter to exit...")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == '__main__':
    _transient = _is_transient_window()
    try:
        main()
    except SystemExit as e:
        if _transient or (sys.platform == 'win32' and e.code != 0):
            _pause_before_exit()
        raise
    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback
        traceback.print_exc()
        if sys.platform == 'win32':
            _pause_before_exit()
        sys.exit(1)
