#!/usr/bin/env python3
"""
APCB Memory Configuration Tool v1.8.0
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

Flashing:
  - SPI programmer (CH341A + SOIC8 clip): Writes raw .bin image directly to
    the flash chip. Supported by all devices.
  - .fd files: Use the manufacturer's update tool (e.g. h2offt for Steam Deck).

Supports:
  - Analysis mode: scans BIOS and reports all APCB blocks and SPD entries
  - Modify mode: patches SPD parameters for target memory configuration
  - Automatic device detection (Steam Deck vs ROG Ally)
  - Validates checksums before and after modification

Usage:
  python sd_apcb_tool.py analyze <bios_file>
  python sd_apcb_tool.py analyze <bios_file> --device rog_ally
  python sd_apcb_tool.py modify <bios_in> <bios_out> --target 32
  python sd_apcb_tool.py modify <bios_in> <bios_out> --target 16  (restore stock)
"""

import argparse
import struct
import sys
import os
import shutil
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import List, Optional, Tuple


# ============================================================================
# Enums
# ============================================================================

class DeviceType(str, Enum):
    """Supported device types (str, Enum for backward compat with string comparisons)."""
    STEAM_DECK = 'steam_deck'
    ROG_ALLY = 'rog_ally'
    ROG_ALLY_X = 'rog_ally_x'
    AUTO = 'auto'


class MemoryTarget(IntEnum):
    """Supported memory target sizes in GB."""
    GB_16 = 16
    GB_32 = 32
    GB_64 = 64


# ============================================================================
# Constants
# ============================================================================

TOOL_VERSION = "1.8.0"

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
ALL_SPD_MAGICS = (LP5_SPD_MAGIC, LP5X_SPD_MAGIC)  # All supported SPD magic types
SPD_ENTRY_SEPARATOR = bytes([0x12, 0x34, 0x56, 0x78])  # Entry boundary marker
BL2_MAGIC = b'$BL2'                           # BIOS Level 2 directory marker

# SPD modification values for different memory configurations
# byte6 = SPD_BYTE_PKG_TYPE (offset 6), byte12 = SPD_BYTE_MODULE_ORG (offset 12)
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
MEMG_OFFSET_ALLY = (0xC0,)      # ROG Ally: PSPG at 0x80, MEMG at 0xC0
MEMG_OFFSET_ALLY_X = (0xC8,)    # ROG Ally X: PSPG at 0x80, MEMG at 0xC8
MEMG_OFFSET_PSPG = (0xC0, 0xC8)  # All ROG Ally series offsets (for scanning)
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
        'memory_targets': (16, 32),
        'chip_count': (2, 4),   # OLED: 2 packages, LCD: 4 packages
        'flash_instructions': 'Flash via SPI programmer (CH341A + SOIC8 clip)',
    },
    'rog_ally': {
        'name': 'ROG Ally',
        'memg_offsets': MEMG_OFFSET_ALLY,
        'memory_targets': (16, 32, 64),
        'chip_count': 4,
        'flash_instructions': 'Flash via SPI programmer (CH341A + SOIC8 clip)',
    },
    'rog_ally_x': {
        'name': 'ROG Ally X',
        'memg_offsets': MEMG_OFFSET_ALLY_X,
        'memory_targets': (16, 32, 64),
        'chip_count': 4,
        'flash_instructions': 'Flash via SPI programmer (CH341A + SOIC8 clip)',
    },
}


# ============================================================================
# Data Structures
# ============================================================================

# SPD byte offsets (JEDEC SPD4.1.2.M-2 / LPDDR5 layout)
# These offsets are relative to the SPD entry magic (e.g. 23 11 13 0E)
SPD_BYTE_DENSITY     = 4   # SDRAM density per die + bank architecture
SPD_BYTE_ADDRESSING  = 5   # Row/column addressing
SPD_BYTE_PKG_TYPE    = 6   # Package type — density/config byte 1 (modified for RAM upgrade)
SPD_BYTE_OPTIONAL    = 7   # Optional features (tMAW, MAC)
SPD_BYTE_MODULE_ORG  = 12  # Module organization — density/config byte 2 (modified for RAM upgrade)
SPD_BYTE_BUS_WIDTH   = 13  # Module memory bus width
SPD_BYTE_TCKMIN      = 18  # tCKmin (MTB units)
SPD_BYTE_TAAMIN      = 24  # tAAmin (MTB units)
SPD_BYTE_TRCDMIN     = 26  # tRCDmin (MTB units)
SPD_BYTE_TRPABMIN    = 27  # tRPABmin (MTB units)
SPD_BYTE_TRPPBMIN    = 28  # tRPPBmin (MTB units)

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

    b4 = spd[SPD_BYTE_DENSITY]      # SDRAM Density and Banks
    b5 = spd[SPD_BYTE_ADDRESSING]    # SDRAM Addressing (rows/cols)
    b6 = spd[SPD_BYTE_PKG_TYPE]      # SDRAM Package Type (die count, density)
    b7 = spd[SPD_BYTE_OPTIONAL]      # Optional Features (tMAW, MAC)
    b12 = spd[SPD_BYTE_MODULE_ORG]   # Module Organization (ranks, device width)
    b13 = spd[SPD_BYTE_BUS_WIDTH]    # Module Memory Bus Width

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
    b18 = spd[SPD_BYTE_TCKMIN]   # tCKmin (MTB)
    b24 = spd[SPD_BYTE_TAAMIN]   # tAAmin (MTB)
    b26 = spd[SPD_BYTE_TRCDMIN]  # tRCDmin (MTB)
    b27 = spd[SPD_BYTE_TRPABMIN] # tRPABmin (MTB)
    b28 = spd[SPD_BYTE_TRPPBMIN] # tRPPBmin (MTB)

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

def _is_pe_firmware(data: bytes) -> bool:
    """Check if data starts with PE/MZ header (firmware update package, not raw SPI)."""
    return len(data) >= 2 and data[:2] == b'MZ'


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
    """Return total module capacity from SPD byte values."""
    for gb, cfg in MEMORY_CONFIGS.items():
        if cfg['byte6'] == byte6 and cfg['byte12'] == byte12:
            return f"{gb}GB"
    return f"Unknown (0x{byte6:02X}/0x{byte12:02X})"


def _capacity_label(byte6: int, byte12: int, chip_count) -> str:
    """Return per-package capacity string like '4x 8GB' or '2x 16GB'.

    Args:
        chip_count: int for fixed count, or tuple (lo, hi) for range
                    (e.g. Steam Deck LCD=4, OLED=2 → (2, 4))
    """
    total_gb = None
    for gb, cfg in MEMORY_CONFIGS.items():
        if cfg['byte6'] == byte6 and cfg['byte12'] == byte12:
            total_gb = gb
            break
    if total_gb is None:
        return f"Unknown (0x{byte6:02X}/0x{byte12:02X})"
    if isinstance(chip_count, tuple):
        chips_lo, chips_hi = chip_count
        per_lo = total_gb // chips_hi   # more packages = smaller each
        per_hi = total_gb // chips_lo   # fewer packages = larger each
        return f"{chips_hi}x{per_lo}GB/{chips_lo}x{per_hi}GB"
    per_chip = total_gb // chip_count
    return f"{chip_count}x {per_chip}GB"


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

            chip_count = device_profile.get('chip_count') if device_profile else None
            print(f"\n    SPD Entries ({len(block.spd_entries)}: {', '.join(type_summary)}):")
            print(f"    {'-'*115}")
            print(f"    {'#':<3} {'Type':<8} {'Module':<24} {'Mfr':<9} {'Capacity':<16} "
                  f"{'Dies':<5} {'Width':<6} {'Ranks':<6} "
                  f"{'tAA':<7} {'tRCD':<7} {'tRP':<7}")
            print(f"    {'-'*115}")

            for j, entry in enumerate(block.spd_entries):
                if chip_count is not None:
                    entry_cap = _capacity_label(entry.byte6, entry.byte12, chip_count)
                else:
                    entry_cap = _density_label(entry.byte6, entry.byte12)
                die_info = f"{entry.die_count}x{entry.die_density}" if entry.die_count and entry.die_density else '?'
                tAA = f"{entry.tAA_ns}ns" if entry.tAA_ns else '?'
                tRCD = f"{entry.tRCD_ns}ns" if entry.tRCD_ns else '?'
                tRP = f"{entry.tRPPB_ns}ns" if entry.tRPPB_ns else '?'

                print(f"    {j+1:<3} {entry.mem_type:<8} {entry.module_name:<24} "
                      f"{entry.manufacturer:<9} {entry_cap:<16} "
                      f"{die_info:<5} {entry.dev_width:<6} {entry.ranks}R    "
                      f"{tAA:<7} {tRCD:<7} {tRP:<7}")

            # Show first-entry SPD config summary
            first = block.spd_entries[0]
            first_den = _density_label(first.byte6, first.byte12)
            print(f"\n    First entry SPD config: {first_den}")
    
    return blocks


# ============================================================================
# DMI / SMBIOS Backup & Restore (AMI DmiEdit $DMI Store)
# ============================================================================

# AMI DmiEdit store signature
AMI_DMI_MAGIC = b'$DMI'  # 4 bytes: 0x24 0x44 0x4D 0x49

# SMBIOS type names for display
SMBIOS_TYPE_NAMES = {
    0: 'BIOS Information', 1: 'System Information', 2: 'Baseboard Information',
    3: 'System Enclosure', 4: 'Processor', 11: 'OEM Strings',
    127: 'End-of-Table',
}

# SMBIOS field names by (type, offset) for human-readable display
SMBIOS_FIELD_NAMES = {
    (1, 0x04): 'Manufacturer',
    (1, 0x05): 'Product Name',
    (1, 0x06): 'Version',
    (1, 0x07): 'Serial Number',
    (1, 0x08): 'UUID',
    (1, 0x19): 'SKU Number',
    (1, 0x1A): 'Family',
    (2, 0x04): 'Manufacturer',
    (2, 0x05): 'Product',
    (2, 0x06): 'Version',
    (2, 0x07): 'Serial Number',
    (2, 0x08): 'Asset Tag',
    (3, 0x04): 'Manufacturer',
    (3, 0x06): 'Version',
    (3, 0x07): 'Serial Number',
    (3, 0x08): 'Asset Tag',
}


@dataclass
class DmiRecord:
    """A single record from the AMI $DMI store.

    AMI DmiEdit record format:
      byte[0]:    SMBIOS type number
      byte[1]:    Field offset within the SMBIOS structure
      byte[2]:    Flag (0x00 = current value, 0xFF = factory default)
      byte[3:5]:  Total record length (uint16 LE, includes 5-byte header)
      byte[5+]:   Data (ASCII string or raw bytes)
    """
    smbios_type: int
    field_offset: int
    flag: int           # 0x00 = current, 0xFF = factory default
    record_length: int
    data: bytes         # The payload after the 5-byte header
    offset_in_file: int # Absolute offset in firmware
    raw_bytes: bytes    # Full record including header

    @property
    def is_current(self) -> bool:
        return self.flag == 0x00

    @property
    def is_default(self) -> bool:
        return self.flag == 0xFF

    @property
    def data_str(self) -> str:
        """Decode data as ASCII string (strips trailing nulls)."""
        return self.data.rstrip(b'\x00').decode('ascii', errors='replace')

    @property
    def field_name(self) -> str:
        """Human-readable field name, or 'Field 0xNN'."""
        name = SMBIOS_FIELD_NAMES.get((self.smbios_type, self.field_offset))
        if name:
            return name
        return f'Field 0x{self.field_offset:02X}'

    @property
    def type_name(self) -> str:
        return SMBIOS_TYPE_NAMES.get(self.smbios_type, f'Type {self.smbios_type}')


def find_dmi_store(data: bytes, allow_empty: bool = False) -> Optional[Tuple[int, int]]:
    """Find the AMI $DMI store region in firmware.

    The $DMI store contains device identity records (serial numbers, UUIDs, etc.)
    written by AMI DmiEdit. Located by scanning for the '$DMI' magic signature.

    Args:
        data: Firmware data to scan
        allow_empty: If True, accept blank $DMI stores (all 0xFF after magic).
            Used by import_dmi() to write into stock firmware files (.fd) that
            ship with an empty $DMI store.

    Returns:
        Tuple of (store_start, store_end) or None if not found.
        store_start is the offset of '$DMI' magic.
        store_end is end of record data, or end of 0xFF region for blank stores.
    """
    pos = 0
    candidates = []
    while pos < len(data) - 8:
        idx = data.find(AMI_DMI_MAGIC, pos)
        if idx < 0:
            break
        # Verify: next bytes after $DMI should be a valid record header
        # (SMBIOS type 0-127, field offset, flag 0x00 or 0xFF)
        rec_start = idx + 4
        if rec_start + 5 <= len(data):
            stype = data[rec_start]
            flag = data[rec_start + 2]
            rec_len = struct.unpack_from('<H', data, rec_start + 3)[0]
            if stype <= 127 and flag in (0x00, 0xFF) and 5 < rec_len < 256:
                # Find end of records: scan until we hit invalid header
                scan = rec_start
                end = min(idx + 8192, len(data))  # Safety limit
                while scan < end - 5:
                    rt = data[scan]
                    rf = data[scan + 2]
                    rl = struct.unpack_from('<H', data, scan + 3)[0]
                    if rt > 127 or rf not in (0x00, 0xFF) or rl < 5 or rl > 256:
                        break
                    scan += rl
                candidates.append((idx, scan))
        pos = idx + 1

    # Fallback: accept blank $DMI stores (stock .fd firmware files)
    # These have $DMI magic followed by all 0xFF -- no records yet
    if not candidates and allow_empty:
        pos = 0
        while pos < len(data) - 4:
            idx = data.find(AMI_DMI_MAGIC, pos)
            if idx < 0:
                break
            # Scan forward to find end of 0xFF region after magic
            scan = idx + 4
            end = min(idx + 8192, len(data))
            while scan < end and data[scan] == 0xFF:
                scan += 1
            if scan > idx + 4:  # At least some 0xFF space exists
                candidates.append((idx, scan))
            pos = idx + 1

    if not candidates:
        return None

    # Return the largest (most records / most space) $DMI store found
    best = max(candidates, key=lambda c: c[1] - c[0])
    return best


def parse_dmi_records(data: bytes, store_start: int, store_end: int) -> List[DmiRecord]:
    """Parse all records from an AMI $DMI store.

    Args:
        data: Full firmware data
        store_start: Offset of '$DMI' magic
        store_end: End of record data

    Returns:
        List of DmiRecord structures
    """
    records = []
    pos = store_start + 4  # Skip '$DMI' magic

    while pos < store_end - 5:
        stype = data[pos]
        foff = data[pos + 1]
        flag = data[pos + 2]
        rec_len = struct.unpack_from('<H', data, pos + 3)[0]

        if stype > 127 or flag not in (0x00, 0xFF) or rec_len < 5 or rec_len > 256:
            break

        payload = data[pos + 5:pos + rec_len]
        raw = data[pos:pos + rec_len]

        records.append(DmiRecord(
            smbios_type=stype, field_offset=foff, flag=flag,
            record_length=rec_len, data=payload,
            offset_in_file=pos, raw_bytes=raw
        ))
        pos += rec_len

    return records


def export_dmi(data: bytes) -> dict:
    """Export DMI/SMBIOS identity data from firmware to a JSON-serializable dict.

    Finds the AMI $DMI store, parses all records, and returns structured data
    suitable for backup and later restoration.

    Args:
        data: Full firmware file contents (raw SPI dump)

    Returns:
        Dict with tool version, region info, raw data, and decoded identity fields

    Raises:
        ValueError: If no $DMI store found in firmware
    """
    result = find_dmi_store(data)
    if result is None:
        raise ValueError(
            "No DMI data found in firmware.\n"
            "Export requires a firmware dump with populated DMI records.\n"
            "Use a raw SPI flash dump from a working (or bricked) device.")

    store_start, store_end = result
    records = parse_dmi_records(data, store_start, store_end)

    # Extract the full region including $DMI magic through end of records
    region_size = store_end - store_start

    export = {
        'tool_version': TOOL_VERSION,
        'format': 'ami_dmi_store',
        'dmi_store_offset': f'0x{store_start:08X}',
        'dmi_store_size': region_size,
        'raw_store_hex': data[store_start:store_end].hex(),
        'records': [],
        'system_info': {},
        'board_info': {},
    }

    for r in records:
        entry = {
            'smbios_type': r.smbios_type,
            'type_name': r.type_name,
            'field_offset': f'0x{r.field_offset:02X}',
            'field_name': r.field_name,
            'flag': 'current' if r.is_current else 'default',
            'record_length': r.record_length,
            'offset': f'0x{r.offset_in_file:08X}',
            'raw_hex': r.raw_bytes.hex(),
            'data_ascii': r.data_str,
        }
        export['records'].append(entry)

        # Build human-readable identity summaries from current-value records
        if r.is_current:
            if r.smbios_type == 1:  # System Information
                if r.field_offset == 0x07:
                    export['system_info']['serial_number'] = r.data_str
                elif r.field_offset == 0x04:
                    export['system_info']['manufacturer'] = r.data_str
                elif r.field_offset == 0x05:
                    export['system_info']['product_name'] = r.data_str
                elif r.field_offset == 0x08:
                    export['system_info']['uuid'] = r.data.hex()
            elif r.smbios_type == 2:  # Baseboard
                if r.field_offset == 0x07:
                    export['board_info']['serial_number'] = r.data_str
                elif r.field_offset == 0x04:
                    export['board_info']['manufacturer'] = r.data_str
                elif r.field_offset == 0x05:
                    export['board_info']['product'] = r.data_str

    return export


def import_dmi(firmware_data: bytearray, dmi_json: dict) -> List[Tuple[int, str]]:
    """Import DMI identity data from a JSON export into firmware.

    Overwrites the $DMI store region in firmware_data with the exported raw data.

    Args:
        firmware_data: Mutable firmware data (modified in-place)
        dmi_json: DMI export dict (from export_dmi)

    Returns:
        List of (offset, description) patches applied

    Raises:
        ValueError: If $DMI store not found or sizes incompatible
    """
    target_result = find_dmi_store(bytes(firmware_data), allow_empty=True)
    if target_result is None:
        raise ValueError(
            "No AMI $DMI store found in target firmware.\n"
            "The target file must contain a '$DMI' signature.\n"
            "Supported: raw SPI flash dumps (.bin) and firmware update files (.fd)")

    target_start, target_end = target_result
    target_size = target_end - target_start

    # Get source data from export
    source_raw = bytes.fromhex(dmi_json['raw_store_hex'])
    source_size = len(source_raw)

    # Find the available space: from $DMI magic to start of next non-FF data
    # The $DMI store sits in a gap between firmware volumes, padded with 0xFF
    available = target_size
    # Scan forward from target_end to find how much 0xFF padding exists
    scan = target_end
    while scan < len(firmware_data) and firmware_data[scan] == 0xFF:
        scan += 1
    available = scan - target_start

    if source_size > available:
        raise ValueError(
            f"Source $DMI store ({source_size} bytes) is larger than "
            f"available space ({available} bytes). Cannot import.")

    patches = []

    # Write source data, pad remaining with 0xFF
    write_size = min(source_size, available)
    firmware_data[target_start:target_start + write_size] = source_raw[:write_size]
    # Fill any remaining space with 0xFF
    if write_size < available:
        firmware_data[target_start + write_size:target_start + available] = b'\xFF' * (available - write_size)

    patches.append((target_start,
        f"$DMI store overwritten ({source_size} bytes from export)"))

    # Log identity info
    si = dmi_json.get('system_info', {})
    bi = dmi_json.get('board_info', {})
    if si.get('serial_number'):
        patches.append((target_start, f"System Serial: {si['serial_number']}"))
    if bi.get('serial_number'):
        patches.append((target_start, f"Board Serial: {bi['serial_number']}"))

    return patches


# (PE Authenticode signing code was removed in v1.8.0 — requires Insyde QA.pfx)


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
                device: str = 'auto', screen: Optional[str] = None):
    """
    Modify BIOS file for target memory configuration.

    Args:
        input_path: Path to input BIOS file
        output_path: Path for modified output file
        target_gb: Target memory size in GB (16, 32, or 64)
        modify_magic_byte: If True, change APCB byte[0] from 0x41 to 0x51 (cosmetic only)
        entry_indices: Which SPD entries to modify (0-based). None = first entry only.
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

    print(f"\n{'='*78}")
    print(f"  APCB Memory Modification Tool v{TOOL_VERSION}")
    print(f"{'='*78}")
    print(f"\n  Device: {device_name}")
    print(f"  Input:  {os.path.basename(input_path)}")
    print(f"  Output: {os.path.basename(output_path)}")
    print(f"  Target: {config['name']}")
    print(f"  {config['description']}")

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
            
            # Calculate absolute file offsets for the two key SPD bytes
            byte6_offset = entry.offset_in_file + SPD_BYTE_PKG_TYPE
            byte12_offset = entry.offset_in_file + SPD_BYTE_MODULE_ORG
            
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
    
    output_data = bytes(data)

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
        if _is_pe_firmware(bytes(data)):
            print(f"  Flash this file using the manufacturer's update tool (e.g. h2offt).")
        else:
            print(f"  Output file is ready for SPI flash.")
        if device_profile:
            flash_instr = device_profile.get('flash_instructions', '')
            if flash_instr:
                if isinstance(flash_instr, str) and '{filename}' in flash_instr:
                    flash_instr = flash_instr.format(filename=os.path.basename(output_path))
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
            b6, b12 = e.offset_in_file + SPD_BYTE_PKG_TYPE, e.offset_in_file + SPD_BYTE_MODULE_ORG
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
    chip_count = state.device_profile.get('chip_count') if state.device_profile else None
    print(f"\n  {c.HEADER}{'#':<4} {'Type':<9} {'Module':<24} {'Mfr':<9} {'Capacity':<16} "
          f"{'Dies':<8} {'Width':<6} {'Ranks':<6} {'Pending'}{c.RESET}")
    print(f"  {c.DIM}{'-'*100}{c.RESET}")
    for i, e in enumerate(entries):
        cur_den = _density_from_bytes(e.byte6, e.byte12)
        if chip_count is not None:
            cur_cap = _capacity_label(e.byte6, e.byte12, chip_count)
        else:
            cur_cap = cur_den
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
              f"{mfr:<9} {cur_cap:<16} "
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
        print(f"  {c.BOLD}  MAGIC{c.RESET}         Toggle APCB magic byte modification")
        print(f"  {c.BOLD}  STATUS{c.RESET}        Show all pending changes")
        print(f"  {c.BOLD}  APPLY{c.RESET}         Write changes to output file")
        print(f"  {c.BOLD}  HELP / ?{c.RESET}      Show this help")
        print(f"  {c.BOLD}  EXIT{c.RESET}          Quit without writing\n")
    elif menu == 'spd':
        targets = state.device_profile.get('memory_targets', (16, 32)) if state.device_profile else (16, 32)
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

    output_data = bytes(data)

    # 3. Write output
    with open(state.output_path, 'wb') as f:
        f.write(output_data)
    print(f"\n  {c.OK}Output written:{c.RESET} {state.output_path} ({len(output_data):,} bytes)")

    # 4. Verify
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
        if _is_pe_firmware(bytes(data)):
            print(f"  Flash using the manufacturer's update tool (e.g. h2offt).")
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
    targets = state.device_profile.get('memory_targets', (16, 32)) if state.device_profile else (16, 32)
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
        chip_count = state.device_profile.get('chip_count') if state.device_profile else None
        cap_str = _capacity_label(e.byte6, e.byte12, chip_count) if chip_count else cur
        die_info = f"{e.die_count}x{e.die_density}" if e.die_count and e.die_density else '?'
        print(f"\n  {c.OK}Entry {n} selected:{c.RESET} {c.VALUE}{name}{c.RESET}")
        print(f"    {c.LABEL}Type:{c.RESET}      {e.mem_type}  ({e.manufacturer or '?'})")
        print(f"    {c.LABEL}Capacity:{c.RESET}  {cap_str}  (b6=0x{e.byte6:02X}, b12=0x{e.byte12:02X})")
        print(f"    {c.LABEL}Package:{c.RESET}   {die_info} dies, {e.dev_width}, {e.ranks}R")
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
                       magic: bool = False, screen: Optional[str] = None):
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
    python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin

  Interactive with screen patch pre-set:
    python sd_apcb_tool.py modify my_bios.bin my_bios_mod.bin --screen deckhd

  Batch: modify for 32GB:
    python sd_apcb_tool.py modify my_bios.bin my_bios_32gb.bin --target 32

  Batch: modify for 64GB (ROG Ally X):
    python sd_apcb_tool.py modify my_bios.bin my_bios_64gb.bin --target 64

  Batch: restore to stock 16GB:
    python sd_apcb_tool.py modify my_bios_32gb.bin my_bios_stock.bin --target 16

  DMI backup (for brick recovery):
    python sd_apcb_tool.py dmi-export my_bios_dump.bin my_dmi_backup.json

  DMI restore into clean BIOS:
    python sd_apcb_tool.py dmi-import clean_bios.bin restored.bin my_dmi_backup.json

Supported devices:
  Steam Deck (LCD & OLED): 16GB/32GB
  ROG Ally / Ally X: 16GB/32GB/64GB

  Omit --target for interactive mode.
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

    # DMI export command
    dmi_export_parser = subparsers.add_parser('dmi-export',
        help='Export DMI/SMBIOS data from firmware to JSON file (for brick recovery)')
    dmi_export_parser.add_argument('bios_file', help='Input BIOS/firmware file')
    dmi_export_parser.add_argument('output_json', help='Output JSON file for DMI data')
    dmi_export_parser.add_argument('--device', choices=['auto', 'steam_deck', 'rog_ally', 'rog_ally_x'],
                                   default='auto', help='Device type (default: auto-detect)')

    # DMI import command
    dmi_import_parser = subparsers.add_parser('dmi-import',
        help='Import DMI/SMBIOS data from JSON into firmware (for brick recovery)')
    dmi_import_parser.add_argument('bios_in', help='Input BIOS/firmware file (clean image)')
    dmi_import_parser.add_argument('bios_out', help='Output BIOS file with DMI data restored')
    dmi_import_parser.add_argument('dmi_json', help='DMI JSON file (from dmi-export)')
    dmi_import_parser.add_argument('--device', choices=['auto', 'steam_deck', 'rog_ally', 'rog_ally_x'],
                                   default='auto', help='Device type (default: auto-detect)')

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
                device=args.device,
                screen=screen,
            )
        else:
            # Interactive mode
            interactive_modify(
                args.bios_in,
                args.bios_out,
                device=args.device,
                magic=args.magic,
                screen=screen,
            )

    elif args.command == 'dmi-export':
        _enable_ansi_colors()
        c = _C
        with open(args.bios_file, 'rb') as f:
            data = f.read()
        device = args.device
        if device == 'auto':
            device = detect_device(data)
        device_name = DEVICE_PROFILES.get(device, {}).get('name', 'Unknown')

        print(f"\n{'='*70}")
        print(f"  DMI/SMBIOS Export -- {device_name}")
        print(f"{'='*70}")

        try:
            dmi_data = export_dmi(data)
        except ValueError as e:
            print(f"\n  {c.ERR}ERROR: {e}{c.RESET}")
            sys.exit(1)

        # Display summary
        si = dmi_data.get('system_info', {})
        bi = dmi_data.get('board_info', {})
        print(f"\n  Store:   {dmi_data['dmi_store_offset']} ({dmi_data['dmi_store_size']} bytes)")
        print(f"  Records: {len(dmi_data['records'])}")
        if si:
            print(f"\n  {c.CYAN}System Information:{c.RESET}")
            if si.get('manufacturer'):
                print(f"    Manufacturer:  {si['manufacturer']}")
            if si.get('product_name'):
                print(f"    Product:       {si['product_name']}")
            if si.get('serial_number'):
                print(f"    Serial:        {si['serial_number']}")
            if si.get('uuid'):
                print(f"    UUID:          {si['uuid']}")
        if bi:
            print(f"\n  {c.CYAN}Board Information:{c.RESET}")
            if bi.get('manufacturer'):
                print(f"    Manufacturer:  {bi['manufacturer']}")
            if bi.get('product'):
                print(f"    Product:       {bi['product']}")
            if bi.get('serial_number'):
                print(f"    Serial:        {bi['serial_number']}")

        import json
        with open(args.output_json, 'w') as f:
            json.dump(dmi_data, f, indent=2)
        print(f"\n  {c.GREEN}Exported to: {args.output_json}{c.RESET}")
        print(f"  Store this file safely -- it contains your device identity.")
        print(f"  Use 'dmi-import' to restore into a clean firmware for brick recovery.")

    elif args.command == 'dmi-import':
        _enable_ansi_colors()
        c = _C
        if os.path.abspath(args.bios_in) == os.path.abspath(args.bios_out):
            print(f"\n  {c.ERR}ERROR: Input and output must be different files (safety measure){c.RESET}")
            sys.exit(1)

        import json
        with open(args.bios_in, 'rb') as f:
            data = bytearray(f.read())
        with open(args.dmi_json, 'r') as f:
            dmi_json = json.load(f)

        device = args.device
        if device == 'auto':
            device = detect_device(bytes(data))
        device_name = DEVICE_PROFILES.get(device, {}).get('name', 'Unknown')

        print(f"\n{'='*70}")
        print(f"  DMI/SMBIOS Import -- {device_name}")
        print(f"{'='*70}")

        si = dmi_json.get('system_info', {})
        if si:
            print(f"\n  Restoring from: {os.path.basename(args.dmi_json)}")
            if si.get('serial_number'):
                print(f"    Serial:  {si['serial_number']}")
            if si.get('uuid'):
                print(f"    UUID:    {si['uuid']}")

        try:
            patches = import_dmi(data, dmi_json)
            for off, desc in patches:
                print(f"    0x{off:08X}: {desc}")

            with open(args.bios_out, 'wb') as f:
                f.write(bytes(data))
            print(f"\n  {c.GREEN}Output written: {args.bios_out}{c.RESET}")
            print(f"  Flash this file to your device via SPI programmer.")
            print(f"  UEFI settings will recreate automatically on first boot.")
        except ValueError as e:
            print(f"\n  {c.ERR}ERROR: {e}{c.RESET}")
            sys.exit(1)

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
            default_out = str(p.parent / f"{p.stem}_modified.bin")
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
