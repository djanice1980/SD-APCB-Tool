#!/usr/bin/env python3
"""
APCB Memory Mod Tool (GUI) v1.9.0
===================================
GUI for analyzing and modifying handheld device BIOS files
to support 16GB/32GB/64GB memory configurations.

Supported devices:
  - Steam Deck (LCD & OLED) — 16GB/32GB
  - ASUS ROG Ally / Ally X — 16GB/32GB/64GB

Auto-detects device type from firmware contents.

Requirements:
  - Python 3.8+ (tkinter included with standard Python on Windows)

Usage: python sd_apcb_gui.py
"""

import os, sys, struct
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import List, Optional, Tuple, Dict
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


class DeviceType(str, Enum):
    """Supported device types."""
    STEAM_DECK = 'steam_deck'
    ROG_ALLY = 'rog_ally'
    ROG_ALLY_X = 'rog_ally_x'
    AUTO = 'auto'


class SteamDeckVariant(str, Enum):
    """Steam Deck sub-variants (LCD vs OLED)."""
    LCD = 'lcd'
    OLED = 'oled'
    UNKNOWN = 'unknown'


class MemoryTarget(IntEnum):
    """Supported memory target sizes in GB."""
    GB_16 = 16
    GB_32 = 32
    GB_64 = 64


APP_TITLE = "SD APCB Memory Mod Tool"
APP_VERSION = "1.9.0"

# Steam Deck firmware filename prefixes for LCD vs OLED variant detection
SD_LCD_PREFIX = 'F7A'     # Jupiter (LCD)
SD_OLED_PREFIX = 'F7G'    # Galileo (OLED)

# Resolved chip counts per Steam Deck variant
VARIANT_CHIP_COUNTS = {
    SteamDeckVariant.LCD: 4,
    SteamDeckVariant.OLED: 2,
    SteamDeckVariant.UNKNOWN: (2, 4),
}

APCB_MAGIC = b'APCB'
APCB_MAGIC_MOD = b'QPCB'
APCB_CHECKSUM_OFFSET = 16
MEMG_MAGIC = b'MEMG'
TOKN_MAGIC = b'TOKN'
PSPG_MAGIC = b'PSPG'
LP5_SPD_MAGIC  = bytes([0x23, 0x11, 0x13, 0x0E])
LP5X_SPD_MAGIC = bytes([0x23, 0x11, 0x15, 0x0E])
ALL_SPD_MAGICS = (LP5_SPD_MAGIC, LP5X_SPD_MAGIC)
SPD_ENTRY_SEPARATOR = bytes([0x12, 0x34, 0x56, 0x78])
# SPD byte offsets relative to entry magic
SPD_BYTE_DENSITY = 4; SPD_BYTE_ADDRESSING = 5; SPD_BYTE_PKG_TYPE = 6; SPD_BYTE_OPTIONAL = 7
SPD_BYTE_MODULE_ORG = 12; SPD_BYTE_BUS_WIDTH = 13; SPD_BYTE_TCKMIN = 18
SPD_BYTE_TAAMIN = 24; SPD_BYTE_TRCDMIN = 26; SPD_BYTE_TRPABMIN = 27; SPD_BYTE_TRPPBMIN = 28
SPD_MTB_PS = 125  # Medium Time Base in picoseconds
MEMORY_CONFIGS = {
    16: {'name': '16GB', 'byte6': 0x95, 'byte12': 0x02},
    32: {'name': '32GB', 'byte6': 0xB5, 'byte12': 0x0A},
    64: {'name': '64GB', 'byte6': 0xF5, 'byte12': 0x49},
}
# Speed profiles — maps MT/s rate to tCK byte value
# Formula: MT/s = 2000 / (tCK_byte * MTB_ns), where MTB_ns = 0.125
SPEED_PROFILES = {
    8000: {'name': '8000 MT/s', 'tCK': 0x02},
    5333: {'name': '5333 MT/s', 'tCK': 0x03},
    4000: {'name': '4000 MT/s', 'tCK': 0x04},
    3200: {'name': '3200 MT/s', 'tCK': 0x05},
}

def speed_from_tck(tck_byte: int) -> str:
    """Convert tCK byte to speed dropdown label, or 'Custom'."""
    for mts, prof in SPEED_PROFILES.items():
        if prof['tCK'] == tck_byte:
            return prof['name']
    return 'Custom'

def tck_from_speed(speed_str: str) -> Optional[int]:
    """Convert speed label to tCK byte, or None for Custom."""
    for mts, prof in SPEED_PROFILES.items():
        if prof['name'] == speed_str:
            return prof['tCK']
    return None

MODULE_DENSITY_MAP = {
    'MT62F512M32D2DR': '16GB', 'MT62F768M32D2DR': '24GB',
    'MT62F1G64D4BS': '32GB', 'MT62F1G64D4AH': '32GB', 'MT62F1G32D4DR': '32GB',
    'MT62F2G64D8AJ': '32GB', 'MT62F2G64D8': '32GB',
    'K3KL3L30CM': '32GB', 'K3LKCKC0BM': '32GB',
    'K3LKBKB0BM': '16GB', 'K3LK7K70BM': '16GB',
    # LPDDR5X modules
    'MT62F1G32D2DS': '16GB', 'MT62F768M32D2DS': '24GB',
    'MT62F1536M32D4DS': '32GB', 'MT62F2G32D4DS': '32GB',
    'MT62F4G32D8DV': '64GB',
    'K3KL8L80CM': '16GB', 'K3KLALA0CM': '64GB',
    'H58G56BK7BX': '16GB', 'H58GE6AK8BX': '32GB', 'H58G66BK8HX': '16GB',
}
MANUFACTURER_IDS = {0x2C: 'Micron', 0xCE: 'Samsung', 0xAD: 'SK Hynix', 0x01: 'Samsung'}
# Known module name prefixes — used for prefix dropdown in GUI editor
# Format: (prefix, display_label) — dropdown shows label, value uses prefix only
MODULE_NAME_PREFIXES = [
    ('MT6', 'MT6 - Micron'),
    ('K3K', 'K3K - Samsung'),
    ('K3L', 'K3L - Samsung'),
    ('H58', 'H58 - SK Hynix'),
    ('H9H', 'H9H - SK Hynix'),
    ('SEC', 'SEC - Samsung'),
    ('SAM', 'SAM - Samsung'),
]
MODULE_PREFIX_LABELS = [label for _, label in MODULE_NAME_PREFIXES]
MODULE_PREFIX_MAP = {label: prefix for prefix, label in MODULE_NAME_PREFIXES}
MODULE_LABEL_MAP = {prefix: label for prefix, label in MODULE_NAME_PREFIXES}

# Screen replacement EDID data and profiles (Steam Deck LCD only)
EDID_MAGIC = bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
BVDT_MAGIC = b'$BVDT$'
SCREEN_PROFILES = {
    'deckhd': {
        'name': 'DeckHD 1200p',
        'description': 'IPS LCD, 1200x1920 @ 60Hz (16:10)',
        'version_tag': 'DeckHD',
        'mfr_id': bytes([0x11, 0x04]),
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
        'mfr_id': bytes([0x12, 0x6F]),
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
SCREEN_MFR_IDS = [p['mfr_id'] for p in SCREEN_PROFILES.values()]

# Device profiles
DEVICE_PROFILES = {
    'steam_deck': {'name': 'Steam Deck', 'memory_targets': (16, 32), 'chip_count': (2, 4)},
    'rog_ally': {'name': 'ROG Ally', 'memory_targets': (16, 32, 64), 'chip_count': 4},
    'rog_ally_x': {'name': 'ROG Ally X', 'memory_targets': (16, 32, 64), 'chip_count': 4},
}

def _is_pe_firmware(data: bytes) -> bool:
    """Check if data starts with PE/MZ header (firmware update package, not raw SPI)."""
    return len(data) >= 2 and data[:2] == b'MZ'

def detect_device(data: bytes) -> str:
    """Auto-detect device type from firmware contents."""
    has_memg_80, has_pspg_memg_c0, has_pspg_memg_c8 = False, False, False
    for magic in [APCB_MAGIC, APCB_MAGIC_MOD]:
        pos = 0
        while pos < len(data) - 32:
            idx = data.find(magic, pos)
            if idx == -1: break
            header = data[idx:idx+32]
            ds = struct.unpack_from('<I', header, 8)[0]
            if ds > 0x100000 or ds < 16: pos = idx + 1; continue
            if idx + 0x84 <= len(data):
                if data[idx+0x80:idx+0x84] == MEMG_MAGIC: has_memg_80 = True
                elif data[idx+0x80:idx+0x84] == PSPG_MAGIC:
                    if idx + 0xC4 <= len(data) and data[idx+0xC0:idx+0xC4] == MEMG_MAGIC:
                        has_pspg_memg_c0 = True
                    if idx + 0xCC <= len(data) and data[idx+0xC8:idx+0xCC] == MEMG_MAGIC:
                        has_pspg_memg_c8 = True
            pos = idx + 1
    if has_memg_80: return 'steam_deck'
    elif has_pspg_memg_c8: return 'rog_ally_x'
    elif has_pspg_memg_c0: return 'rog_ally'
    return 'unknown'

def detect_steam_deck_variant(data: bytes, filename: Optional[str] = None) -> str:
    """Detect Steam Deck sub-variant (LCD vs OLED) using a 3-tier strategy.

    Tier 1: Filename prefix — F7A = LCD (Jupiter), F7G = OLED (Galileo)
    Tier 2: Firmware content — codename string scan
    Tier 3: Returns 'unknown' (caller should prompt user or show dropdown)
    """
    # Tier 1: Filename prefix
    if filename:
        basename = os.path.basename(filename).upper()
        if basename.startswith(SD_LCD_PREFIX):
            return SteamDeckVariant.LCD
        if basename.startswith(SD_OLED_PREFIX):
            return SteamDeckVariant.OLED

    # Tier 2: Codename string scan (Galileo = OLED, Jupiter = LCD)
    if b'Galileo' in data or b'GALILEO' in data:
        return SteamDeckVariant.OLED
    if b'Jupiter' in data or b'JUPITER' in data:
        return SteamDeckVariant.LCD

    # Tier 3: Unknown
    return SteamDeckVariant.UNKNOWN

# SPD byte field constants (JEDEC SPD4.1.2.M-2 / LPDDR5 layout)
SPD_MTB_PS = 125  # Medium Time Base in picoseconds
_DIE_DENSITY_MAP = {0x4: '4Gb', 0xB: '6Gb', 0x5: '8Gb', 0x8: '12Gb', 0x6: '16Gb', 0x9: '24Gb', 0x7: '32Gb'}
_DIE_COUNT_MAP = {0: 1, 1: 2, 2: 4, 3: 8}
_DEV_WIDTH_MAP = {0: 'x4', 1: 'x8', 2: 'x16', 3: 'x32'}

def _decode_spd_fields(spd: bytes) -> dict:
    """Decode LPDDR5/LPDDR5X SPD bytes into human-readable fields."""
    if len(spd) < 29: return {}
    b4, b5, b6 = spd[SPD_BYTE_DENSITY], spd[SPD_BYTE_ADDRESSING], spd[SPD_BYTE_PKG_TYPE]
    b12, b13 = spd[SPD_BYTE_MODULE_ORG], spd[SPD_BYTE_BUS_WIDTH]
    return {
        'die_density': _DIE_DENSITY_MAP.get(b4 & 0x0F, '?'),
        'die_count': _DIE_COUNT_MAP.get((b6 >> 4) & 0x07, 0),
        'ranks': ((b12 >> 3) & 0x07) + 1,
        'dev_width': _DEV_WIDTH_MAP.get(b12 & 0x07, '?'),
        'bus_width': {0: 8, 1: 16, 2: 32, 3: 64}.get(b13 & 0x07, 0),
        'row_bits': ((b5 >> 3) & 0x07) + 12,
        'col_bits': (b5 & 0x07) + 9,
        'bank_groups': {0: 1, 1: 2, 2: 4}.get((b4 >> 4) & 0x03, 0),
        'banks_per_group': {0: 4, 1: 8, 2: 16}.get((b4 >> 6) & 0x03, 0),
        'tCK_byte': spd[SPD_BYTE_TCKMIN],
        'tAA_ns': round(spd[SPD_BYTE_TAAMIN] * SPD_MTB_PS / 1000, 2),
        'tRCD_ns': round(spd[SPD_BYTE_TRCDMIN] * SPD_MTB_PS / 1000, 2),
        'tRPAB_ns': round(spd[SPD_BYTE_TRPABMIN] * SPD_MTB_PS / 1000, 2),
        'tRPPB_ns': round(spd[SPD_BYTE_TRPPBMIN] * SPD_MTB_PS / 1000, 2),
    }

@dataclass
class SPDEntry:
    offset_in_apcb: int; offset_in_file: int; spd_bytes: bytes
    module_name: str = ''; manufacturer: str = ''; density_guess: str = ''
    byte6: int = 0; byte12: int = 0; config_id: int = 0; mfr_flag: int = 0; mem_type: str = 'LPDDR5'
    module_name_offset: int = -1; module_name_field_len: int = 0
    # Decoded SPD fields
    die_density: str = ''; die_count: int = 0; ranks: int = 0; dev_width: str = ''
    bus_width: int = 0; row_bits: int = 0; col_bits: int = 0
    bank_groups: int = 0; banks_per_group: int = 0
    tCK_byte: int = 0
    tAA_ns: float = 0.0; tRCD_ns: float = 0.0; tRPAB_ns: float = 0.0; tRPPB_ns: float = 0.0

@dataclass
class APCBBlock:
    offset: int; data_size: int; total_size: int; checksum_byte: int
    checksum_valid: bool; content_type: str
    spd_entries: List[SPDEntry] = field(default_factory=list)
    @property
    def is_memg(self): return self.content_type == 'MEMG'

def calculate_apcb_checksum(block_data: bytes) -> int:
    total = 0
    for i, b in enumerate(block_data):
        if i == APCB_CHECKSUM_OFFSET: continue
        total = (total + b) & 0xFF
    return (0x100 - total) & 0xFF

def verify_apcb_checksum(block_data: bytes) -> bool:
    return calculate_apcb_checksum(block_data) == block_data[APCB_CHECKSUM_OFFSET]

def find_apcb_blocks(data: bytes) -> List[APCBBlock]:
    blocks, found = [], set()
    for magic in [APCB_MAGIC, APCB_MAGIC_MOD]:
        pos = 0
        while pos < len(data) - 32:
            idx = data.find(magic, pos)
            if idx == -1: break
            if idx in found: pos = idx + 1; continue
            found.add(idx)
            header = data[idx:idx+32]
            ds = struct.unpack_from('<I', header, 8)[0]
            ts = struct.unpack_from('<I', header, 12)[0]
            cb = header[16]
            if ds > 0x100000 or ds < 16 or ts > 0x100000: pos = idx+1; continue
            ct = 'UNKNOWN'
            if idx+0x84 < len(data):
                if data[idx+0x80:idx+0x84] == MEMG_MAGIC: ct = 'MEMG'
                elif data[idx+0x80:idx+0x84] == TOKN_MAGIC: ct = 'TOKN'
            if ct == 'UNKNOWN':
                for alt_off in [0xC0, 0xC8]:
                    if idx+alt_off+4 < len(data):
                        if data[idx+alt_off:idx+alt_off+4] == MEMG_MAGIC: ct = 'MEMG'; break
                        elif data[idx+alt_off:idx+alt_off+4] == TOKN_MAGIC: ct = 'TOKN'; break
            cv = verify_apcb_checksum(data[idx:idx+ds]) if idx+ds <= len(data) else False
            block = APCBBlock(idx, ds, ts, cb, cv, ct)
            if ct == 'MEMG': block.spd_entries = parse_spd_entries(data, idx, ds)
            blocks.append(block)
            pos = idx + 1
    blocks.sort(key=lambda b: b.offset)
    return blocks

def parse_spd_entries(data: bytes, apcb_offset: int, apcb_size: int) -> List[SPDEntry]:
    entries, apcb = [], data[apcb_offset:apcb_offset+apcb_size]
    raw = []
    for spd_magic, mt in [(LP5_SPD_MAGIC, 'LPDDR5'), (LP5X_SPD_MAGIC, 'LPDDR5X')]:
        pos = 0
        while pos < len(apcb):
            idx = apcb.find(spd_magic, pos)
            if idx == -1 or idx+16 > len(apcb): break
            raw.append((idx, mt)); pos = idx + 1
    raw.sort(key=lambda x: x[0])
    for idx, mt in raw:
        spd_len = min(128, len(apcb) - idx)
        spd = apcb[idx:idx+spd_len]
        e = SPDEntry(idx, apcb_offset+idx, spd, byte6=spd[6] if len(spd) > 6 else 0, byte12=spd[12] if len(spd) > 12 else 0, mem_type=mt)
        # Decode detailed SPD fields
        fields = _decode_spd_fields(spd)
        if fields:
            for k, v in fields.items():
                if hasattr(e, k): setattr(e, k, v)
        for j in range(idx, min(idx+0x200, len(apcb)-20)):
            if apcb[j:j+3] in [b'MT6', b'K3K', b'K3L', b'SEC', b'SAM', b'H9H', b'H58']:
                end = j
                while end < min(j+30, len(apcb)) and 0x20 <= apcb[end] < 0x7F: end += 1
                e.module_name = apcb[j:end].decode('ascii', errors='replace').strip()
                e.module_name_offset = apcb_offset + j
                e.module_name_field_len = end - j
                mfr_off = end + 2
                if mfr_off < len(apcb): e.manufacturer = MANUFACTURER_IDS.get(apcb[mfr_off], f'0x{apcb[mfr_off]:02X}')
                break
        for prefix, density in MODULE_DENSITY_MAP.items():
            if prefix in e.module_name: e.density_guess = density; break
        ss = max(0, idx-48)
        si = apcb[ss:idx].find(SPD_ENTRY_SEPARATOR)
        if si >= 0:
            ha = ss + si; hdr = apcb[ha:idx]
            if len(hdr) >= 12: e.mfr_flag = struct.unpack_from('<H', hdr, 8)[0]; e.config_id = struct.unpack_from('<H', hdr, 10)[0]
        entries.append(e)
    return entries

def detect_current_config(blocks: List[APCBBlock]) -> str:
    """Determine if firmware SPD entries are stock, modded, or mixed."""
    configs_found = set()
    for b in blocks:
        if b.is_memg and b.spd_entries:
            for e in b.spd_entries:
                matched = False
                for gb, cfg in MEMORY_CONFIGS.items():
                    if cfg['byte6'] == e.byte6 and cfg['byte12'] == e.byte12:
                        configs_found.add(gb)
                        matched = True
                        break
                if not matched:
                    configs_found.add('custom')
            break  # Only check first MEMG block
    if not configs_found:
        return "No MEMG"
    if configs_found == {16}:
        return "Stock"
    if len(configs_found) == 1:
        gb = configs_found.pop()
        return f"Modded ({gb}GB)" if isinstance(gb, int) else "Custom"
    return "Mixed"

def density_from_bytes(byte6: int, byte12: int) -> str:
    """Map current byte6/byte12 to a total capacity string."""
    for gb, cfg in MEMORY_CONFIGS.items():
        if cfg['byte6'] == byte6 and cfg['byte12'] == byte12:
            return f"{gb}GB"
    return "16GB"

def _capacity_label(byte6: int, byte12: int, chip_count) -> str:
    """Return per-package capacity string like '4x 8GB' or '2x 16GB'.

    When chip_count is a tuple (ambiguous, e.g. Steam Deck LCD vs OLED),
    returns just the total (e.g. '16GB').
    """
    total_gb = None
    for gb, cfg in MEMORY_CONFIGS.items():
        if cfg['byte6'] == byte6 and cfg['byte12'] == byte12:
            total_gb = gb
            break
    if total_gb is None:
        return "Unknown"
    if isinstance(chip_count, tuple):
        return f"{total_gb}GB"
    return f"{chip_count}x {total_gb // chip_count}GB"

def _resolve_chip_count(device_profile: Optional[dict], variant: str = 'unknown'):
    """Resolve chip_count, using variant to disambiguate Steam Deck LCD/OLED."""
    chip_count = device_profile.get('chip_count') if device_profile else None
    if isinstance(chip_count, tuple) and variant in VARIANT_CHIP_COUNTS:
        return VARIANT_CHIP_COUNTS.get(variant, chip_count)
    return chip_count

def modify_bios_data(data: bytearray, entry_modifications: List[Dict], modify_magic: bool = False) -> List[tuple]:
    """Modify BIOS data with per-entry configurations.

    Args:
        data: bytearray of BIOS
        entry_modifications: list of dicts with keys:
            'index': int - SPD entry index
            'target_gb': int|None - 16, 32, or 64 (None if custom bytes)
            'new_name': str|None - new module name or None to keep current
            'custom_byte6': int|None - custom byte6 value (when target_gb is None)
            'custom_byte12': int|None - custom byte12 value (when target_gb is None)
            'timing': dict|None - optional timing byte overrides with keys:
                'tCK', 'tAA', 'tRCD', 'tRPab', 'tRPpb' (int values)
        modify_magic: bool - modify APCB magic byte
    Returns:
        list of (offset, old_byte, new_byte) tuples
    """
    blocks = find_apcb_blocks(bytes(data))
    mods = []
    # Build a lookup: index -> modification
    mod_by_idx = {m['index']: m for m in entry_modifications}
    # Determine magic byte from first modification's target (or default 32)
    first_target = entry_modifications[0].get('target_gb') or 32 if entry_modifications else 32
    for block in [b for b in blocks if b.is_memg]:
        if not block.spd_entries: continue
        for idx, mod in mod_by_idx.items():
            if idx >= len(block.spd_entries): continue
            e = block.spd_entries[idx]
            # Use custom bytes if provided, else lookup from MEMORY_CONFIGS
            if mod.get('custom_byte6') is not None:
                new_b6, new_b12 = mod['custom_byte6'], mod['custom_byte12']
            else:
                config = MEMORY_CONFIGS[mod['target_gb']]
                new_b6, new_b12 = config['byte6'], config['byte12']
            # Write SPD config bytes (package type + module organization)
            b6, b12 = e.offset_in_file + SPD_BYTE_PKG_TYPE, e.offset_in_file + SPD_BYTE_MODULE_ORG
            mods.append((b6, data[b6], new_b6)); mods.append((b12, data[b12], new_b12))
            data[b6] = new_b6; data[b12] = new_b12
            # Write module name if changed
            new_name = mod.get('new_name')
            if new_name is not None and e.module_name_offset >= 0 and e.module_name_field_len > 0:
                name_bytes = new_name.encode('ascii', errors='replace')[:e.module_name_field_len]
                name_bytes = name_bytes + b'\x00' * (e.module_name_field_len - len(name_bytes))
                for i, nb in enumerate(name_bytes):
                    off = e.module_name_offset + i
                    if data[off] != nb:
                        mods.append((off, data[off], nb)); data[off] = nb
            # Write timing bytes if modified
            timing = mod.get('timing')
            if timing:
                for spd_off, key in [
                    (SPD_BYTE_TCKMIN, 'tCK'), (SPD_BYTE_TAAMIN, 'tAA'),
                    (SPD_BYTE_TRCDMIN, 'tRCD'), (SPD_BYTE_TRPABMIN, 'tRPab'),
                    (SPD_BYTE_TRPPBMIN, 'tRPpb')
                ]:
                    off = e.offset_in_file + spd_off
                    new_val = timing[key]
                    if data[off] != new_val:
                        mods.append((off, data[off], new_val))
                        data[off] = new_val
        if modify_magic:
            nb = 0x51 if first_target == 32 else 0x41
            if data[block.offset] != nb: mods.append((block.offset, data[block.offset], nb)); data[block.offset] = nb
        bb = data[block.offset:block.offset+block.data_size]
        nc = calculate_apcb_checksum(bytes(bb)); oc = data[block.offset+APCB_CHECKSUM_OFFSET]
        if oc != nc: data[block.offset+APCB_CHECKSUM_OFFSET] = nc; mods.append((block.offset+APCB_CHECKSUM_OFFSET, oc, nc))
        if not verify_apcb_checksum(bytes(data[block.offset:block.offset+block.data_size])):
            raise RuntimeError(f"Checksum failed at 0x{block.offset:08X}")
    return mods

# ── Screen Replacement Patch ──

def find_edid_blocks(data: bytes) -> list:
    """Find all EDID blocks in firmware. Returns list of (offset, edid_bytes) tuples."""
    blocks = []
    pos = 0
    while pos < len(data) - 128:
        idx = data.find(EDID_MAGIC, pos)
        if idx == -1: break
        edid = data[idx:idx + 128]
        if len(edid) == 128 and sum(edid) % 256 == 0:
            blocks.append((idx, edid))
        pos = idx + 1
    return blocks

def patch_screen(data: bytearray, screen_key: str) -> List[tuple]:
    """Apply screen replacement patches to Steam Deck LCD firmware.
    Patches EDID blocks and appends version tag to $BVDT$ version strings.
    Returns list of (offset, description) tuples for logging.
    """
    profile = SCREEN_PROFILES[screen_key]
    target_edid = profile['edid']
    target_mfr_id = profile['mfr_id']
    version_tag = profile['version_tag']
    screen_name = profile['name']
    patches = []
    # Replace stock EDID blocks with target screen EDID
    for offset, edid in find_edid_blocks(bytes(data)):
        if edid[8:10] == target_mfr_id: continue  # Already this screen
        if any(edid[8:10] == mid for mid in SCREEN_MFR_IDS): continue  # Another known screen
        h_cm, v_cm = edid[21], edid[22]
        if not (5 <= h_cm <= 20 and 5 <= v_cm <= 25): continue  # Not a handheld panel
        data[offset:offset + 128] = target_edid
        patches.append((offset, f"EDID replaced with {screen_name}"))
    # Append version tag to $BVDT$ version strings
    pos = 0
    while pos < len(data) - 64:
        idx = data.find(BVDT_MAGIC, pos)
        if idx == -1: break
        ver_offset = idx + 0x0E
        if ver_offset + 32 > len(data): pos = idx + 1; continue
        ver_field = data[ver_offset:ver_offset + 32]
        null_end = ver_field.find(0x00)
        if null_end < 0: null_end = 32
        current_ver = ver_field[:null_end].decode('ascii', errors='replace')
        if version_tag not in current_ver:
            new_ver = current_ver + ' ' + version_tag
            new_bytes = new_ver.encode('ascii')[:32]
            new_bytes = new_bytes + b'\x00' * (32 - len(new_bytes))
            data[ver_offset:ver_offset + 32] = new_bytes
            patches.append((ver_offset, f"Version: '{current_ver}' -> '{new_ver}'"))
        pos = idx + 1
    return patches

# (PE Authenticode signing code was removed in v1.8.0 — requires Insyde QA.pfx)

# ── DMI / SMBIOS (AMI DmiEdit $DMI Store) ──
AMI_DMI_MAGIC = b'$DMI'
SMBIOS_FIELD_NAMES = {
    (1,0x04):'Manufacturer',(1,0x05):'Product Name',(1,0x06):'Version',(1,0x07):'Serial Number',
    (1,0x08):'UUID',(2,0x04):'Manufacturer',(2,0x05):'Product',(2,0x06):'Version',
    (2,0x07):'Serial Number',(2,0x08):'Asset Tag',(3,0x04):'Manufacturer',(3,0x07):'Serial Number',
}
SMBIOS_TYPE_NAMES = {0:'BIOS Information',1:'System Information',2:'Baseboard Information',
    3:'System Enclosure',4:'Processor',11:'OEM Strings',127:'End-of-Table'}

@dataclass
class DmiRecord:
    smbios_type: int; field_offset: int; flag: int; record_length: int
    data: bytes; offset_in_file: int; raw_bytes: bytes
    @property
    def is_current(self): return self.flag == 0x00
    @property
    def data_str(self): return self.data.rstrip(b'\x00').decode('ascii', errors='replace')
    @property
    def field_name(self): return SMBIOS_FIELD_NAMES.get((self.smbios_type, self.field_offset), f'Field 0x{self.field_offset:02X}')
    @property
    def type_name(self): return SMBIOS_TYPE_NAMES.get(self.smbios_type, f'Type {self.smbios_type}')

def find_dmi_store(data: bytes, allow_empty: bool = False) -> Optional[Tuple[int, int]]:
    pos, candidates = 0, []
    while pos < len(data) - 8:
        idx = data.find(AMI_DMI_MAGIC, pos)
        if idx < 0: break
        rs = idx + 4
        if rs + 5 <= len(data):
            st, fl = data[rs], data[rs+2]
            rl = struct.unpack_from('<H', data, rs+3)[0]
            if st <= 127 and fl in (0x00,0xFF) and 5 < rl < 256:
                scan, end = rs, min(idx+8192, len(data))
                while scan < end - 5:
                    rt, rf = data[scan], data[scan+2]
                    rrl = struct.unpack_from('<H', data, scan+3)[0]
                    if rt > 127 or rf not in (0x00,0xFF) or rrl < 5 or rrl > 256: break
                    scan += rrl
                candidates.append((idx, scan))
        pos = idx + 1
    # Fallback: accept blank $DMI stores (stock .fd firmware files)
    if not candidates and allow_empty:
        pos = 0
        while pos < len(data) - 4:
            idx = data.find(AMI_DMI_MAGIC, pos)
            if idx < 0: break
            scan, end = idx + 4, min(idx + 8192, len(data))
            while scan < end and data[scan] == 0xFF: scan += 1
            if scan > idx + 4: candidates.append((idx, scan))
            pos = idx + 1
    return max(candidates, key=lambda c: c[1]-c[0]) if candidates else None

def parse_dmi_records(data: bytes, store_start: int, store_end: int) -> list:
    records, pos = [], store_start + 4
    while pos < store_end - 5:
        st, fo, fl = data[pos], data[pos+1], data[pos+2]
        rl = struct.unpack_from('<H', data, pos+3)[0]
        if st > 127 or fl not in (0x00,0xFF) or rl < 5 or rl > 256: break
        records.append(DmiRecord(st, fo, fl, rl, data[pos+5:pos+rl], pos, data[pos:pos+rl]))
        pos += rl
    return records

def export_dmi(data: bytes) -> dict:
    result = find_dmi_store(data)
    if result is None:
        raise ValueError("No DMI data found in firmware.\n"
            "Export requires a firmware dump with populated DMI records.\n"
            "Use a raw SPI flash dump from a working (or bricked) device.")
    ss, se = result
    records = parse_dmi_records(data, ss, se)
    export = {'tool_version': APP_VERSION, 'format': 'ami_dmi_store',
              'dmi_store_offset': f'0x{ss:08X}', 'dmi_store_size': se-ss,
              'raw_store_hex': data[ss:se].hex(), 'records': [], 'system_info': {}, 'board_info': {}}
    for r in records:
        export['records'].append({'smbios_type': r.smbios_type, 'type_name': r.type_name,
            'field_offset': f'0x{r.field_offset:02X}', 'field_name': r.field_name,
            'flag': 'current' if r.is_current else 'default', 'record_length': r.record_length,
            'offset': f'0x{r.offset_in_file:08X}', 'raw_hex': r.raw_bytes.hex(), 'data_ascii': r.data_str})
        if r.is_current:
            if r.smbios_type == 1:
                if r.field_offset == 0x07: export['system_info']['serial_number'] = r.data_str
                elif r.field_offset == 0x04: export['system_info']['manufacturer'] = r.data_str
                elif r.field_offset == 0x05: export['system_info']['product_name'] = r.data_str
            elif r.smbios_type == 2:
                if r.field_offset == 0x07: export['board_info']['serial_number'] = r.data_str
                elif r.field_offset == 0x04: export['board_info']['manufacturer'] = r.data_str
                elif r.field_offset == 0x05: export['board_info']['product'] = r.data_str
    return export

def import_dmi(firmware_data: bytearray, dmi_json: dict) -> bytearray:
    result = find_dmi_store(bytes(firmware_data), allow_empty=True)
    if result is None:
        raise ValueError("No AMI $DMI store found in target firmware.\n"
            "The target file must contain a '$DMI' signature.\n"
            "Supported: raw SPI dumps (.bin) and firmware update files (.fd)")
    ts, te = result; target_size = te - ts
    source_raw = bytes.fromhex(dmi_json['raw_store_hex'])
    # Find available space (including 0xFF padding after store)
    scan = te
    while scan < len(firmware_data) and firmware_data[scan] == 0xFF: scan += 1
    available = scan - ts
    if len(source_raw) > available:
        raise ValueError(f"Source $DMI store ({len(source_raw)}B) larger than available space ({available}B)")
    firmware_data[ts:ts+len(source_raw)] = source_raw
    if len(source_raw) < available:
        firmware_data[ts+len(source_raw):ts+available] = b'\xFF' * (available - len(source_raw))
    patches = [(ts, f"$DMI store overwritten ({len(source_raw)} bytes)")]
    si, bi = dmi_json.get('system_info', {}), dmi_json.get('board_info', {})
    if si.get('serial_number'): patches.append((ts, f"System Serial: {si['serial_number']}"))
    if bi.get('serial_number'): patches.append((ts, f"Board Serial: {bi['serial_number']}"))
    return patches

# ── GUI ──
C_BG='#1a1b26'; C_BGL='#24283b'; C_BGE='#1f2335'; C_FG='#c0caf5'; C_FGD='#565f89'; C_FGB='#e0e6ff'
C_ACC='#7aa2f7'; C_GRN='#9ece6a'; C_RED='#f7768e'; C_ORG='#ff9e64'; C_CYN='#7dcfff'; C_BDR='#3b4261'
C_BTN='#3d59a1'; C_BTH='#5177c9'

class APCBToolGUI:
    def __init__(self, root):
        self.root = root; root.title(APP_TITLE); root.configure(bg=C_BG)
        self.loaded_file = None; self.loaded_data = None; self.blocks = []; self.current_config = ""
        self.detected_device = 'unknown'; self.device_profile = None; self.sd_variant = SteamDeckVariant.UNKNOWN
        # Fix combobox popup list colors (must be before any Combobox creation)
        root.option_add('*TCombobox*Listbox.background', C_BGE)
        root.option_add('*TCombobox*Listbox.foreground', C_FG)
        root.option_add('*TCombobox*Listbox.selectBackground', C_ACC)
        root.option_add('*TCombobox*Listbox.selectForeground', C_BG)
        self._setup_styles(); self._build_ui()

    def _setup_styles(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('.', background=C_BG, foreground=C_FG, fieldbackground=C_BGE, bordercolor=C_BDR,
                    darkcolor=C_BG, lightcolor=C_BGL, troughcolor=C_BGE, selectbackground=C_ACC, selectforeground=C_BG, focuscolor=C_ACC)
        for n,kw in [('TFrame',{'background':C_BG}),('TLabel',{'background':C_BG,'foreground':C_FG,'font':('Segoe UI',10)}),
            ('Title.TLabel',{'font':('Segoe UI',14,'bold'),'foreground':C_FGB,'background':C_BG}),
            ('Subtitle.TLabel',{'font':('Segoe UI',10),'foreground':C_FGD,'background':C_BG}),
            ('Section.TLabel',{'font':('Segoe UI',11,'bold'),'foreground':C_ACC,'background':C_BG}),
            ('Status.TLabel',{'font':('Segoe UI',10),'foreground':C_FGD,'background':C_BGL}),
            ('Good.TLabel',{'foreground':C_GRN,'background':C_BGL,'font':('Segoe UI',10,'bold')}),
            ('Warn.TLabel',{'foreground':C_ORG,'background':C_BGL,'font':('Segoe UI',10,'bold')}),
            ('Bad.TLabel',{'foreground':C_RED,'background':C_BGL,'font':('Segoe UI',10,'bold')}),
            ('Info.TLabel',{'foreground':C_CYN,'background':C_BGL,'font':('Segoe UI',10)})]:
            s.configure(n, **kw)
        s.configure('TButton', font=('Segoe UI',10), padding=(16,8), background=C_BTN, foreground=C_FGB, borderwidth=0)
        s.map('TButton', background=[('active',C_BTH),('disabled',C_BGL)], foreground=[('disabled',C_FGD)])
        s.configure('Action.TButton', font=('Segoe UI',11,'bold'), padding=(24,10), background=C_GRN, foreground=C_BG)
        s.map('Action.TButton', background=[('active','#b5e685'),('disabled',C_BGL)], foreground=[('disabled',C_FGD)])
        s.configure('TCombobox', fieldbackground=C_BGE, background=C_BGL, foreground=C_FG,
                    arrowcolor=C_FG, selectbackground=C_ACC, selectforeground=C_BG)
        s.map('TCombobox',
              fieldbackground=[('readonly',C_BGE),('disabled',C_BGL),('focus',C_BGE)],
              foreground=[('readonly',C_FG),('disabled',C_FGD),('focus',C_FG)],
              background=[('readonly',C_BGL),('disabled',C_BG)],
              selectbackground=[('readonly',C_ACC)], selectforeground=[('readonly',C_BG)],
              arrowcolor=[('disabled',C_FGD)])
        s.configure('TPanedwindow', background=C_BG)
        s.configure('Sash', sashthickness=6, gripcount=0, sashrelief='flat')
        for w in ['TRadiobutton','TCheckbutton']:
            s.configure(w, background=C_BGL, foreground=C_FG, font=('Segoe UI',10), focuscolor=C_BGL, indicatorcolor=C_BGE)
            s.map(w, indicatorcolor=[('selected',C_ACC)], background=[('active',C_BGL)])

    def _build_ui(self):
        # Header (above the paned split)
        top = ttk.Frame(self.root, padding=(16,12,16,0)); top.pack(fill='x')
        h = ttk.Frame(top); h.pack(fill='x')
        ttk.Label(h, text="SD Memory Mod Tool", style='Title.TLabel').pack(side='left')
        ttk.Label(h, text=f"v{APP_VERSION}", style='Subtitle.TLabel').pack(side='left', padx=(8,0), pady=(4,0))
        # Two-column paned layout
        paned = ttk.PanedWindow(self.root, orient='horizontal')
        paned.pack(fill='both', expand=True, padx=16, pady=(4,4))
        self._paned = paned
        # LEFT COLUMN — settings + buttons
        left = ttk.Frame(paned); paned.add(left, weight=0)
        # File selection row
        ff = ttk.Frame(left); ff.pack(fill='x', pady=(8,8))
        ttk.Button(ff, text="Open BIOS File", command=self._open_file).pack(side='left')
        self.btn_dmi_export = ttk.Button(ff, text="Export DMI", command=self._export_dmi, state='disabled')
        self.btn_dmi_export.pack(side='left', padx=(8,0))
        self.btn_dmi_import = ttk.Button(ff, text="Import DMI", command=self._import_dmi, state='disabled')
        self.btn_dmi_import.pack(side='left', padx=(8,0))
        self.file_label = ttk.Label(ff, text="No file loaded", style='Subtitle.TLabel'); self.file_label.pack(side='left', padx=(12,0))
        # File info panel
        ic = tk.Frame(left, bg=C_BGL, padx=16, pady=12, highlightbackground=C_BDR, highlightthickness=1); ic.pack(fill='x', pady=(0,10))
        r1 = tk.Frame(ic, bg=C_BGL); r1.pack(fill='x')
        self.lbl_fn = ttk.Label(r1, text="--", style='Info.TLabel'); self.lbl_fn.pack(side='left')
        self.lbl_fs = ttk.Label(r1, text="", style='Status.TLabel'); self.lbl_fs.pack(side='right')
        r1b = tk.Frame(ic, bg=C_BGL); r1b.pack(fill='x', pady=(4,0))
        self.lbl_dev = ttk.Label(r1b, text="", style='Status.TLabel'); self.lbl_dev.pack(side='left')
        # Steam Deck variant selector (LCD / OLED) — only enabled when Steam Deck detected
        self.variant_var = tk.StringVar(value="Auto")
        self.variant_combo = ttk.Combobox(r1b, textvariable=self.variant_var,
            values=["Auto", "LCD", "OLED"], state='disabled', width=8, font=('Segoe UI', 9))
        self.variant_combo.pack(side='left', padx=(8, 0))
        self.variant_label = tk.Label(r1b, text="", bg=C_BGL, fg=C_FGD, font=('Segoe UI', 9))
        self.variant_label.pack(side='left', padx=(4, 0))
        self.variant_combo.bind('<<ComboboxSelected>>', self._on_variant_changed)
        r2 = tk.Frame(ic, bg=C_BGL); r2.pack(fill='x', pady=(4,0))
        self.lbl_bl = ttk.Label(r2, text="", style='Status.TLabel'); self.lbl_bl.pack(side='left')
        self.lbl_cf = ttk.Label(r2, text="", style='Status.TLabel'); self.lbl_cf.pack(side='right')
        # Target configuration
        ttk.Label(left, text="Target Configuration", style='Section.TLabel').pack(anchor='w', pady=(4,0))
        ttk.Label(left, text="Sets density and SPD timings for all checked entries below", style='Subtitle.TLabel').pack(anchor='w', pady=(0,4))
        tc = tk.Frame(left, bg=C_BGL, padx=16, pady=12, highlightbackground=C_BDR, highlightthickness=1); tc.pack(fill='x', pady=(0,10))
        self.target_var = tk.IntVar(value=32)
        self.target_radios = {}
        for val, txt, desc in [(32,"32GB Upgrade","Patches SPD for 32GB"),(64,"64GB Upgrade","Patches SPD for 64GB (ROG Ally series)"),(16,"16GB Restore","Restores stock configuration")]:
            rf = tk.Frame(tc, bg=C_BGL); rf.pack(fill='x', pady=(0,4))
            rb = ttk.Radiobutton(rf, text=txt, variable=self.target_var, value=val); rb.pack(side='left')
            self.target_radios[val] = rb
            ttk.Label(rf, text=f"-- {desc}", style='Status.TLabel').pack(side='left', padx=(8,0))
        of = tk.Frame(tc, bg=C_BGL); of.pack(fill='x', pady=(6,0))
        self.magic_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="Modify APCB magic byte (cosmetic, not required)", variable=self.magic_var).pack(side='left')
        df = tk.Frame(tc, bg=C_BGL); df.pack(fill='x', pady=(4,0))
        tk.Label(df, text="Screen patch:", bg=C_BGL, fg=C_FG, font=('Segoe UI', 10)).pack(side='left')
        self.screen_var = tk.StringVar(value="None")
        screen_options = ["None"] + [p['name'] for p in SCREEN_PROFILES.values()]
        self.screen_combo = ttk.Combobox(df, textvariable=self.screen_var, values=screen_options,
            state='disabled', width=20, font=('Segoe UI', 9))
        self.screen_combo.pack(side='left', padx=(8,0))
        tk.Label(df, text="(Steam Deck LCD only)", bg=C_BGL, fg=C_FGD, font=('Segoe UI', 9)).pack(side='left', padx=(8,0))
        # Speed setting
        spf = tk.Frame(tc, bg=C_BGL); spf.pack(fill='x', pady=(4,0))
        tk.Label(spf, text="SPD Timings:", bg=C_BGL, fg=C_FG, font=('Segoe UI', 10)).pack(side='left')
        speed_options = [SPEED_PROFILES[k]['name'] for k in sorted(SPEED_PROFILES.keys(), reverse=True)]
        speed_options.append('Custom')
        self.speed_var = tk.StringVar(value='5333 MT/s')
        self.speed_combo = ttk.Combobox(spf, textvariable=self.speed_var, values=speed_options,
            state='disabled', width=14, font=('Segoe UI', 9))
        self.speed_combo.pack(side='left', padx=(8,0))
        tk.Label(spf, text="(SPD timing capability \u2014 actual speed set via CBS/PBS)", bg=C_BGL, fg=C_FGD, font=('Segoe UI', 9)).pack(side='left', padx=(8,0))
        # SPD entry section label
        ttk.Label(left, text="SPD Entries to Modify", style='Section.TLabel').pack(anchor='w', pady=(4,4))
        # Button row — pack BEFORE canvas so buttons always visible at bottom
        br = ttk.Frame(left); br.pack(side='bottom', fill='x', pady=(8,4))
        self.btn_mod = ttk.Button(br, text="Apply Modification", style='Action.TButton', command=self._do_modify, state='disabled'); self.btn_mod.pack(side='left')
        self.btn_ana = ttk.Button(br, text="Analyze Only", command=self._do_analyze, state='disabled'); self.btn_ana.pack(side='left', padx=(8,0))
        # Footer warning — pack BEFORE canvas
        ft = ttk.Frame(left); ft.pack(side='bottom', fill='x', pady=(4,0))
        ttk.Label(ft, text="Always back up your original BIOS before modifying.", style='Subtitle.TLabel').pack(side='left')
        # SPD entry canvas — fills remaining space
        self.entry_outer = tk.Frame(left, bg=C_BDR, padx=1, pady=1); self.entry_outer.pack(fill='both', expand=True, pady=(0,4))
        self.entry_canvas = tk.Canvas(self.entry_outer, bg=C_BGL, highlightthickness=0, height=100)
        self.entry_scrollbar = ttk.Scrollbar(self.entry_outer, orient='vertical', command=self.entry_canvas.yview)
        self.entry_inner = tk.Frame(self.entry_canvas, bg=C_BGL)
        self.entry_inner.bind('<Configure>', lambda e: self.entry_canvas.configure(scrollregion=self.entry_canvas.bbox('all')))
        self.entry_canvas.create_window((0, 0), window=self.entry_inner, anchor='nw')
        self.entry_canvas.configure(yscrollcommand=self.entry_scrollbar.set)
        self.entry_canvas.pack(side='left', fill='both', expand=True)
        self.entry_scrollbar.pack(side='right', fill='y')
        # Mouse wheel scrolling — only for SPD canvas area (not global)
        self.entry_canvas.bind('<MouseWheel>', self._on_canvas_mousewheel)
        self.entry_inner.bind('<MouseWheel>', self._on_canvas_mousewheel)
        # Placeholder
        self.entry_placeholder = ttk.Label(self.entry_inner, text="  Load a BIOS file to see SPD entries", style='Status.TLabel')
        self.entry_placeholder.pack(anchor='w', padx=8, pady=8)
        self.entry_rows = []
        self.select_all_var = tk.BooleanVar(value=True)
        # Wire global target radio to sync per-entry dropdowns
        self.target_var.trace_add('write', self._sync_target_to_entries)
        # Wire global SPD timings combo to sync per-entry dropdowns
        self.speed_var.trace_add('write', self._sync_speed_to_entries)
        # RIGHT COLUMN — log output
        right = ttk.Frame(paned); paned.add(right, weight=1)
        lh = ttk.Frame(right); lh.pack(fill='x', pady=(8,4))
        ttk.Label(lh, text="Log Output", style='Section.TLabel').pack(side='left')
        ttk.Button(lh, text="Copy Log", command=self._copy_log).pack(side='right', padx=(4,0))
        ttk.Button(lh, text="Clear Log", command=self._log_clear).pack(side='right')
        lf = tk.Frame(right, bg=C_BDR, padx=1, pady=1); lf.pack(fill='both', expand=True)
        self.log = scrolledtext.ScrolledText(lf, wrap='none', font=('Consolas',9), bg=C_BGE, fg=C_FG, insertbackground=C_FG,
            selectbackground=C_ACC, selectforeground=C_BG, relief='flat', borderwidth=0, padx=8, pady=8, state='disabled')
        self.log.pack(fill='both', expand=True)
        # Horizontal scrollbar for log (wrap=none)
        log_hscroll = ttk.Scrollbar(lf, orient='horizontal', command=self.log.xview)
        log_hscroll.pack(side='bottom', fill='x')
        self.log.configure(xscrollcommand=log_hscroll.set)
        for t,c in [('info',C_FG),('success',C_GRN),('warning',C_ORG),('error',C_RED),('accent',C_ACC),('cyan',C_CYN),('dim',C_FGD)]:
            self.log.tag_configure(t, foreground=c)
        self.log.tag_configure('header', foreground=C_FGB, font=('Consolas',9,'bold'))
        # Set initial sash position after layout
        def _set_sash():
            pw = paned.winfo_width()
            paned.sashpos(0, int(pw * 0.40))  # Left 40%, Log 60%
        self.root.after(100, _set_sash)

    def _log(self, text, tag='info'):
        self.log.configure(state='normal'); self.log.insert('end', text+'\n', tag); self.log.see('end'); self.log.configure(state='disabled')
    def _log_clear(self):
        self.log.configure(state='normal'); self.log.delete('1.0','end'); self.log.configure(state='disabled')
    def _copy_log(self):
        text = self.log.get('1.0', 'end-1c')
        self.root.clipboard_clear(); self.root.clipboard_append(text)

    def _populate_entries(self, entries):
        """Populate the SPD entry editor rows from the first MEMG block's entries."""
        for w in self.entry_inner.winfo_children(): w.destroy()
        self.entry_rows = []
        if not entries:
            ttk.Label(self.entry_inner, text="  No SPD entries found", style='Status.TLabel').pack(anchor='w', padx=8, pady=8)
            return
        # Determine available density options based on device
        if self.device_profile and 64 in self.device_profile.get('memory_targets', []):
            density_options = ['16GB', '32GB', '64GB', 'Custom']
        else:
            density_options = ['16GB', '32GB', 'Custom']
        # Select All checkbox
        sa_frame = tk.Frame(self.entry_inner, bg=C_BGL); sa_frame.pack(fill='x', padx=8, pady=(6,2))
        self.select_all_var.set(False)
        ttk.Checkbutton(sa_frame, text="Select All", variable=self.select_all_var, command=self._toggle_all).pack(side='left')
        # Column headers — same font size (9) and widget types as rows for pixel-perfect alignment
        hdr = tk.Frame(self.entry_inner, bg=C_BGL); hdr.pack(fill='x', padx=8, pady=(4,2))
        _hdr_font = ('Consolas', 9)  # Must match row font size
        _hdr_kw = dict(bg=C_BGL, fg=C_FGD, font=_hdr_font, anchor='w')
        # Checkbox placeholder — real checkbox, same width as row checkboxes
        _hcb = ttk.Checkbutton(hdr, text=''); _hcb.pack(side='left')
        _hcb.state(['disabled'])
        tk.Label(hdr, text='#', width=3, **_hdr_kw).pack(side='left')
        tk.Label(hdr, text='Type', width=7, **_hdr_kw).pack(side='left')
        # Combobox header — same width as row prefix combo
        _hp = ttk.Combobox(hdr, values=['Mfr Prefix'], state='disabled', width=14, font=_hdr_font)
        _hp.set('Mfr Prefix'); _hp.pack(side='left', padx=(2,0))
        # Entry header — same width as row suffix entry
        _hs = tk.Entry(hdr, font=_hdr_font, width=14, bg=C_BGL, fg=C_FGD, relief='flat',
            borderwidth=1, highlightbackground=C_BDR, highlightthickness=1, state='disabled',
            disabledbackground=C_BGL, disabledforeground=C_FGD)
        _hs.pack(side='left', padx=(0,2))
        _hs.configure(state='normal'); _hs.insert(0, 'Module Suffix'); _hs.configure(state='disabled')
        # Density combo header — same width as row density combo
        _hd = ttk.Combobox(hdr, values=['Cap'], state='disabled', width=5, font=_hdr_font)
        _hd.set('Cap'); _hd.pack(side='left', padx=(0,2))
        # Byte6/Byte12 entry headers — same width as row hex entries
        for hdr_text in ['b6', 'b12']:
            _he = tk.Entry(hdr, font=_hdr_font, width=4, bg=C_BGL, fg=C_FGD, relief='flat',
                borderwidth=1, highlightbackground=C_BDR, highlightthickness=1, state='disabled',
                disabledbackground=C_BGL, disabledforeground=C_FGD)
            _he.pack(side='left', padx=(0,1))
            _he.configure(state='normal'); _he.insert(0, hdr_text); _he.configure(state='disabled')
        tk.Label(hdr, text='Current', **_hdr_kw).pack(side='left')
        # Timing column headers (second line)
        thdr = tk.Frame(self.entry_inner, bg=C_BGL); thdr.pack(fill='x', padx=8)
        # Indent to align past checkbox + index
        _thcb = ttk.Checkbutton(thdr, text=''); _thcb.pack(side='left'); _thcb.state(['disabled'])
        tk.Label(thdr, text='', width=3, **_hdr_kw).pack(side='left')
        # SPD Rate combo header — same width as row speed combo
        _hsp = ttk.Combobox(thdr, values=['SPD Rate'], state='disabled', width=12, font=_hdr_font)
        _hsp.set('SPD Rate'); _hsp.pack(side='left', padx=(2,2))
        # Timing byte headers
        for lbl in ['tCK', 'tAA', 'tRCD', 'tRPab', 'tRPpb']:
            _ht = tk.Entry(thdr, font=_hdr_font, width=5, bg=C_BGL, fg=C_FGD, relief='flat',
                borderwidth=1, highlightbackground=C_BDR, highlightthickness=1, state='disabled',
                disabledbackground=C_BGL, disabledforeground=C_FGD)
            _ht.pack(side='left', padx=(0,1))
            _ht.configure(state='normal'); _ht.insert(0, lbl); _ht.configure(state='disabled')
        # Separator
        tk.Frame(self.entry_inner, bg=C_BDR, height=1).pack(fill='x', padx=8, pady=2)
        # Individual entry rows
        for i, e in enumerate(entries):
            enabled_var = tk.BooleanVar(value=False)
            current_density = density_from_bytes(e.byte6, e.byte12)
            density_var = tk.StringVar(value=current_density)
            # Split module name into prefix and suffix
            orig_name = e.module_name or ''
            orig_prefix = ''
            orig_prefix_label = ''
            orig_suffix = orig_name
            for pfx, label in MODULE_NAME_PREFIXES:
                if orig_name.startswith(pfx):
                    orig_prefix = pfx
                    orig_prefix_label = label
                    orig_suffix = orig_name[len(pfx):]
                    break
            prefix_var = tk.StringVar(value=orig_prefix_label)
            suffix_var = tk.StringVar(value=orig_suffix)
            ef = tk.Frame(self.entry_inner, bg=C_BGL); ef.pack(fill='x', padx=8, pady=1)
            # Checkbox
            cb = ttk.Checkbutton(ef, variable=enabled_var)
            cb.pack(side='left')
            # Index
            tk.Label(ef, text=f"[{i+1}]", bg=C_BGL, fg=C_FG, font=('Consolas', 9), width=3, anchor='w').pack(side='left')
            # Type
            tk.Label(ef, text=e.mem_type, bg=C_BGL, fg=C_FGD, font=('Consolas', 9), width=7, anchor='w').pack(side='left')
            # Manufacturer prefix dropdown (shows descriptive labels, maps to 3-char prefix)
            has_name = e.module_name_offset >= 0
            prefix_combo = ttk.Combobox(ef, textvariable=prefix_var, values=MODULE_PREFIX_LABELS,
                state='disabled', width=14, font=('Consolas', 9))
            prefix_combo.pack(side='left', padx=(2,0))
            # Module name suffix entry (constrained)
            field_len = e.module_name_field_len if e.module_name_field_len > 0 else 20
            suffix_entry = tk.Entry(ef, textvariable=suffix_var, font=('Consolas', 9), width=14,
                bg=C_BGE, fg=C_FG, insertbackground=C_FG, relief='flat', borderwidth=1,
                highlightbackground=C_BDR, highlightthickness=1, state='disabled')
            suffix_entry.pack(side='left', padx=(0,2))
            # Validate suffix: printable ASCII only, length constrained by field_len minus prefix (3 chars)
            def _validate_suffix(new_val, fl=field_len, pv=prefix_var):
                # Prefix is always 3 chars regardless of display label
                pfx = MODULE_PREFIX_MAP.get(pv.get(), pv.get())
                max_suf = fl - len(pfx)
                if len(new_val) > max_suf: return False
                return all(0x20 <= ord(c) < 0x7F for c in new_val)
            vcmd = (self.root.register(_validate_suffix), '%P')
            suffix_entry.configure(validate='key', validatecommand=vcmd)
            if not has_name:
                suffix_var.set('(no name field)')
            # Density combobox
            density_combo = ttk.Combobox(ef, textvariable=density_var, values=density_options,
                state='disabled', width=5, font=('Consolas', 9))
            density_combo.pack(side='left', padx=(0,2))
            # Hex byte6/byte12 entry fields for manual editing
            byte6_var = tk.StringVar(value=f"0x{e.byte6:02X}")
            byte12_var = tk.StringVar(value=f"0x{e.byte12:02X}")
            byte6_entry = tk.Entry(ef, textvariable=byte6_var, font=('Consolas', 9), width=4,
                bg=C_BGE, fg=C_FG, insertbackground=C_FG, relief='flat', borderwidth=1,
                highlightbackground=C_BDR, highlightthickness=1, state='disabled')
            byte6_entry.pack(side='left', padx=(0,1))
            byte12_entry = tk.Entry(ef, textvariable=byte12_var, font=('Consolas', 9), width=4,
                bg=C_BGE, fg=C_FG, insertbackground=C_FG, relief='flat', borderwidth=1,
                highlightbackground=C_BDR, highlightthickness=1, state='disabled')
            byte12_entry.pack(side='left', padx=(0,1))
            # Hex validation: 0x prefix + up to 2 hex digits, max 4 chars
            def _validate_hex(new_val):
                if new_val == '': return True
                if len(new_val) > 4: return False
                if new_val.startswith('0x') or new_val.startswith('0X'):
                    return all(c in '0123456789abcdefABCDEF' for c in new_val[2:])
                return all(c in '0123456789abcdefABCDEFxX' for c in new_val)
            hex_vcmd = (self.root.register(_validate_hex), '%P')
            byte6_entry.configure(validate='key', validatecommand=hex_vcmd)
            byte12_entry.configure(validate='key', validatecommand=hex_vcmd)
            # Bidirectional sync: density dropdown → hex fields
            def _on_density_changed(*args, dv=density_var, b6v=byte6_var, b12v=byte12_var):
                val = dv.get()
                if val == 'Custom': return
                try:
                    gb = int(val.replace('GB', ''))
                except ValueError:
                    return
                if gb in MEMORY_CONFIGS:
                    b6v.set(f"0x{MEMORY_CONFIGS[gb]['byte6']:02X}")
                    b12v.set(f"0x{MEMORY_CONFIGS[gb]['byte12']:02X}")
            density_var.trace_add('write', _on_density_changed)
            # Bidirectional sync: hex fields → density dropdown
            def _on_hex_changed(*args, dv=density_var, b6v=byte6_var, b12v=byte12_var):
                try:
                    b6 = int(b6v.get(), 16)
                    b12 = int(b12v.get(), 16)
                except (ValueError, TypeError):
                    return
                for gb, cfg in MEMORY_CONFIGS.items():
                    if cfg['byte6'] == b6 and cfg['byte12'] == b12:
                        if dv.get() != f"{gb}GB":
                            dv.set(f"{gb}GB")
                        return
                if dv.get() != 'Custom':
                    dv.set('Custom')
            byte6_var.trace_add('write', _on_hex_changed)
            byte12_var.trace_add('write', _on_hex_changed)
            # Current capacity label (read-only)
            chip_count = _resolve_chip_count(self.device_profile, self.sd_variant)
            if chip_count is not None:
                cap_info = _capacity_label(e.byte6, e.byte12, chip_count)
            else:
                cap_info = density_from_bytes(e.byte6, e.byte12)
            tk.Label(ef, text=cap_info, bg=C_BGL, fg=C_FGD, font=('Consolas', 8), anchor='w').pack(side='left')
            # --- Timing row (second line per entry) ---
            tf = tk.Frame(self.entry_inner, bg=C_BGL); tf.pack(fill='x', padx=8, pady=(0,2))
            # Indent past checkbox + index (matching header alignment)
            _tcb = ttk.Checkbutton(tf, text=''); _tcb.pack(side='left'); _tcb.state(['disabled'])
            tk.Label(tf, text='', bg=C_BGL, width=3, font=('Consolas', 9)).pack(side='left')
            # Speed dropdown per entry
            current_speed = speed_from_tck(e.tCK_byte)
            speed_options_entry = [SPEED_PROFILES[k]['name'] for k in sorted(SPEED_PROFILES.keys(), reverse=True)] + ['Custom']
            speed_var = tk.StringVar(value=current_speed)
            speed_combo = ttk.Combobox(tf, textvariable=speed_var, values=speed_options_entry,
                state='disabled', width=12, font=('Consolas', 9))
            speed_combo.pack(side='left', padx=(2,2))
            # Timing hex fields: tCK, tAA, tRCD, tRPab, tRPpb
            tCK_var = tk.StringVar(value=f"0x{e.tCK_byte:02X}")
            tAA_var = tk.StringVar(value=f"0x{e.spd_bytes[SPD_BYTE_TAAMIN]:02X}" if len(e.spd_bytes) > SPD_BYTE_TAAMIN else "0x00")
            tRCD_var = tk.StringVar(value=f"0x{e.spd_bytes[SPD_BYTE_TRCDMIN]:02X}" if len(e.spd_bytes) > SPD_BYTE_TRCDMIN else "0x00")
            tRPab_var = tk.StringVar(value=f"0x{e.spd_bytes[SPD_BYTE_TRPABMIN]:02X}" if len(e.spd_bytes) > SPD_BYTE_TRPABMIN else "0x00")
            tRPpb_var = tk.StringVar(value=f"0x{e.spd_bytes[SPD_BYTE_TRPPBMIN]:02X}" if len(e.spd_bytes) > SPD_BYTE_TRPPBMIN else "0x00")
            timing_vars = [tCK_var, tAA_var, tRCD_var, tRPab_var, tRPpb_var]
            timing_widgets = []
            for tv in timing_vars:
                tw = tk.Entry(tf, textvariable=tv, font=('Consolas', 9), width=5,
                    bg=C_BGE, fg=C_FG, insertbackground=C_FG, relief='flat', borderwidth=1,
                    highlightbackground=C_BDR, highlightthickness=1, state='disabled')
                tw.pack(side='left', padx=(0,1))
                tw.configure(validate='key', validatecommand=hex_vcmd)
                timing_widgets.append(tw)
            # Bidirectional sync: speed dropdown → tCK hex field
            def _on_speed_changed(*args, sv=speed_var, tv=tCK_var):
                val = sv.get()
                tck = tck_from_speed(val)
                if tck is not None:
                    tv.set(f"0x{tck:02X}")
            speed_var.trace_add('write', _on_speed_changed)
            # Bidirectional sync: tCK hex field → speed dropdown
            def _on_tck_changed(*args, sv=speed_var, tv=tCK_var):
                try:
                    tck = int(tv.get(), 16)
                except (ValueError, TypeError):
                    return
                label = speed_from_tck(tck)
                if sv.get() != label:
                    sv.set(label)
            tCK_var.trace_add('write', _on_tck_changed)
            # Store row data
            row = {
                'index': i,
                'enabled_var': enabled_var,
                'prefix_var': prefix_var,
                'suffix_var': suffix_var,
                'density_var': density_var,
                'byte6_var': byte6_var,
                'byte12_var': byte12_var,
                'prefix_widget': prefix_combo,
                'suffix_widget': suffix_entry,
                'combo_widget': density_combo,
                'byte6_widget': byte6_entry,
                'byte12_widget': byte12_entry,
                'original_name': orig_name,
                'original_prefix': orig_prefix,
                'original_suffix': orig_suffix,
                'original_density': current_density,
                'max_name_len': field_len,
                'has_name_field': has_name,
                # SPD timing fields
                'speed_var': speed_var,
                'tCK_var': tCK_var,
                'tAA_var': tAA_var,
                'tRCD_var': tRCD_var,
                'tRPab_var': tRPab_var,
                'tRPpb_var': tRPpb_var,
                'speed_widget': speed_combo,
                'timing_widgets': timing_widgets,
                'timing_frame': tf,
                'original_tCK': e.tCK_byte,
                'original_tAA': e.spd_bytes[SPD_BYTE_TAAMIN] if len(e.spd_bytes) > SPD_BYTE_TAAMIN else 0,
                'original_tRCD': e.spd_bytes[SPD_BYTE_TRCDMIN] if len(e.spd_bytes) > SPD_BYTE_TRCDMIN else 0,
                'original_tRPab': e.spd_bytes[SPD_BYTE_TRPABMIN] if len(e.spd_bytes) > SPD_BYTE_TRPABMIN else 0,
                'original_tRPpb': e.spd_bytes[SPD_BYTE_TRPPBMIN] if len(e.spd_bytes) > SPD_BYTE_TRPPBMIN else 0,
            }
            self.entry_rows.append(row)
            # Bind checkbox toggle to enable/disable widgets and sync density/timings from global
            cb.configure(command=lambda v=enabled_var, pw=prefix_combo, sw=suffix_entry,
                         cw=density_combo, b6w=byte6_entry, b12w=byte12_entry,
                         hn=has_name, dv=density_var,
                         scw=speed_combo, tws=timing_widgets, spv=speed_var:
                         self._on_entry_toggle(v, pw, sw, cw, b6w, b12w, hn, dv, scw, tws, spv))
        # Bind mousewheel to all child widgets for scrolling
        self._bind_mousewheel_recursive(self.entry_inner)

    def _on_canvas_mousewheel(self, event: 'tk.Event') -> None:
        """Handle mousewheel scrolling in the SPD entry canvas."""
        self.entry_canvas.yview_scroll(-1 * (event.delta // 120), 'units')

    def _bind_mousewheel_recursive(self, widget: 'tk.Widget') -> None:
        """Bind mousewheel scrolling to widget and all its descendants."""
        widget.bind('<MouseWheel>', self._on_canvas_mousewheel)
        for child in widget.winfo_children():
            self._bind_mousewheel_recursive(child)

    def _on_entry_toggle(self, var: 'tk.BooleanVar', pw: 'tk.Widget',
                         sw: 'tk.Widget', cw: 'tk.Widget',
                         b6w: 'tk.Widget', b12w: 'tk.Widget',
                         has_name: bool, density_var: 'tk.StringVar',
                         scw: 'tk.Widget' = None, tws: list = None,
                         spv: 'tk.StringVar' = None) -> None:
        """Handle per-entry checkbox toggle: enable/disable widgets and sync density/timings."""
        if var.get():
            if has_name:
                pw.configure(state='readonly')
                sw.configure(state='normal', fg=C_FG, insertbackground=C_FG)
            cw.configure(state='readonly')
            b6w.configure(state='normal', fg=C_FG, insertbackground=C_FG)
            b12w.configure(state='normal', fg=C_FG, insertbackground=C_FG)
            density_var.set(f"{self.target_var.get()}GB")
            # Enable SPD timing widgets
            if scw: scw.configure(state='readonly')
            if tws:
                for tw in tws:
                    tw.configure(state='normal', fg=C_FG, insertbackground=C_FG)
            if spv: spv.set(self.speed_var.get())
        else:
            pw.configure(state='disabled')
            sw.configure(state='disabled', fg=C_FG, insertbackground=C_FG)
            cw.configure(state='disabled')
            b6w.configure(state='disabled')
            b12w.configure(state='disabled')
            # Disable SPD timing widgets
            if scw: scw.configure(state='disabled')
            if tws:
                for tw in tws:
                    tw.configure(state='disabled')

    def _toggle_all(self):
        """Toggle all entry checkboxes and enable/disable widgets."""
        val = self.select_all_var.get()
        density_str = f"{self.target_var.get()}GB"
        speed_str = self.speed_var.get()
        for row in self.entry_rows:
            row['enabled_var'].set(val)
            if val:
                if row['has_name_field']:
                    row['prefix_widget'].configure(state='readonly')
                    row['suffix_widget'].configure(state='normal', fg=C_FG, insertbackground=C_FG)
                row['combo_widget'].configure(state='readonly')
                row['byte6_widget'].configure(state='normal', fg=C_FG, insertbackground=C_FG)
                row['byte12_widget'].configure(state='normal', fg=C_FG, insertbackground=C_FG)
                row['density_var'].set(density_str)
                # Enable SPD timing widgets
                if 'speed_widget' in row:
                    row['speed_widget'].configure(state='readonly')
                if 'timing_widgets' in row:
                    for tw in row['timing_widgets']:
                        tw.configure(state='normal', fg=C_FG, insertbackground=C_FG)
                if 'speed_var' in row:
                    row['speed_var'].set(speed_str)
            else:
                row['prefix_widget'].configure(state='disabled')
                row['suffix_widget'].configure(state='disabled', fg=C_FG, insertbackground=C_FG)
                row['combo_widget'].configure(state='disabled')
                row['byte6_widget'].configure(state='disabled')
                row['byte12_widget'].configure(state='disabled')
                # Disable SPD timing widgets
                if 'speed_widget' in row:
                    row['speed_widget'].configure(state='disabled')
                if 'timing_widgets' in row:
                    for tw in row['timing_widgets']:
                        tw.configure(state='disabled')

    def _sync_target_to_entries(self, *args):
        """When global target changes, update all checked entries' density dropdowns and hex fields."""
        target = self.target_var.get()
        density_str = f"{target}GB"
        for row in self.entry_rows:
            if row['enabled_var'].get():
                row['density_var'].set(density_str)
                # Hex fields are auto-updated by the density_var trace callback

    def _sync_speed_to_entries(self, *args):
        """When global SPD timings dropdown changes, update all checked entries."""
        speed = self.speed_var.get()
        for row in self.entry_rows:
            if row['enabled_var'].get() and 'speed_var' in row:
                row['speed_var'].set(speed)
                # tCK hex field is auto-updated by the speed_var trace callback

    def _on_variant_changed(self, event=None):
        """Handle user changing the Steam Deck variant dropdown."""
        val = self.variant_var.get()
        if val == "LCD":
            self.sd_variant = SteamDeckVariant.LCD
        elif val == "OLED":
            self.sd_variant = SteamDeckVariant.OLED
        else:
            self.sd_variant = SteamDeckVariant.UNKNOWN
        # Update device display name
        if self.sd_variant != SteamDeckVariant.UNKNOWN:
            name = f"Steam Deck ({self.sd_variant.value.upper()})"
        else:
            name = "Steam Deck"
        self.lbl_dev.configure(text=f"Device: {name}", style='Info.TLabel')
        self.variant_label.configure(text="(manually selected)" if val != "Auto" else "(select variant)")
        # Update screen patch dropdown (LCD only, not OLED)
        if self.sd_variant != SteamDeckVariant.OLED:
            self.screen_combo.configure(state='readonly')
        else:
            self.screen_var.set('None')
            self.screen_combo.configure(state='disabled')
        # Re-populate entry rows to update capacity labels
        if self.blocks:
            first_memg = next((b for b in self.blocks if b.is_memg and b.spd_entries), None)
            if first_memg:
                self._populate_entries(first_memg.spd_entries)

    def _open_file(self):
        fp = filedialog.askopenfilename(title="Open BIOS File", filetypes=[("All files","*.*"),("BIOS Files","*.bin *.fd *.rom")])
        if not fp: return
        self._log_clear(); self._log(f"Loading: {fp}", 'accent')
        try:
            with open(fp,'rb') as f: data = f.read()
        except Exception as e: self._log(f"ERROR: {e}", 'error'); return
        self.loaded_file, self.loaded_data = fp, data
        fn, fs = os.path.basename(fp), len(data)
        self.file_label.configure(text=fn); self.lbl_fn.configure(text=fn)
        self.lbl_fs.configure(text=f"{fs:,} bytes ({fs/1024/1024:.2f} MB)")
        # Device detection
        self.detected_device = detect_device(data)
        self.device_profile = DEVICE_PROFILES.get(self.detected_device)
        device_name = self.device_profile['name'] if self.device_profile else 'Unknown Device'
        # Steam Deck variant detection (LCD vs OLED)
        self.sd_variant = SteamDeckVariant.UNKNOWN
        if self.detected_device == 'steam_deck':
            self.sd_variant = detect_steam_deck_variant(data, filename=fp)
            self.variant_combo.configure(state='readonly')
            if self.sd_variant == SteamDeckVariant.LCD:
                self.variant_var.set("LCD")
                self.variant_label.configure(text="(auto-detected)")
            elif self.sd_variant == SteamDeckVariant.OLED:
                self.variant_var.set("OLED")
                self.variant_label.configure(text="(auto-detected)")
            else:
                self.variant_var.set("Auto")
                self.variant_label.configure(text="(select variant)")
            if self.sd_variant != SteamDeckVariant.UNKNOWN:
                device_name = f"Steam Deck ({self.sd_variant.value.upper()})"
        else:
            self.variant_combo.configure(state='disabled')
            self.variant_var.set("Auto")
            self.variant_label.configure(text="")
        self.lbl_dev.configure(text=f"Device: {device_name}", style='Info.TLabel')
        self._log(f"Device: {device_name}", 'cyan')
        # Enable/disable 64GB option based on device support
        if self.device_profile and 64 in self.device_profile.get('memory_targets', []):
            self.target_radios[64].configure(state='normal')
        else:
            self.target_radios[64].configure(state='disabled')
            if self.target_var.get() == 64: self.target_var.set(32)
        # Enable screen patch dropdown only for Steam Deck LCD (not OLED)
        if self.detected_device == 'steam_deck' and self.sd_variant != SteamDeckVariant.OLED:
            self.screen_combo.configure(state='readonly')
        else:
            self.screen_var.set('None')
            self.screen_combo.configure(state='disabled')
        # Enable SPD timings dropdown on file load
        self.speed_combo.configure(state='readonly')
        self._log(f"Format: {'PE firmware (.fd)' if data[:2]==b'MZ' else 'Raw SPI dump'}", 'dim')
        self._log("Scanning...", 'dim')
        self.blocks = find_apcb_blocks(data)
        mc = sum(1 for b in self.blocks if b.is_memg); tc = sum(1 for b in self.blocks if b.content_type=='TOKN')
        self.lbl_bl.configure(text=f"APCB: {len(self.blocks)} blocks ({mc} MEMG, {tc} TOKN)")
        if mc == 0:
            self.lbl_cf.configure(text="No MEMG!", style='Bad.TLabel'); self._log("No APCB MEMG blocks found.", 'warning')
            self._populate_entries([])
            self.btn_mod.configure(state='disabled'); self.btn_ana.configure(state='normal')
            self.btn_dmi_export.configure(state='normal'); self.btn_dmi_import.configure(state='normal'); return
        # Populate entry checkboxes from first MEMG block
        first_memg = next((b for b in self.blocks if b.is_memg and b.spd_entries), None)
        self._populate_entries(first_memg.spd_entries if first_memg else [])
        self.current_config = detect_current_config(self.blocks)
        self.lbl_cf.configure(text=f"Config: {self.current_config}", style='Good.TLabel')
        self._log(f"Found {len(self.blocks)} blocks ({mc} MEMG, {tc} TOKN)", 'success')
        self._log(f"Config: {self.current_config}", 'cyan')
        for b in self.blocks:
            if b.is_memg and b.spd_entries:
                lp5 = sum(1 for e in b.spd_entries if e.mem_type == 'LPDDR5')
                lp5x = sum(1 for e in b.spd_entries if e.mem_type == 'LPDDR5X')
                ts = ', '.join(filter(None, [f"{lp5} LPDDR5" if lp5 else "", f"{lp5x} LPDDR5X" if lp5x else ""]))
                self._log(f"\nMEMG @ 0x{b.offset:08X} — {len(b.spd_entries)} SPD entries ({ts}), cksum {'VALID' if b.checksum_valid else 'INVALID'}", 'header')
                chip_count = _resolve_chip_count(self.device_profile, self.sd_variant)
                for i,e in enumerate(b.spd_entries):
                    if chip_count is not None:
                        den = _capacity_label(e.byte6, e.byte12, chip_count)
                    else:
                        den = density_from_bytes(e.byte6, e.byte12)
                    die_info = f"{e.die_count}x{e.die_density}" if e.die_count and e.die_density else '?'
                    self._log(f"  [{i+1}] {e.mem_type:<8} {e.module_name or '(unnamed)':<24} {den:<16}  "
                              f"{e.manufacturer or '?':<8}  {die_info:<8} {e.dev_width:<4} {e.ranks}R  "
                              f"tAA={e.tAA_ns}ns tRCD={e.tRCD_ns}ns", 'dim')
                break
        self.btn_mod.configure(state='normal'); self.btn_ana.configure(state='normal')
        self.btn_dmi_export.configure(state='normal'); self.btn_dmi_import.configure(state='normal')

    def _do_analyze(self):
        if not self.loaded_data: return
        self._log_clear()
        dev_name = self.device_profile['name'] if self.device_profile else 'Unknown Device'
        if self.detected_device == 'steam_deck' and self.sd_variant != SteamDeckVariant.UNKNOWN:
            dev_name = f"Steam Deck ({self.sd_variant.value.upper()})"
        self._log("═"*70, 'header'); self._log("  FULL BIOS ANALYSIS", 'header'); self._log("═"*70, 'header')
        self._log(f"  File: {os.path.basename(self.loaded_file)}", 'info')
        self._log(f"  Size: {len(self.loaded_data):,} bytes", 'info')
        self._log(f"  Device: {dev_name}", 'cyan')
        self._log(f"  Config: {self.current_config}", 'cyan')
        for i,block in enumerate(self.blocks):
            self._log(f"\n{'─'*60}", 'dim')
            self._log(f"  APCB Block {i+1}: {block.content_type}", 'header')
            self._log(f"  Offset: 0x{block.offset:08X}  |  Size: 0x{block.data_size:04X}  |  Checksum: 0x{block.checksum_byte:02X} ({'VALID' if block.checksum_valid else 'INVALID'})",
                      'success' if block.checksum_valid else 'error')
            if block.is_memg and block.spd_entries:
                chip_count = _resolve_chip_count(self.device_profile, self.sd_variant)
                self._log(f"\n  {'#':<4} {'Type':<8} {'Module':<24} {'Mfr':<9} {'Capacity':<16} "
                          f"{'Dies':<8} {'Width':<5} {'Ranks':<6} {'tAA':<8} {'tRCD':<8} {'tRP'}", 'accent')
                self._log(f"  {'─'*105}", 'dim')
                for j,e in enumerate(block.spd_entries):
                    if chip_count is not None:
                        cap = _capacity_label(e.byte6, e.byte12, chip_count)
                    else:
                        cap = density_from_bytes(e.byte6, e.byte12)
                    die_info = f"{e.die_count}x{e.die_density}" if e.die_count and e.die_density else '?'
                    tAA = f"{e.tAA_ns}ns" if e.tAA_ns else '?'
                    tRCD = f"{e.tRCD_ns}ns" if e.tRCD_ns else '?'
                    tRP = f"{e.tRPPB_ns}ns" if e.tRPPB_ns else '?'
                    self._log(f"  {j+1:<4} {e.mem_type:<8} {e.module_name or '—':<24} "
                              f"{e.manufacturer or '?':<9} {cap:<16} "
                              f"{die_info:<8} {e.dev_width:<5} {e.ranks}R    "
                              f"{tAA:<8} {tRCD:<8} {tRP}", 'info')

    def _do_modify(self):
        if not self.loaded_data or not self.loaded_file: return
        # Gather per-entry modifications from editor rows
        entry_mods = []
        for row in self.entry_rows:
            if not row['enabled_var'].get(): continue
            prefix_label = row['prefix_var'].get()
            prefix = MODULE_PREFIX_MAP.get(prefix_label, prefix_label)
            new_name = prefix + row['suffix_var'].get().strip()
            name_to_write = new_name if (row['has_name_field'] and new_name != row['original_name']) else None
            density_val = row['density_var'].get()
            if density_val == 'Custom':
                try:
                    custom_b6 = int(row['byte6_var'].get(), 16)
                    custom_b12 = int(row['byte12_var'].get(), 16)
                except (ValueError, TypeError):
                    messagebox.showerror("Invalid Hex", f"Entry [{row['index']+1}] has invalid density hex values."); return
                mod = {'index': row['index'], 'target_gb': None,
                       'custom_byte6': custom_b6, 'custom_byte12': custom_b12,
                       'new_name': name_to_write}
            else:
                target_gb = int(density_val.replace('GB', ''))
                mod = {'index': row['index'], 'target_gb': target_gb, 'new_name': name_to_write}
            # Collect timing byte modifications if any changed from original
            if 'tCK_var' in row:
                try:
                    timing_tCK = int(row['tCK_var'].get(), 16)
                    timing_tAA = int(row['tAA_var'].get(), 16)
                    timing_tRCD = int(row['tRCD_var'].get(), 16)
                    timing_tRPab = int(row['tRPab_var'].get(), 16)
                    timing_tRPpb = int(row['tRPpb_var'].get(), 16)
                except (ValueError, TypeError):
                    messagebox.showerror("Invalid Hex", f"Entry [{row['index']+1}] has invalid timing hex values."); return
                timing_changed = (
                    timing_tCK != row['original_tCK'] or
                    timing_tAA != row['original_tAA'] or
                    timing_tRCD != row['original_tRCD'] or
                    timing_tRPab != row['original_tRPab'] or
                    timing_tRPpb != row['original_tRPpb']
                )
                if timing_changed:
                    mod['timing'] = {
                        'tCK': timing_tCK, 'tAA': timing_tAA,
                        'tRCD': timing_tRCD, 'tRPab': timing_tRPab, 'tRPpb': timing_tRPpb
                    }
            entry_mods.append(mod)
        if not entry_mods:
            messagebox.showwarning("No Entries Selected", "Select at least one SPD entry to modify."); return
        # Determine output filename from most common target
        targets = [m['target_gb'] for m in entry_mods if m.get('target_gb') is not None]
        if targets:
            primary_target = max(set(targets), key=targets.count)
        else:
            primary_target = None
        sp = Path(self.loaded_file)
        if primary_target == 64: suffix = '_64GB'
        elif primary_target == 32: suffix = '_32GB'
        elif primary_target == 16: suffix = '_stock'
        else: suffix = '_custom'
        dn = f"{sp.stem}{suffix}.bin"  # Always output as .bin (SPI flash image)
        ftypes = [("BIN files", "*.bin"), ("All files", "*.*")]
        op = filedialog.asksaveasfilename(title="Save Modified BIOS As", initialfile=dn, initialdir=str(sp.parent),
            filetypes=ftypes)
        if not op: return
        if os.path.abspath(op) == os.path.abspath(self.loaded_file): messagebox.showerror("Error","Cannot overwrite input."); return
        self._log_clear()
        # Build summary of per-entry changes
        has_custom = any(m.get('target_gb') is None for m in entry_mods)
        unique_targets = sorted(set(targets))
        parts = [f"{t}GB" for t in unique_targets]
        if has_custom: parts.append('Custom')
        target_summary = ', '.join(parts) if parts else 'Custom'
        self._log("═"*70, 'header'); self._log(f"  MODIFYING SPD ENTRIES ({target_summary})", 'header'); self._log("═"*70, 'header')
        self._log(f"  Input:  {os.path.basename(self.loaded_file)}", 'info')
        self._log(f"  Output: {os.path.basename(op)}", 'info')
        self._log(f"  Entries: {len(entry_mods)} selected", 'accent')
        for mod in entry_mods:
            name_note = f" → '{mod['new_name']}'" if mod['new_name'] else ''
            density_note = f"{mod['target_gb']}GB" if mod.get('target_gb') else 'Custom'
            timing_note = ''
            if mod.get('timing'):
                t = mod['timing']
                tck_ns = t['tCK'] * SPD_MTB_PS / 1000
                mts = int(2000 / tck_ns) if tck_ns > 0 else 0
                timing_note = f" | SPD tCK: {mts} MT/s (0x{t['tCK']:02X})"
            self._log(f"    [{mod['index']+1}] → {density_note}{name_note}{timing_note}", 'dim')
        self._log(f"  Output: Flash via SPI programmer", 'dim')
        # Resolve screen selection to profile key
        screen_selection = self.screen_var.get()
        screen_key = None
        if screen_selection != 'None':
            for key, profile in SCREEN_PROFILES.items():
                if profile['name'] == screen_selection:
                    screen_key = key; break
        if screen_key:
            self._log(f"  Screen: {SCREEN_PROFILES[screen_key]['name']} patch enabled", 'cyan')
        try:
            data = bytearray(self.loaded_data)
            # Apply screen replacement patch if selected
            if screen_key:
                screen_name = SCREEN_PROFILES[screen_key]['name']
                self._log(f"\n  Applying {screen_name} screen patch...", 'accent')
                screen_patches = patch_screen(data, screen_key)
                if screen_patches:
                    for off, desc in screen_patches:
                        self._log(f"    0x{off:08X}: {desc}", 'dim')
                    self._log(f"  {screen_name}: {len(screen_patches)} patch(es) applied", 'success')
                else:
                    self._log(f"  {screen_name}: No patchable blocks found (may already be patched)", 'warning')
            mods = modify_bios_data(data, entry_mods, self.magic_var.get())
            self._log(f"\n  Byte changes: {len(mods)}", 'success')
            for off,old,new in mods: self._log(f"    0x{off:08X}: 0x{old:02X} → 0x{new:02X}", 'dim')
            od = bytes(data)
            with open(op,'wb') as f: f.write(od)
            self._log(f"\n  Verifying...", 'dim')
            vb = find_apcb_blocks(open(op,'rb').read()); ok = True
            # Build per-entry expected config lookup
            expected = {}
            for m in entry_mods:
                if m.get('custom_byte6') is not None:
                    expected[m['index']] = {'byte6': m['custom_byte6'], 'byte12': m['custom_byte12'], 'name': 'Custom'}
                else:
                    expected[m['index']] = MEMORY_CONFIGS[m['target_gb']]
            for b in vb:
                if b.is_memg:
                    if not b.checksum_valid: self._log(f"    FAIL: 0x{b.offset:08X}", 'error'); ok = False
                    elif b.spd_entries:
                        self._log(f"    0x{b.offset:08X}: cksum VALID", 'success')
                        for idx, ecfg in expected.items():
                            if idx < len(b.spd_entries):
                                e = b.spd_entries[idx]; m = e.byte6==ecfg['byte6'] and e.byte12==ecfg['byte12']
                                self._log(f"      [{idx+1}] b6=0x{e.byte6:02X} b12=0x{e.byte12:02X} → {ecfg['name']} [{'OK' if m else 'MISMATCH'}]", 'success' if m else 'error')
                                if not m: ok = False
            if ok:
                self._log(f"\n  ✓ MODIFICATION SUCCESSFUL", 'success')
                dev_name = self.device_profile['name'] if self.device_profile else 'device'
                flash_msg = "Flash via SPI programmer."
                self._log(f"  {flash_msg}", 'success')
                msg = f"Modified {len(entry_mods)} entries ({target_summary})!\n\nDevice: {dev_name}\n{op}\n\n{len(mods)} bytes changed."
                if screen_key: msg += f"\n{SCREEN_PROFILES[screen_key]['name']} screen patch applied."
                msg += f"\n\n{flash_msg}"
                messagebox.showinfo("Success", msg)
            else:
                self._log(f"\n  ✗ VERIFICATION FAILED", 'error'); messagebox.showerror("Failed","DO NOT flash this file.")
        except Exception as e:
            self._log(f"\n  ERROR: {e}", 'error'); messagebox.showerror("Error", str(e))
            import traceback; self._log(traceback.format_exc(), 'error')

    def _export_dmi(self):
        """Export DMI/SMBIOS data from loaded firmware to JSON file."""
        if not self.loaded_data: return
        try:
            dmi_data = export_dmi(self.loaded_data)
        except ValueError as e:
            self._log(f"DMI Export Error: {e}", 'error')
            messagebox.showerror("DMI Export Error", str(e)); return
        si = dmi_data.get('system_info', {})
        bi = dmi_data.get('board_info', {})
        # Ask for save location
        sp = Path(self.loaded_file)
        default_name = f"{sp.stem}_dmi.json"
        op = filedialog.asksaveasfilename(title="Save DMI Export",
            initialfile=default_name, initialdir=str(sp.parent),
            filetypes=[("JSON files","*.json"),("All files","*.*")])
        if not op: return
        import json
        with open(op, 'w') as f: json.dump(dmi_data, f, indent=2)
        self._log(f"\nDMI exported: {os.path.basename(op)}", 'success')
        self._log(f"  Store: {dmi_data['dmi_store_offset']} ({dmi_data['dmi_store_size']} bytes)", 'dim')
        self._log(f"  Records: {len(dmi_data['records'])}", 'dim')
        if si.get('serial_number'): self._log(f"  System Serial:  {si['serial_number']}", 'cyan')
        if bi.get('serial_number'): self._log(f"  Board Serial:   {bi['serial_number']}", 'cyan')
        self._log(f"  Store this file safely -- it contains your device identity.", 'dim')
        summary = f"Records: {len(dmi_data['records'])}"
        if si.get('serial_number'): summary += f"\nSystem Serial: {si['serial_number']}"
        if bi.get('serial_number'): summary += f"\nBoard Serial: {bi['serial_number']}"
        messagebox.showinfo("DMI Export", f"DMI data exported successfully.\n\n{summary}\n\nSaved to:\n{op}")

    def _import_dmi(self):
        """Import DMI/SMBIOS data from JSON into loaded firmware."""
        if not self.loaded_data or not self.loaded_file: return
        # Open DMI JSON
        json_path = filedialog.askopenfilename(title="Open DMI JSON File",
            filetypes=[("JSON files","*.json"),("All files","*.*")])
        if not json_path: return
        import json
        try:
            with open(json_path, 'r') as f: dmi_json = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read DMI JSON:\n{e}"); return
        # Show what we're importing and confirm
        si = dmi_json.get('system_info', {})
        details = f"Source: {os.path.basename(json_path)}"
        if si.get('serial_number'): details += f"\nSerial: {si['serial_number']}"
        if si.get('uuid'): details += f"\nUUID: {si['uuid']}"
        if not messagebox.askyesno("Confirm DMI Import",
                f"Import DMI data into firmware?\n\n{details}"): return
        # Ask for output path (never modify input)
        sp = Path(self.loaded_file)
        default_name = f"{sp.stem}_dmi_restored.bin"
        op = filedialog.asksaveasfilename(title="Save Firmware with DMI Restored",
            initialfile=default_name, initialdir=str(sp.parent),
            filetypes=[("BIN files","*.bin"),("BIOS Files","*.fd *.rom"),("All files","*.*")])
        if not op: return
        if os.path.abspath(op) == os.path.abspath(self.loaded_file):
            messagebox.showerror("Error", "Cannot overwrite input file."); return
        try:
            data = bytearray(self.loaded_data)
            patches = import_dmi(data, dmi_json)
            with open(op, 'wb') as f: f.write(bytes(data))
            self._log(f"\nDMI imported into: {os.path.basename(op)}", 'success')
            for off, desc in patches:
                self._log(f"  0x{off:08X}: {desc}", 'dim')
            self._log(f"  Flash this file to your device via SPI programmer.", 'success')
            self._log(f"  UEFI settings will recreate automatically on first boot.", 'dim')
            messagebox.showinfo("DMI Import", f"DMI data restored successfully.\n\nOutput: {op}\n\nFlash via SPI programmer.\nUEFI settings recreate on first boot.")
        except Exception as e:
            self._log(f"DMI import error: {e}", 'error')
            messagebox.showerror("DMI Import Error", str(e))

def main() -> None:
    root = tk.Tk()
    root.update_idletasks()
    # Get screen size in Tk's coordinate system
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    # Tk reports DPI-scaled values (e.g. 2560x1440 for 4K at 150%)
    # Target: ~60% physical screen width, ~80% physical height
    w = int(sw * 0.55)
    h = int(sh * 0.75)
    x = int(sw * 0.01)
    y = max(10, (sh - h) // 2 - 30)
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.minsize(700, 500)
    APCBToolGUI(root); root.mainloop()

if __name__ == '__main__':
    main()
