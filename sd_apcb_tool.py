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
    # Samsung LPDDR5X
    'K3KL8L80CM':      '16GB',    # Samsung LPDDR5X — Ally X stock
    'K3KLALA0CM':      '64GB',    # Samsung LPDDR5X 64GB (16GB/pkg × 4)
    # SK Hynix LPDDR5X
    'H58G56BK7BX':     '16GB',    # SK Hynix LPDDR5X 16GB — Ally X stock
    'H58GE6AK8BX':     '32GB',    # SK Hynix LPDDR5X 32GB — Ally X
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

@dataclass
class SPDEntry:
    """A single SPD (Serial Presence Detect) entry within an APCB MEMG block."""
    offset_in_apcb: int          # Offset of SPD magic within the APCB block
    offset_in_file: int          # Absolute offset in the BIOS file
    spd_bytes: bytes             # The 16 SPD parameter bytes (magic + config)
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
      - MEMG at offset 0x80 → Steam Deck
      - PSPG at offset 0x80 + MEMG at offset 0xC0 → ROG Ally
      - PSPG at offset 0x80 + MEMG at offset 0xC8 → ROG Ally X

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
        spd_bytes = apcb[idx:idx+16]

        entry = SPDEntry(
            offset_in_apcb=idx,
            offset_in_file=apcb_offset + idx,
            spd_bytes=spd_bytes,
            byte6=spd_bytes[6],
            byte12=spd_bytes[12],
            mem_type=mem_type,
        )

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
        print(f"\n  {'─'*74}")
        print(f"  APCB Block {i+1}: {block.content_type}")
        print(f"  {'─'*74}")
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
            print(f"    {'─'*78}")
            print(f"    {'#':<3} {'Type':<8} {'Module':<27} {'Density':<8} {'Mfr':<10} {'b6':<5} {'b12':<5} {'cfg':<6}")
            print(f"    {'─'*78}")

            for j, entry in enumerate(block.spd_entries):
                # Highlight non-stock entries
                marker = ''
                if entry.byte6 == 0xB5 and entry.byte12 == 0x0A:
                    marker = ' ** 32GB **'
                elif entry.byte6 == 0xF5 and entry.byte12 == 0x49:
                    marker = ' ** 64GB **'

                print(f"    {j+1:<3} {entry.mem_type:<8} {entry.module_name:<27} {entry.density_guess:<8} "
                      f"{entry.manufacturer:<10} 0x{entry.byte6:02X}  0x{entry.byte12:02X}  "
                      f"0x{entry.config_id:04X}{marker}")

            # Show current active configuration
            first = block.spd_entries[0]
            if first.byte6 == 0x95 and first.byte12 == 0x02:
                config = "16GB/24GB (stock)"
            elif first.byte6 == 0xB5 and first.byte12 == 0x0A:
                config = "32GB (modified)"
            elif first.byte6 == 0xF5 and first.byte12 == 0x49:
                config = "64GB (modified)"
            else:
                config = f"Unknown (byte6=0x{first.byte6:02X}, byte12=0x{first.byte12:02X})"
            print(f"\n    First entry config: {config}")
    
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


def _build_spc_indirect_data(pe_hash):
    """Build the SPC_INDIRECT_DATA_CONTENT structure."""
    spc_flags = _der_tag(0x03, bytes([0x00, 0x00]))
    spc_link = _der_context(0, b'\x00' * 28, constructed=False)
    spc_file = _der_context(2, spc_link)
    spc_pe_data = _der_sequence(spc_flags + _der_context(0, spc_file))
    spc_attr = _der_sequence(_der_oid(_OID_SPC_PE_IMAGE_DATA) + spc_pe_data)
    digest_algo = _der_sequence(_der_oid(_OID_SHA256) + _der_null())
    digest_info = _der_sequence(digest_algo + _der_octet_string(pe_hash))
    return _der_sequence(spc_attr + digest_info)


def _build_auth_attrs(spc_content_der, signing_time):
    """Build authenticated attributes for signer info."""
    attr_ct = _der_sequence(
        _der_oid(_OID_CONTENT_TYPE) + _der_set(_der_oid(_OID_SPC_INDIRECT_DATA)))
    attr_st = _der_sequence(
        _der_oid(_OID_SIGNING_TIME) + _der_set(_der_utctime(signing_time)))
    attr_opus = _der_sequence(
        _der_oid(_OID_SPC_SP_OPUS_INFO) +
        _der_set(_der_sequence(_der_oid(_OID_MS_IND_CODE_SIGN))))
    content_hash = hashlib.sha256(spc_content_der).digest()
    attr_md = _der_sequence(
        _der_oid(_OID_MESSAGE_DIGEST) + _der_set(_der_octet_string(content_hash)))
    return attr_ct + attr_st + attr_opus + attr_md


def _build_pkcs7(pe_hash, cert_der, private_key, signing_time):
    """Build complete PKCS#7 SignedData for Authenticode."""
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography import x509 as _x509

    cert = _x509.load_der_x509_certificate(cert_der)
    serial = cert.serial_number
    issuer_der = cert.issuer.public_bytes()

    spc_content = _build_spc_indirect_data(pe_hash)
    content_info = _der_sequence(
        _der_oid(_OID_SPC_INDIRECT_DATA) + _der_context(0, spc_content))
    sha256_algo = _der_sequence(_der_oid(_OID_SHA256) + _der_null())
    digest_algos = _der_set(sha256_algo)
    certificates = _der_context(0, cert_der)

    auth_attrs_content = _build_auth_attrs(spc_content, signing_time)
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


def sign_firmware(data_in):
    """
    Sign a PE firmware file with a fresh self-signed certificate.
    
    Strips any existing Authenticode signature, generates a new self-signed
    RSA-2048/SHA-256 certificate, computes the PE Authenticode hash, builds
    a PKCS#7 SignedData structure, and writes a WIN_CERTIFICATE to the file.
    
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

    # Strip existing signature
    old_va = struct.unpack_from('<I', data, secdir_offset)[0]
    if old_va > 0 and old_va < len(data):
        data = data[:old_va]

    # Clear header fields for hash computation
    struct.pack_into('<I', data, secdir_offset, 0)
    struct.pack_into('<I', data, secdir_offset + 4, 0)
    struct.pack_into('<I', data, checksum_offset, 0)

    # Compute Authenticode hash (excluding checksum, secdir entry, cert table)
    h = hashlib.sha256()
    h.update(bytes(data[:checksum_offset]))
    h.update(bytes(data[checksum_offset + 4:secdir_offset]))
    h.update(bytes(data[secdir_offset + 8:]))
    pe_hash = h.digest()

    # Generate self-signed certificate
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

    # Build PKCS#7 SignedData
    pkcs7 = _build_pkcs7(pe_hash, cert_der, key, now)

    # Build WIN_CERTIFICATE (8-byte aligned)
    wc_len = (8 + len(pkcs7) + 7) & ~7
    win_cert = struct.pack('<IHH', wc_len, 0x0200, 0x0002) + pkcs7
    win_cert += b'\x00' * (wc_len - len(win_cert))

    # Update PE security directory
    cert_offset = len(data)
    struct.pack_into('<I', data, secdir_offset, cert_offset)
    struct.pack_into('<I', data, secdir_offset + 4, wc_len)

    # Append certificate
    data.extend(win_cert)

    # Compute and write PE checksum
    checksum = _compute_pe_checksum(bytes(data))
    struct.pack_into('<I', data, checksum_offset, checksum)

    return bytes(data)


# ============================================================================
# Modification Engine
# ============================================================================

def modify_bios(input_path: str, output_path: str, target_gb: int,
                modify_magic_byte: bool = False, entry_indices: Optional[List[int]] = None,
                sign_output: bool = False, device: str = 'auto'):
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
    print(f"\n  {'─'*74}")
    print(f"  MODIFICATION SUMMARY")
    print(f"  {'─'*74}")
    print(f"  Total byte changes: {len(modifications)}")
    print(f"  MEMG blocks modified: {len(memg_blocks)}")
    
    if modifications:
        print(f"\n  All modifications:")
        for offset, old, new in modifications:
            print(f"    0x{offset:08X}: 0x{old:02X} -> 0x{new:02X}")
    
    # Sign if requested
    output_data = bytes(data)
    
    if sign_output:
        print(f"\n  {'─'*74}")
        print(f"  PE AUTHENTICODE SIGNING")
        print(f"  {'─'*74}")
        
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
                print(f"  Signing complete ✓")
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

  Analyze with explicit device type:
    python sd_apcb_tool.py analyze my_bios.fd --device rog_ally

  Modify for 32GB (SPI flash ready, no signing):
    python sd_apcb_tool.py modify my_bios.fd my_bios_32gb.fd --target 32

  Modify for 64GB (ROG Ally X, requires LPDDR5X hardware):
    python sd_apcb_tool.py modify my_bios.bin my_bios_64gb.bin --target 64

  Modify for 32GB with signing (Steam Deck h2offt software flash):
    python sd_apcb_tool.py modify my_bios.fd my_bios_32gb.fd --target 32 --sign

  Restore to stock 16GB:
    python sd_apcb_tool.py modify my_bios_32gb.fd my_bios_stock.fd --target 16

Supported devices:
  Steam Deck (LCD & OLED): 16GB/32GB, SPI flash or h2offt (--sign)
  ROG Ally / Ally X: 16GB/32GB/64GB, SPI flash only (signing not supported)

  The --sign flag requires: pip install cryptography
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
    modify_parser.add_argument('--target', type=int, required=True, choices=[16, 32, 64],
                              help='Target memory size in GB')
    modify_parser.add_argument('--sign', action='store_true',
                              help='Re-sign firmware with PE Authenticode for h2offt software flash. '
                                   'Requires: pip install cryptography')
    modify_parser.add_argument('--magic', action='store_true',
                              help='Modify APCB magic byte[0] (0x41→0x51). Cosmetic marker only, '
                                   'not required for the mod. LCD known-good mods do NOT change this.')
    modify_parser.add_argument('--all-entries', action='store_true',
                              help='Modify ALL SPD entries (this is now the default behavior)')
    modify_parser.add_argument('--entry', type=int, action='append',
                              help='Specific entry index to modify (0-based, can repeat)')
    modify_parser.add_argument('--device', choices=['auto', 'steam_deck', 'rog_ally', 'rog_ally_x'],
                              default='auto', help='Device type (default: auto-detect)')
    
    args = parser.parse_args()
    
    if args.command == 'analyze':
        analyze_bios(args.bios_file, device=args.device)
        
    elif args.command == 'modify':
        if args.bios_in == args.bios_out:
            print("\n  ERROR: Input and output must be different files (safety measure)")
            sys.exit(1)
        
        entry_indices = None
        if args.all_entries:
            entry_indices = 'all'  # Signal to modify all entries
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
        )
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
