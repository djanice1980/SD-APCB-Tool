#!/usr/bin/env python3
"""
Steam Deck APCB Memory Mod Tool (GUI) v1.2.0
=============================================
GUI for analyzing and modifying Steam Deck LCD/OLED BIOS files
to support 16GB/32GB memory configurations.

Validated against known-good 32GB mods for both LCD (F7A) and OLED (F7G).
Supports both SPI flash output and signed h2offt-ready firmware.

Requirements:
  - Python 3.8+ (tkinter included with standard Python on Windows)
  - For h2offt signing: pip install cryptography

Usage: python sd_apcb_gui.py
"""

import os, sys, struct, hashlib, datetime
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

APP_TITLE = "Steam Deck APCB Memory Mod Tool"
APP_VERSION = "1.2.0"
APCB_MAGIC = b'APCB'
APCB_MAGIC_MOD = b'QPCB'
APCB_CHECKSUM_OFFSET = 16
MEMG_MAGIC = b'MEMG'
TOKN_MAGIC = b'TOKN'
LP5_SPD_MAGIC = bytes([0x23, 0x11, 0x13, 0x0E])
SPD_ENTRY_SEPARATOR = bytes([0x12, 0x34, 0x56, 0x78])
MEMORY_CONFIGS = {
    16: {'name': '16GB (Stock)', 'byte6': 0x95, 'byte12': 0x02},
    32: {'name': '32GB Upgrade', 'byte6': 0xB5, 'byte12': 0x0A},
}
MODULE_DENSITY_MAP = {
    'MT62F512M32D2DR': '16GB', 'MT62F768M32D2DR': '24GB',
    'MT62F1G64D4BS': '32GB', 'MT62F1G64D4AH': '32GB', 'MT62F1G32D4DR': '32GB',
    'MT62F2G64D8AJ': '32GB', 'MT62F2G64D8': '32GB',
    'K3KL3L30CM': '32GB', 'K3LKCKC0BM': '32GB',
}
MANUFACTURER_IDS = {0x2C: 'Micron', 0xCE: 'Samsung', 0xAD: 'SK Hynix', 0x01: 'Samsung'}

@dataclass
class SPDEntry:
    offset_in_apcb: int; offset_in_file: int; spd_bytes: bytes
    module_name: str = ''; manufacturer: str = ''; density_guess: str = ''
    byte6: int = 0; byte12: int = 0; config_id: int = 0; mfr_flag: int = 0

@dataclass
class APCBBlock:
    offset: int; data_size: int; total_size: int; checksum_byte: int
    checksum_valid: bool; content_type: str
    spd_entries: List[SPDEntry] = field(default_factory=list)
    @property
    def is_memg(self): return self.content_type == 'MEMG'

def calculate_apcb_checksum(block_data):
    total = 0
    for i, b in enumerate(block_data):
        if i == APCB_CHECKSUM_OFFSET: continue
        total = (total + b) & 0xFF
    return (0x100 - total) & 0xFF

def verify_apcb_checksum(block_data):
    return calculate_apcb_checksum(block_data) == block_data[APCB_CHECKSUM_OFFSET]

def find_apcb_blocks(data):
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
            cv = verify_apcb_checksum(data[idx:idx+ds]) if idx+ds <= len(data) else False
            block = APCBBlock(idx, ds, ts, cb, cv, ct)
            if ct == 'MEMG': block.spd_entries = parse_spd_entries(data, idx, ds)
            blocks.append(block)
            pos = idx + 1
    blocks.sort(key=lambda b: b.offset)
    return blocks

def parse_spd_entries(data, apcb_offset, apcb_size):
    entries, apcb, pos = [], data[apcb_offset:apcb_offset+apcb_size], 0
    while pos < len(apcb):
        idx = apcb.find(LP5_SPD_MAGIC, pos)
        if idx == -1 or idx+16 > len(apcb): break
        spd = apcb[idx:idx+16]
        e = SPDEntry(idx, apcb_offset+idx, spd, byte6=spd[6], byte12=spd[12])
        for j in range(idx, min(idx+0x200, len(apcb)-20)):
            if apcb[j:j+3] in [b'MT6', b'K3K', b'SEC', b'SAM']:
                end = j
                while end < min(j+30, len(apcb)) and 0x20 <= apcb[end] < 0x7F: end += 1
                e.module_name = apcb[j:end].decode('ascii', errors='replace').strip()
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
        entries.append(e); pos = idx + 1
    return entries

def detect_current_config(blocks):
    for b in blocks:
        if b.is_memg and b.spd_entries:
            e = b.spd_entries[0]
            if e.byte6 == 0xB5 and e.byte12 == 0x0A: return "32GB (modified)"
            elif e.byte6 == 0x95 and e.byte12 == 0x02: return "16GB/24GB (stock)"
            else: return f"Unknown (0x{e.byte6:02X}/0x{e.byte12:02X})"
    return "No MEMG blocks found"

def modify_bios_data(data, target_gb, modify_magic=False):
    config = MEMORY_CONFIGS[target_gb]
    blocks = find_apcb_blocks(bytes(data))
    mods = []
    for block in [b for b in blocks if b.is_memg]:
        if not block.spd_entries: continue
        e = block.spd_entries[0]
        b6, b12 = e.offset_in_file+6, e.offset_in_file+12
        mods.append((b6, data[b6], config['byte6'])); mods.append((b12, data[b12], config['byte12']))
        data[b6] = config['byte6']; data[b12] = config['byte12']
        if modify_magic:
            nb = 0x51 if target_gb == 32 else 0x41
            if data[block.offset] != nb: mods.append((block.offset, data[block.offset], nb)); data[block.offset] = nb
        bb = data[block.offset:block.offset+block.data_size]
        nc = calculate_apcb_checksum(bytes(bb)); oc = data[block.offset+APCB_CHECKSUM_OFFSET]
        if oc != nc: data[block.offset+APCB_CHECKSUM_OFFSET] = nc; mods.append((block.offset+APCB_CHECKSUM_OFFSET, oc, nc))
        if not verify_apcb_checksum(bytes(data[block.offset:block.offset+block.data_size])):
            raise RuntimeError(f"Checksum failed at 0x{block.offset:08X}")
    return mods

# ── PE Authenticode Signing Engine ──

def _check_signing_available():
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa; return True
    except ImportError: return False

def _dl(length):
    if length < 0x80: return bytes([length])
    elif length < 0x100: return bytes([0x81, length])
    elif length < 0x10000: return bytes([0x82, (length>>8)&0xFF, length&0xFF])
    elif length < 0x1000000: return bytes([0x83, (length>>16)&0xFF, (length>>8)&0xFF, length&0xFF])
    else: return bytes([0x84, (length>>24)&0xFF, (length>>16)&0xFF, (length>>8)&0xFF, length&0xFF])

def _dt(tag, c): return bytes([tag]) + _dl(len(c)) + c
def _ds(c): return _dt(0x30, c)
def _dset(c): return _dt(0x31, c)
def _dn(): return b'\x05\x00'
def _do(d): return _dt(0x04, d)
def _dc(t, c, con=True): return _dt((0xA0 if con else 0x80)|t, c)
def _dut(dt): return _dt(0x17, dt.strftime('%y%m%d%H%M%SZ').encode())

def _doid(s):
    p = [int(x) for x in s.split('.')]
    e = bytes([40*p[0]+p[1]])
    for v in p[2:]:
        if v < 0x80: e += bytes([v])
        elif v < 0x4000: e += bytes([(v>>7)|0x80, v&0x7F])
        elif v < 0x200000: e += bytes([(v>>14)|0x80, ((v>>7)&0x7F)|0x80, v&0x7F])
        else: e += bytes([(v>>21)|0x80, ((v>>14)&0x7F)|0x80, ((v>>7)&0x7F)|0x80, v&0x7F])
    return _dt(0x06, e)

def _dint(v):
    if isinstance(v, int):
        if v == 0: return _dt(0x02, b'\x00')
        r = []
        while v > 0: r.insert(0, v&0xFF); v >>= 8
        if r[0] & 0x80: r.insert(0, 0)
        return _dt(0x02, bytes(r))
    return _dt(0x02, v)

_P7='1.2.840.113549.1.7.2'; _SID='1.3.6.1.4.1.311.2.1.4'; _SPE='1.3.6.1.4.1.311.2.1.15'
_SOP='1.3.6.1.4.1.311.2.1.12'; _MIC='1.3.6.1.4.1.311.2.1.21'
_S256='2.16.840.1.101.3.4.2.1'; _RSA='1.2.840.113549.1.1.1'
_CT='1.2.840.113549.1.9.3'; _ST='1.2.840.113549.1.9.5'; _MD='1.2.840.113549.1.9.4'

def _pe_cksum(data):
    po = struct.unpack_from('<I', data, 0x3C)[0]; co = po+4+20+64
    c, r = 0, len(data)%4
    for i in range(0, len(data)-r, 4):
        if i == co: continue
        v = struct.unpack_from('<I', data, i)[0]; c = (c&0xFFFFFFFF)+v+(c>>32); c = (c&0xFFFF)+(c>>16)
    if r:
        v = int.from_bytes(data[-(r):]+b'\x00'*(4-r), 'little'); c = (c&0xFFFFFFFF)+v+(c>>32); c = (c&0xFFFF)+(c>>16)
    c = (c&0xFFFF)+(c>>16); return (c+len(data))&0xFFFFFFFF

def sign_firmware(data_in):
    from cryptography.hazmat.primitives import hashes as H
    from cryptography.hazmat.primitives.asymmetric import rsa as R, padding as P
    from cryptography.x509 import CertificateBuilder as CB, Name, NameAttribute, NameOID, random_serial_number
    from cryptography.hazmat.primitives.serialization import Encoding
    d = bytearray(data_in)
    if d[:2] != b'MZ': raise ValueError("Not PE")
    po = struct.unpack_from('<I', d, 0x3C)[0]; os_ = po+4+20
    m = struct.unpack_from('<H', d, os_)[0]; co = os_+64
    dd = os_+(112 if m == 0x20B else 96); so = dd+32
    ov = struct.unpack_from('<I', d, so)[0]
    if ov > 0 and ov < len(d): d = d[:ov]
    struct.pack_into('<I', d, so, 0); struct.pack_into('<I', d, so+4, 0); struct.pack_into('<I', d, co, 0)
    h = hashlib.sha256(); h.update(bytes(d[:co])); h.update(bytes(d[co+4:so])); h.update(bytes(d[so+8:])); ph = h.digest()
    k = R.generate_private_key(65537, 2048); now = datetime.datetime.now(datetime.timezone.utc)
    subj = Name([NameAttribute(NameOID.COMMON_NAME, "SD APCB Tool")])
    cert = CB().subject_name(subj).issuer_name(subj).public_key(k.public_key()).serial_number(random_serial_number()).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=3650)).sign(k, H.SHA256())
    cd = cert.public_bytes(Encoding.DER)
    # Build SPC
    sf = _dt(0x03, b'\x00\x00'); sl = _dc(0, b'\x00'*28, False); spd = _ds(sf+_dc(0, _dc(2, sl)))
    sa = _ds(_doid(_SPE)+spd); da = _ds(_doid(_S256)+_dn()); di = _ds(da+_do(ph))
    spc = _ds(sa+di)
    ci = _ds(_doid(_SID)+_dc(0, spc)); s256a = _ds(_doid(_S256)+_dn())
    # Auth attrs
    ac = _ds(_doid(_CT)+_dset(_doid(_SID))); at = _ds(_doid(_ST)+_dset(_dut(now)))
    ao = _ds(_doid(_SOP)+_dset(_ds(_doid(_MIC)))); ch = hashlib.sha256(spc).digest()
    am = _ds(_doid(_MD)+_dset(_do(ch))); aa = ac+at+ao+am
    sig = k.sign(_dset(aa), P.PKCS1v15(), H.SHA256())
    ias = _ds(cert.issuer.public_bytes()+_dint(cert.serial_number))
    ra = _ds(_doid(_RSA)+_dn())
    si = _ds(_dint(1)+ias+s256a+_dc(0,aa)+ra+_do(sig))
    sd = _ds(_dint(1)+_dset(s256a)+ci+_dc(0,cd)+_dset(si))
    p7 = _ds(_doid(_P7)+_dc(0, sd))
    wl = (8+len(p7)+7)&~7; wc = struct.pack('<IHH', wl, 0x0200, 0x0002)+p7+b'\x00'*(wl-8-len(p7))
    struct.pack_into('<I', d, so, len(d)); struct.pack_into('<I', d, so+4, wl)
    d.extend(wc); ck = _pe_cksum(bytes(d)); struct.pack_into('<I', d, co, ck)
    return bytes(d)

# ── GUI ──
C_BG='#1a1b26'; C_BGL='#24283b'; C_BGE='#1f2335'; C_FG='#c0caf5'; C_FGD='#565f89'; C_FGB='#e0e6ff'
C_ACC='#7aa2f7'; C_GRN='#9ece6a'; C_RED='#f7768e'; C_ORG='#ff9e64'; C_CYN='#7dcfff'; C_BDR='#3b4261'
C_BTN='#3d59a1'; C_BTH='#5177c9'

class APCBToolGUI:
    def __init__(self, root):
        self.root = root; root.title(APP_TITLE); root.geometry("820x720"); root.minsize(700,600); root.configure(bg=C_BG)
        self.loaded_file = None; self.loaded_data = None; self.blocks = []; self.current_config = ""
        self.signing_available = _check_signing_available()
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
        for w in ['TRadiobutton','TCheckbutton']:
            s.configure(w, background=C_BGL, foreground=C_FG, font=('Segoe UI',10), focuscolor=C_BGL, indicatorcolor=C_BGE)
            s.map(w, indicatorcolor=[('selected',C_ACC)], background=[('active',C_BGL)])

    def _build_ui(self):
        m = ttk.Frame(self.root, padding=16); m.pack(fill='both', expand=True)
        h = ttk.Frame(m); h.pack(fill='x', pady=(0,12))
        ttk.Label(h, text="⚡ SD Memory Mod Tool", style='Title.TLabel').pack(side='left')
        ttk.Label(h, text=f"v{APP_VERSION}", style='Subtitle.TLabel').pack(side='left', padx=(8,0), pady=(4,0))
        ff = ttk.Frame(m); ff.pack(fill='x', pady=(0,8))
        ttk.Button(ff, text="Open BIOS File", command=self._open_file).pack(side='left')
        self.file_label = ttk.Label(ff, text="No file loaded", style='Subtitle.TLabel'); self.file_label.pack(side='left', padx=(12,0))
        ic = tk.Frame(m, bg=C_BGL, padx=16, pady=12, highlightbackground=C_BDR, highlightthickness=1); ic.pack(fill='x', pady=(0,10))
        r1 = tk.Frame(ic, bg=C_BGL); r1.pack(fill='x')
        self.lbl_fn = ttk.Label(r1, text="—", style='Info.TLabel'); self.lbl_fn.pack(side='left')
        self.lbl_fs = ttk.Label(r1, text="", style='Status.TLabel'); self.lbl_fs.pack(side='right')
        r2 = tk.Frame(ic, bg=C_BGL); r2.pack(fill='x', pady=(4,0))
        self.lbl_bl = ttk.Label(r2, text="", style='Status.TLabel'); self.lbl_bl.pack(side='left')
        self.lbl_cf = ttk.Label(r2, text="", style='Status.TLabel'); self.lbl_cf.pack(side='right')
        ttk.Label(m, text="Target Configuration", style='Section.TLabel').pack(anchor='w', pady=(4,4))
        tc = tk.Frame(m, bg=C_BGL, padx=16, pady=12, highlightbackground=C_BDR, highlightthickness=1); tc.pack(fill='x', pady=(0,10))
        self.target_var = tk.IntVar(value=32)
        for val, txt, desc in [(32,"32GB Upgrade","Patches SPD for 32GB LPDDR5"),(16,"16GB Restore","Restores stock configuration")]:
            rf = tk.Frame(tc, bg=C_BGL); rf.pack(fill='x', pady=(0,4))
            ttk.Radiobutton(rf, text=txt, variable=self.target_var, value=val).pack(side='left')
            ttk.Label(rf, text=f"— {desc}", style='Status.TLabel').pack(side='left', padx=(8,0))
        of = tk.Frame(tc, bg=C_BGL); of.pack(fill='x', pady=(6,0))
        self.magic_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="Modify APCB magic byte (cosmetic, not required)", variable=self.magic_var).pack(side='left')
        sf = tk.Frame(tc, bg=C_BGL); sf.pack(fill='x', pady=(4,0))
        self.sign_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sf, text="Sign firmware for h2offt software flash (PE Authenticode)", variable=self.sign_var).pack(side='left')
        st = "✓ cryptography installed" if self.signing_available else "⚠ pip install cryptography"
        ttk.Label(sf, text=st, style='Status.TLabel').pack(side='left', padx=(12,0))
        if not self.signing_available: self.sign_var.set(False)
        br = ttk.Frame(m); br.pack(fill='x', pady=(0,8))
        self.btn_mod = ttk.Button(br, text="Apply Modification", style='Action.TButton', command=self._do_modify, state='disabled'); self.btn_mod.pack(side='left')
        self.btn_ana = ttk.Button(br, text="Analyze Only", command=self._do_analyze, state='disabled'); self.btn_ana.pack(side='left', padx=(8,0))
        ttk.Label(m, text="Log Output", style='Section.TLabel').pack(anchor='w', pady=(4,4))
        lf = tk.Frame(m, bg=C_BDR, padx=1, pady=1); lf.pack(fill='both', expand=True)
        self.log = scrolledtext.ScrolledText(lf, wrap='word', font=('Consolas',9), bg=C_BGE, fg=C_FG, insertbackground=C_FG,
            selectbackground=C_ACC, selectforeground=C_BG, relief='flat', borderwidth=0, padx=8, pady=8, state='disabled')
        self.log.pack(fill='both', expand=True)
        for t,c in [('info',C_FG),('success',C_GRN),('warning',C_ORG),('error',C_RED),('accent',C_ACC),('cyan',C_CYN),('dim',C_FGD)]:
            self.log.tag_configure(t, foreground=c)
        self.log.tag_configure('header', foreground=C_FGB, font=('Consolas',9,'bold'))
        ft = ttk.Frame(m); ft.pack(fill='x', pady=(6,0))
        ttk.Label(ft, text="⚠ Always back up your original BIOS before modifying.", style='Subtitle.TLabel').pack(side='left')

    def _log(self, text, tag='info'):
        self.log.configure(state='normal'); self.log.insert('end', text+'\n', tag); self.log.see('end'); self.log.configure(state='disabled')
    def _log_clear(self):
        self.log.configure(state='normal'); self.log.delete('1.0','end'); self.log.configure(state='disabled')

    def _open_file(self):
        fp = filedialog.askopenfilename(title="Open Steam Deck BIOS File", filetypes=[("BIOS Files","*.fd *.bin *.rom"),("All","*.*")])
        if not fp: return
        self._log_clear(); self._log(f"Loading: {fp}", 'accent')
        try:
            with open(fp,'rb') as f: data = f.read()
        except Exception as e: self._log(f"ERROR: {e}", 'error'); return
        self.loaded_file, self.loaded_data = fp, data
        fn, fs = os.path.basename(fp), len(data)
        self.file_label.configure(text=fn); self.lbl_fn.configure(text=fn)
        self.lbl_fs.configure(text=f"{fs:,} bytes ({fs/1024/1024:.2f} MB)")
        self._log(f"Format: {'PE firmware (.fd)' if data[:2]==b'MZ' else 'Raw SPI dump'}", 'dim')
        self._log("Scanning...", 'dim')
        self.blocks = find_apcb_blocks(data)
        mc = sum(1 for b in self.blocks if b.is_memg); tc = sum(1 for b in self.blocks if b.content_type=='TOKN')
        self.lbl_bl.configure(text=f"APCB: {len(self.blocks)} blocks ({mc} MEMG, {tc} TOKN)")
        if mc == 0:
            self.lbl_cf.configure(text="⚠ No MEMG!", style='Bad.TLabel'); self._log("No APCB MEMG blocks found.", 'warning')
            self.btn_mod.configure(state='disabled'); self.btn_ana.configure(state='normal'); return
        self.current_config = detect_current_config(self.blocks)
        self.lbl_cf.configure(text=f"Config: {self.current_config}", style='Warn.TLabel' if '32GB' in self.current_config else 'Good.TLabel')
        self._log(f"Found {len(self.blocks)} blocks ({mc} MEMG, {tc} TOKN)", 'success')
        self._log(f"Config: {self.current_config}", 'cyan')
        for b in self.blocks:
            if b.is_memg and b.spd_entries:
                self._log(f"\nMEMG @ 0x{b.offset:08X} — {len(b.spd_entries)} SPD entries, cksum {'VALID' if b.checksum_valid else 'INVALID'}", 'header')
                for i,e in enumerate(b.spd_entries):
                    mk = " ◄ 32GB" if e.byte6==0xB5 and e.byte12==0x0A else ""
                    self._log(f"  [{i+1}] {e.module_name or '(unnamed)':<28} {e.density_guess or '?':<6}  {e.manufacturer or '?':<8}  b6=0x{e.byte6:02X}  b12=0x{e.byte12:02X}{mk}", 'warning' if mk else 'dim')
                break
        self.btn_mod.configure(state='normal'); self.btn_ana.configure(state='normal')

    def _do_analyze(self):
        if not self.loaded_data: return
        self._log_clear()
        self._log("═"*70, 'header'); self._log("  FULL BIOS ANALYSIS", 'header'); self._log("═"*70, 'header')
        self._log(f"  File: {os.path.basename(self.loaded_file)}", 'info')
        self._log(f"  Size: {len(self.loaded_data):,} bytes", 'info')
        self._log(f"  Config: {self.current_config}", 'cyan')
        for i,block in enumerate(self.blocks):
            self._log(f"\n{'─'*60}", 'dim')
            self._log(f"  APCB Block {i+1}: {block.content_type}", 'header')
            self._log(f"  Offset: 0x{block.offset:08X}  |  Size: 0x{block.data_size:04X}  |  Checksum: 0x{block.checksum_byte:02X} ({'VALID' if block.checksum_valid else 'INVALID'})",
                      'success' if block.checksum_valid else 'error')
            if block.is_memg and block.spd_entries:
                self._log(f"\n  {'#':<4} {'Module':<28} {'Size':<7} {'Mfr':<10} {'b6':<6} {'b12':<6} {'cfg'}", 'accent')
                self._log(f"  {'─'*64}", 'dim')
                for j,e in enumerate(block.spd_entries):
                    mk = "  ◄◄ 32GB CONFIG" if e.byte6==0xB5 and e.byte12==0x0A else ""
                    self._log(f"  {j+1:<4} {e.module_name or '—':<28} {e.density_guess or '?':<7} {e.manufacturer or '?':<10} 0x{e.byte6:02X}   0x{e.byte12:02X}   0x{e.config_id:04X}{mk}",
                              'warning' if mk else 'info')

    def _do_modify(self):
        if not self.loaded_data or not self.loaded_file: return
        target = self.target_var.get(); config = MEMORY_CONFIGS[target]; do_sign = self.sign_var.get()
        if do_sign and not self.signing_available:
            messagebox.showwarning("Signing Unavailable", "Install: pip install cryptography\n\nContinuing unsigned."); do_sign = False
        if do_sign and self.loaded_data[:2] != b'MZ':
            messagebox.showinfo("Signing Skipped", "Raw SPI dump — signing not applicable."); do_sign = False
        sp = Path(self.loaded_file); dn = f"{sp.stem}{'_32GB' if target==32 else '_stock'}{sp.suffix}"
        op = filedialog.asksaveasfilename(title="Save Modified BIOS As", initialfile=dn, initialdir=str(sp.parent),
            filetypes=[("BIOS Files","*.fd *.bin *.rom"),("All","*.*")])
        if not op: return
        if os.path.abspath(op) == os.path.abspath(self.loaded_file): messagebox.showerror("Error","Cannot overwrite input."); return
        self._log_clear()
        self._log("═"*70, 'header'); self._log(f"  MODIFYING FOR {config['name'].upper()}", 'header'); self._log("═"*70, 'header')
        self._log(f"  Input:  {os.path.basename(self.loaded_file)}", 'info')
        self._log(f"  Output: {os.path.basename(op)}", 'info')
        self._log(f"  Target: {config['name']}", 'accent')
        self._log(f"  Signing: {'Yes (PE Authenticode)' if do_sign else 'No'}", 'dim')
        try:
            data = bytearray(self.loaded_data); mods = modify_bios_data(data, target, self.magic_var.get())
            self._log(f"\n  Byte changes: {len(mods)}", 'success')
            for off,old,new in mods: self._log(f"    0x{off:08X}: 0x{old:02X} → 0x{new:02X}", 'dim')
            od = bytes(data)
            if do_sign:
                self._log(f"\n  Signing...", 'accent')
                try: od = sign_firmware(bytes(data)); self._log(f"  Signed ✓ ({len(od):,} bytes)", 'success')
                except Exception as e: self._log(f"  Sign failed: {e}", 'error'); od = bytes(data); do_sign = False
            with open(op,'wb') as f: f.write(od)
            self._log(f"\n  Verifying...", 'dim')
            vb = find_apcb_blocks(open(op,'rb').read()); ok = True
            for b in vb:
                if b.is_memg:
                    if not b.checksum_valid: self._log(f"    FAIL: 0x{b.offset:08X}", 'error'); ok = False
                    elif b.spd_entries:
                        e = b.spd_entries[0]; m = e.byte6==config['byte6'] and e.byte12==config['byte12']
                        self._log(f"    0x{b.offset:08X}: cksum VALID, b6=0x{e.byte6:02X} b12=0x{e.byte12:02X} [{'OK' if m else 'MISMATCH'}]", 'success' if m else 'error')
                        if not m: ok = False
            if ok:
                self._log(f"\n  ✓ MODIFICATION SUCCESSFUL", 'success')
                if do_sign: self._log(f"  Ready for h2offt: sudo h2offt {os.path.basename(op)}", 'cyan')
                else: self._log(f"  Ready for SPI flash.", 'success')
                msg = f"Modified for {config['name']}!\n\n{op}\n\n{len(mods)} bytes changed.\n\n"
                msg += f"{'Signed for h2offt.' if do_sign else 'Ready for SPI flash.'}"
                messagebox.showinfo("Success", msg)
            else:
                self._log(f"\n  ✗ VERIFICATION FAILED", 'error'); messagebox.showerror("Failed","DO NOT flash this file.")
        except Exception as e:
            self._log(f"\n  ERROR: {e}", 'error'); messagebox.showerror("Error", str(e))
            import traceback; self._log(traceback.format_exc(), 'error')

def main():
    root = tk.Tk(); root.update_idletasks()
    w,h = 820,720; root.geometry(f"{w}x{h}+{(root.winfo_screenwidth()//2)-(w//2)}+{(root.winfo_screenheight()//2)-(h//2)}")
    APCBToolGUI(root); root.mainloop()

if __name__ == '__main__':
    main()
