"""
Mach-O binary probing. Lightweight; full parsing requires macholib.
"""

import struct
import os

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC   = 0xBEBAFECA


def is_macho(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
            return magic in (MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC,
                             0xFEEDFACE, 0xCEFAEDFE)
    except Exception:
        return False


def macho_arch_name(path: str) -> str:
    """Best-effort arch detection for Mach-O files."""
    try:
        with open(path, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
        if magic in (FAT_MAGIC, 0xBEBAFECA):
            return 'universal'
        if magic in (MH_MAGIC_64, MH_CIGAM_64):
            f.seek(4)
            cpu = struct.unpack('<I', f.read(4))[0]
            _map = {0x01000007: 'x86-64', 0x0100000C: 'ARM64'}
            return _map.get(cpu, f'unknown(0x{cpu:08X})')
        return 'unknown'
    except Exception:
        return 'unknown'
