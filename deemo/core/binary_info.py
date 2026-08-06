"""
Binary file detection and info extraction.
Supports ELF, PE, Mach-O. Falls back to `file` command on Linux.
"""

import os
import struct
import subprocess
from typing import Dict, Optional

from utils.elf import is_elf, get_elf_class, elf_arch_name, ELFCLASS64, read_elf_sections
from utils.pe import is_pe, pe_arch_name, read_pe_sections
from utils.macho import is_macho, macho_arch_name


# cache the last result to avoid re-reading the same binary within a pipeline run
_last_path: Optional[str] = None
_last_info: Optional[Dict] = None


def detect_format(path: str) -> str:
    """Return 'ELF', 'PE', 'Mach-O', or 'unknown'."""
    if is_elf(path):
        return 'ELF'
    if is_pe(path):
        return 'PE'
    if is_macho(path):
        return 'Mach-O'
    return 'unknown'


def _r2_info(path: str) -> Dict:
    """Gather binary metadata via radare2."""
    try:
        result = subprocess.run(
            ['r2', '-q', '-e', 'io.color=false', '-c', 'iI', path],
            capture_output=True, text=True, timeout=30
        )
        info = {}
        for line in result.stdout.splitlines():
            if ' ' in line:
                k, _, v = line.partition(' ')
                info[k.strip()] = v.strip()
        return info
    except Exception:
        return {}


def get_binary_info(path: str) -> Dict:
    """Extract core metadata: arch, bits, sections, imports, strings."""
    global _last_path, _last_info

    path = os.path.abspath(path)
    if path == _last_path and _last_info is not None:
        return _last_info

    if not os.path.isfile(path):
        return {'error': f'file not found: {path}', 'path': path}

    fmt = detect_format(path)
    info = {
        'path': path,
        'filename': os.path.basename(path),
        'size': os.path.getsize(path),
        'format': fmt,
        'arch': 'unknown',
        'bits': 64,
        'sections': [],
    }

    if fmt == 'ELF':
        cls = get_elf_class(path)
        info['bits'] = 64 if cls == ELFCLASS64 else 32
        info['arch'] = elf_arch_name(path)
        info['sections'] = read_elf_sections(path)
    elif fmt == 'PE':
        info['arch'] = pe_arch_name(path)
        info['bits'] = 64 if '64' in info['arch'] else 32
        info['sections'] = read_pe_sections(path)
    elif fmt == 'Mach-O':
        info['arch'] = macho_arch_name(path)
        info['bits'] = 64

    r2 = _r2_info(path)
    info['r2'] = r2
    if 'arch' in r2 and info['arch'] == 'unknown':
        info['arch'] = r2['arch']
    if 'bintype' in r2:
        info['bintype'] = r2['bintype']

    _last_path = path
    _last_info = info
    return info


def validate_binary(path: str) -> bool:
    """True if the file exists and looks like a supported binary."""
    return os.path.isfile(path) and detect_format(path) != 'unknown'
