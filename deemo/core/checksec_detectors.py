"""
Per-format hardening detection logic.

ELF/PE/Mach-O 三种格式的硬化机制检测实现，各自独立以隔离解析依赖。
"""


import struct
from typing import Any, Dict

from .checksec_constants import (
    CANARY_SYMBOLS,
    DF_1_NOW,
    DF_BIND_NOW,
    DT_FLAGS,
    PF_R,
    PF_W,
    PF_X,
    PT_GNU_RELRO,
    PT_GNU_STACK,
    _log,
)
from .checksec_elf_parser import (
    _parse_dynamic_section,
    _parse_elf_headers,
    _read_struct,
)


def _detect_canary_from_imports(path: str) -> bool:
    """
    Detect canary by scanning ELF import symbol table.

    Fallback when pyelftools is not available: searches for symbol name strings directly.
    """
    try:
        # Quick detection via r2
        import subprocess
        proc = subprocess.run(
            ['radare2', '-q', '-e', 'io.color=false', '-c', 'is~__stack_chk', path],
            capture_output=True, text=True, timeout=15,
        )
        return bool(proc.stdout.strip())
    except Exception:
        pass

    # Pure-Python fallback: search for canary symbols in .dynstr
    try:
        with open(path, 'rb') as f:
            content = f.read()
        for sym in CANARY_SYMBOLS:
            if sym.encode() in content:
                return True
    except OSError:
        pass
    return False


def _detect_elf_checksec(path: str, result: Dict[str, Any]) -> None:
    """Detect ELF binary hardening mechanisms."""
    headers = _parse_elf_headers(path)
    if headers is None:
        return

    phdrs = headers['phdrs']
    is_64bit = headers['is_64bit']

    # NX (based on PF_X flag in PT_GNU_STACK)
    for phdr in phdrs:
        if phdr['type'] == PT_GNU_STACK:
            result['nx'] = not bool(phdr['flags'] & PF_X)
            break

    # PIE (ET_DYN vs ET_EXEC)
    try:
        with open(path, 'rb') as f:
            if is_64bit:
                e_type = _read_struct(f, 16, '<H')[0]
            else:
                e_type = _read_struct(f, 16, '<H')[0]
        # ET_DYN=3 (shared object, PIE-enabled); ET_EXEC=2 (fixed address)
        result['pie'] = e_type == 3
    except (OSError, struct.error):
        pass

    # Canary
    result['canary'] = _detect_canary_from_imports(path)

    # RELRO (PT_GNU_RELRO + DT_FLAGS/DT_FLAGS_1)
    dynamic = _parse_dynamic_section(
        path, phdrs,
        headers['dyn_entry_fmt'],
        headers['dyn_entry_size'],
    )

    has_relro_segment = any(phdr['type'] == PT_GNU_RELRO for phdr in phdrs)

    if has_relro_segment:
        result['relro'] = 'partial'
        # BIND_NOW signals Full RELRO
        if dynamic.get(DF_1_NOW, 0) & 1:
            result['relro'] = 'full'
        elif dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW:
            result['relro'] = 'full'

    # FORTIFY_SOURCE（导入 __*_chk 函数）
    try:
        with open(path, 'rb') as f:
            raw = f.read(1048576)  # first 1MB
        fortify_markers = [b'__memcpy_chk', b'__sprintf_chk', b'__strcpy_chk',
                           b'__fprintf_chk', b'__snprintf_chk']
        result['fortify'] = any(m in raw for m in fortify_markers)
    except OSError:
        pass

    # RWX 段检测
    rwx_mask = PF_R | PF_W | PF_X
    result['rwx_segments'] = any(
        (phdr['flags'] & rwx_mask) == rwx_mask for phdr in phdrs
    )

    # ASLR（PIE 是必要条件）
    result['aslr'] = result['pie']


def _detect_pe_checksec(path: str, result: Dict[str, Any]) -> None:
    """Detect PE binary hardening mechanisms."""
    try:
        import pefile
        pe = pefile.PE(path)

        # NX: IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x100)
        result['nx'] = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100)

        # PIE: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x40)
        result['pie'] = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)

        # Canary/GS: LOAD_CONFIG 存在即判定
        result['canary'] = hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG')

        result['aslr'] = result['pie']
        result['relro'] = 'none'  # PE 无 RELRO 概念
    except ImportError:
        _log.debug("pefile not installed, PE checksec limited to magic detection")
    except Exception as e:
        _log.debug("PE checksec parse error: %s", e)


def _detect_macho_checksec(path: str, result: Dict[str, Any]) -> None:
    """Detect Mach-O binary hardening mechanisms (simplified)."""
    try:
        import macholib.MachO
        macho = macholib.MachO.MachO(path)

        # PIE: MH_PIE (0x200000)
        result['pie'] = bool(macho.headers[0].flags & 0x200000)

        # NX: MH_ALLOW_STACK_EXEC 逆
        flags = macho.headers[0].flags
        result['nx'] = not bool(flags & 0x20000)

        result['aslr'] = result['pie']
        result['relro'] = 'none'
    except ImportError:
        _log.debug("macholib not installed, Mach-O checksec unavailable")
    except Exception as e:
        _log.debug("Mach-O checksec parse error: %s", e)
