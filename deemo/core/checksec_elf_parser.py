"""
ELF low-level parsing primitives.

封装 ELF 文件头/程序头/动态段的二进制读取，为上层硬化检测提供结构化数据。
纯 Python 实现以避免 pyelftools 依赖，对 stripped binary 优雅降级。
"""


import struct
from typing import Any, Dict, List, Optional, Tuple

from .checksec_constants import (
    ELFMAG,
    ELFCLASS64,
    DT_NULL,
    _log,
)


def _read_struct(f, offset: int, fmt: str) -> Tuple:
    """Read structured data from ELF at the given offset without moving the file pointer."""
    f.seek(offset)
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, f.read(size))


def _detect_elf_class(f) -> int:
    """Read the EI_CLASS byte to determine 32- vs 64-bit."""
    f.seek(0)
    magic = f.read(5)
    if magic[:4] != ELFMAG:
        return 0
    return magic[4]


def _parse_elf_headers(path: str) -> Optional[Dict[str, Any]]:
    """
    Parse ELF file header and Program Headers.

    Returns a dict with phdrs, dynamic section offsets, and string table info,
    or None on parse failure.
    """
    try:
        with open(path, 'rb') as f:
            elf_class = _detect_elf_class(f)
            if elf_class == 0:
                return None

            is_64bit = elf_class == ELFCLASS64

            if is_64bit:
                elf_header_fmt = '<HHIQQQIHHHHHH'
                phdr_fmt = '<IIQQQQQQ'
                phdr_size = 56
                dyn_entry_fmt = '<QQ'
                dyn_entry_size = 16
            else:
                elf_header_fmt = '<HHIIIIIHHHHHH'
                phdr_fmt = '<IIIIIIII'
                phdr_size = 32
                dyn_entry_fmt = '<II'
                dyn_entry_size = 8

            header = _read_struct(f, 0, elf_header_fmt)
            e_phoff = header[is_64bit and 4 or 4]
            e_phentsize = header[is_64bit and 8 or 8]
            e_phnum = header[is_64bit and 9 or 9]

            phdrs = []
            for i in range(min(e_phnum, 64)):
                offset = e_phoff + i * e_phentsize
                phdr = _read_struct(f, offset, phdr_fmt)
                p_type = phdr[0]
                p_vaddr = phdr[is_64bit and 2 or 2]
                p_flags = phdr[is_64bit and 1 or 3]

                if is_64bit:
                    p_offset, p_filesz = phdr[1], phdr[3]
                else:
                    p_offset, p_filesz = phdr[1], phdr[4]

                phdrs.append({
                    'type': p_type,
                    'flags': p_flags,
                    'vaddr': p_vaddr,
                    'offset': p_offset,
                    'filesz': p_filesz,
                })

            return {
                'is_64bit': is_64bit,
                'phdrs': phdrs,
                'dyn_entry_fmt': dyn_entry_fmt,
                'dyn_entry_size': dyn_entry_size,
            }
    except (OSError, struct.error) as e:
        _log.debug("ELF header parse failed for %s: %s", path, e)
        return None


def _parse_dynamic_section(
    path: str,
    phdrs: List[Dict],
    dyn_entry_fmt: str,
    dyn_entry_size: int,
) -> Dict[int, int]:
    """
    Parse the .dynamic section, extracting all tag-value pairs.

    Iterates entries from PT_DYNAMIC, stopping at DT_NULL.
    """
    dynamic: Dict[int, int] = {}
    for phdr in phdrs:
        if phdr['type'] == 2:  # PT_DYNAMIC
            try:
                with open(path, 'rb') as f:
                    offset = phdr['offset']
                    f.seek(offset)
                    while True:
                        raw = f.read(dyn_entry_size)
                        if len(raw) < dyn_entry_size:
                            break
                        tag, val = struct.unpack(dyn_entry_fmt, raw)
                        if tag == DT_NULL:
                            break
                        dynamic[tag] = val
            except OSError:
                pass
            break
    return dynamic
