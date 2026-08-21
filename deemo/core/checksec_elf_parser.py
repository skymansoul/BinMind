"""
封装 ELF 文件头/程序头/动态段的二进制读取, 为上层硬化检测提供结构化数据。
纯 Python 实现以避免 pyelftools 依赖, 对 stripped 二进制优雅降级。
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
    """在指定偏移读取 ELF 结构化数据, 不移动文件指针。"""
    f.seek(offset)
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, f.read(size))


def _detect_elf_class(f) -> int:
    """读取 EI_CLASS 字节判断 32/64 位。"""
    f.seek(0)
    magic = f.read(5)
    if magic[:4] != ELFMAG:
        return 0
    return magic[4]


def _parse_elf_headers(path: str) -> Optional[Dict[str, Any]]:
    """解析 ELF 文件头与程序头, 返回 phdrs/动态段偏移/字符串表信息, 解析失败返回 None。"""
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
            # e_phoff/e_phentsize/e_phnum 在 32/64 位 ELF 头中的索引一致
            e_phoff = header[4]
            e_phentsize = header[8]
            e_phnum = header[9]

            phdrs = []
            for i in range(min(e_phnum, 64)):
                offset = e_phoff + i * e_phentsize
                phdr = _read_struct(f, offset, phdr_fmt)
                p_type = phdr[0]
                if is_64bit:
                    # ELF64 Phdr: type, flags, offset, vaddr, paddr, filesz, memsz, align
                    p_offset = phdr[2]
                    p_vaddr = phdr[3]
                    p_filesz = phdr[5]
                    p_flags = phdr[1]
                else:
                    # ELF32 Phdr: type, offset, vaddr, paddr, filesz, memsz, flags, align
                    p_offset = phdr[1]
                    p_vaddr = phdr[2]
                    p_filesz = phdr[4]
                    p_flags = phdr[6]

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
    """解析 .dynamic 段, 提取全部 tag-value 对; 从 PT_DYNAMIC 起遍历条目, 遇 DT_NULL 停止。"""
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
