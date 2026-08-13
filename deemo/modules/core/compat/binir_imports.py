# -*- coding: utf-8 -*-
"""导入表 / PLT / 初始化数据指针解析 — stripped 二进制的调用名恢复."""

import os, re, subprocess
from typing import Dict, List, Optional, Tuple

from modules.core.compat.binir_common import norm_name

_IMPORT_CACHE: Dict[str, Dict[int, str]] = {}

_IMPORT_LINE = re.compile(
    r'^\s*([0-9a-f]+)\s+<none>\s+[0-9a-f]+\s+(\w+)', re.I)
_IMAGE_BASE = re.compile(r'^ImageBase\s+([0-9a-fA-F]+)\s*$', re.I)
_THUNK_JMP = re.compile(
    r'^\s*([0-9a-f]+):.*jmp\s+QWORD PTR \[rip[^\]]+\]\s*#\s*(0x[0-9a-fA-F]+)', re.I)
_SECTION_HEAD = re.compile(
    r'^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)', re.I)


def parse_imports(elf_path: str, objdump_bin: str = 'objdump') -> Dict[int, str]:
    """解析 PE 导入表 / ELF PLT, 返回 {thunk_addr: 函数名}."""
    key = os.path.abspath(elf_path)
    if key in _IMPORT_CACHE:
        return _IMPORT_CACHE[key]
    thunk_map: Dict[int, str] = {}
    try:
        p = subprocess.run([objdump_bin, '-p', elf_path],
                           capture_output=True, text=True, timeout=30)
        p_out = p.stdout if p.returncode == 0 else ''
    except Exception:
        p_out = ''

    if 'file format pei' in p_out:
        base = 0
        for line in p_out.splitlines():
            m = _IMAGE_BASE.match(line.strip())
            if m:
                base = int(m.group(1), 16)
                break
        iat: Dict[int, str] = {}
        for line in p_out.splitlines():
            m = _IMPORT_LINE.match(line.strip())
            if m:
                rva = int(m.group(1), 16)
                iat[base + rva] = norm_name(m.group(2))
        for line in _disasm_text(elf_path).splitlines():
            m = _THUNK_JMP.match(line.strip())
            if m and int(m.group(2), 16) in iat:
                thunk_map[int(m.group(1), 16)] = iat[int(m.group(2), 16)]
        thunk_map.update(_resolve_data_pointers(elf_path, thunk_map))
    else:
        got_map: Dict[int, str] = {}
        if p_out:
            for line in p_out.splitlines():
                m = re.search(r'\b([0-9a-f]+)\s+R_X86_64_JUMP_SLOT\s+(\S+)', line)
                if m:
                    got_map[int(m.group(1), 16)] = norm_name(m.group(2))
        for line in _disasm_text(elf_path).splitlines():
            m = re.search(
                r'^\s*([0-9a-f]+):.*jmp\s+\*?(0x[0-9a-fA-F]+)\b', line)
            if m and int(m.group(2), 16) in got_map:
                thunk_map[int(m.group(1), 16)] = got_map[int(m.group(2), 16)]
        thunk_map.update(_resolve_data_pointers(elf_path, thunk_map))
    _IMPORT_CACHE[key] = thunk_map
    return thunk_map


def _resolve_data_pointers(elf_path: str, thunk_map: Dict[int, str],
                           objdump_bin: str = 'objdump') -> Dict[int, str]:
    """扫描初始化数据节, 将装载导入指针的数据槽地址映射到函数名."""
    try:
        h = subprocess.run([objdump_bin, '-h', elf_path],
                           capture_output=True, text=True, timeout=30)
        h_out = h.stdout if h.returncode == 0 else ''
    except Exception:
        return {}
    sections: List[Tuple[int, int, int]] = []
    for line in h_out.splitlines():
        m = _SECTION_HEAD.match(line.strip())
        if m:
            name, size_s, vma_s, off_s = m.groups()
            sections.append((int(vma_s, 16), int(size_s, 16),
                             int(off_s, 16)))
    if not sections:
        return {}
    try:
        with open(elf_path, 'rb') as f:
            raw = f.read()
    except OSError:
        return {}
    inv_thunk = {v: k for k, v in thunk_map.items()}
    result: Dict[int, str] = {}
    try:
        for vma, size, off in sections:
            for slot in range(vma, vma + size - 7, 8):
                filepos = off + (slot - vma)
                ptr = int.from_bytes(raw[filepos:filepos + 8], 'little')
                if ptr in inv_thunk:
                    result[slot] = inv_thunk[ptr]
    except (ValueError, IndexError):
        pass
    return result


def _disasm_text(elf_path: str, objdump_bin: str = 'objdump') -> str:
    try:
        r = subprocess.run([objdump_bin, '-d', '-M', 'intel', elf_path],
                           capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else ''
    except Exception:
        return ''


# 逐函数寄存器/栈槽级数据流 — 构建 ir_ops 与 def-use 链.

import re
from typing import Any, Dict, List, Optional
