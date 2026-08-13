"""UAF 基线载体解析辅助 — 分配来源回溯与全局桥接.

模块级函数, 由 UafBaseScanner 调用. 语义:
  - _prev_alloc: mov <reg>,rax 前 3 条内的 alloc 调用, 返回
    (函数名, call 行索引), 索引区分同函数多次分配实例.
  - _src_alloc_origin: 写入行源寄存器的分配来源, rax 直查 alloc
    call, 其他寄存器经 reg_sources 回调解析, 槽传递时递归.
  - _slot_alloc_origin: 槽最近写入的寄存器 → 分配来源.
  - _global_alloc_source: 全局槽 (rip 相对) 的 alloc 来源, 桥接
    free 的 ret:<alloc> 载体与 use 的 ripabs 载体.
  - _call_arg_sources: call 行参数寄存器 (rcx/rdx/r8) 来源身份与
    free 载体相交时返回命中集 (memcpy(dst,p,n) 型无解引用 use).
"""

import re as _re
from typing import Dict, List, Optional, Set, Tuple

from .gen_flow import slot_name

_ALLOC_FUNCS = ('malloc', 'calloc', 'realloc')


def prev_alloc(instructions: List[str], mov_idx: int,
               import_map=None):
    """mov <reg>,rax 前 3 条内的 alloc 调用 (位置敏感)."""
    for j in range(mov_idx - 1, max(0, mov_idx - 3) - 1, -1):
        line = instructions[j]
        if not line.strip().startswith('call'):
            continue
        m = _re.search(r'<([^>]+)>', line)
        if m:
            name = m.group(1).split('+')[0].split('@')[0].strip()
            if name in _ALLOC_FUNCS:
                return name, j
            continue
        if import_map:
            try:
                target = int(line.strip().split()[1], 16)
                name = import_map.get(target, '')
                if name in _ALLOC_FUNCS:
                    return name, j
            except (ValueError, IndexError):
                pass
    return None


def src_alloc_origin(reg_sources, instructions, write_idx, src_reg,
                     import_map=None):
    """写入行源寄存器的分配来源: rax 直查 / reg_sources 回调 / 槽递归."""
    if src_reg in ('rax', 'eax'):
        alloc = prev_alloc(instructions, write_idx, import_map)
        if alloc:
            return alloc
    srcs = reg_sources(instructions, write_idx, src_reg, import_map)
    for s in srcs:
        if s.startswith('ret:'):
            name, _, idx = s[4:].partition('@')
            return name, int(idx)
    for s in srcs:
        if s.startswith('rbp') or s.startswith('rsp'):
            alloc = slot_alloc_origin(reg_sources, instructions,
                                      write_idx, s, import_map)
            if alloc:
                return alloc
    return None


def slot_alloc_origin(reg_sources, instructions, at, slot,
                      import_map=None):
    """槽最近写入的寄存器 → 分配来源."""
    for i in range(at - 1, max(0, at - 60) - 1, -1):
        line = instructions[i].strip()
        m = _re.search(
            r'mov\s+QWORD PTR \[((?:rbp|rsp)[-+]0x[0-9a-f]+)\]\s*,\s*'
            r'([a-z0-9]+)', line, _re.I)
        if not m:
            continue
        if slot_name(f'[{m.group(1)}]') != slot:
            continue
        return src_alloc_origin(reg_sources, instructions, i,
                                m.group(2), import_map)
    return None


def global_alloc_source(reg_sources, instructions, at, glob_addr,
                        import_map=None):
    """全局槽 (rip 相对) 的 alloc 来源, 桥接 free/use 全局载体."""
    pat = _re.compile(
        r'mov\s+QWORD PTR \[rip\+0x[0-9a-f]+\]\s*,\s*([a-z0-9]+)'
        r'.*?#\s+(?:0x)?([0-9a-fA-F]{6,16})\b', _re.I)
    for i in range(max(0, at - 200), at):
        line = instructions[i]
        if 'mov' not in line or '[' not in line:
            continue
        m = pat.search(line)
        if not m:
            continue
        if m.group(2).lower() == glob_addr:
            alloc = src_alloc_origin(reg_sources, instructions, i,
                                     m.group(1), import_map)
            if alloc:
                return alloc
    return None


def call_arg_sources(reg_sources, instructions, at, fslots: set,
                     import_map=None) -> set:
    """call 行参数寄存器来源与 free 载体相交时返回命中集."""
    line = instructions[at].strip()
    if not line.startswith('call'):
        return set()
    hits = set()
    for reg in ('rcx', 'rdx', 'r8'):
        srcs = reg_sources(instructions, at, reg, import_map)
        inter = srcs & fslots
        if inter:
            hits |= inter
    return hits
