#!/usr/bin/env python3
"""
ASIP源码检测提取模块 — 分配点、上下文(guard/clamp/loop等)提取.
写入提取在 asip_source_writes 中.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from core.heap_overflow_detector import HeapAllocSite, HeapStore
from core.asip_source_regex import (
    _ALLOC_RE, _ALLOC_NESTED_RE, _SIZEOF_RE,
    _CLAMP_RE, _GUARD_RETURN_RE, _GUARD_COMPOUND_RE,
    _GUARD_NEG_POS_RE, _GUARD_RANGE_RE, _PATH_COND_RE,
    _LOOP_BOUND_RE, _REALLOC_RE, _CALL_RE,
    _try_int, _parse_size,
)


# 分配提取

def _extract_struct_sizes(lines: List[str]) -> Dict[str, int]:
    """从源码中提取struct定义并估算大小(4对齐)."""
    result = {}
    struct_re = re.compile(r'struct\s+(\w[\w]*)\s*\{([^}]+)\}', re.IGNORECASE)
    source = '\n'.join(lines)
    for m in struct_re.finditer(source):
        name = m.group(1)
        body = m.group(2)
        size = 0
        for field_line in body.split(';'):
            field_line = field_line.strip()
            if not field_line:
                continue
            arr_m = re.search(r'char\s+\w+\s*\[\s*(\d+)\s*\]', field_line)
            if arr_m:
                size += int(arr_m.group(1))
                continue
            if re.search(r'\b(int|long|unsigned)\b', field_line):
                size += 4
                continue
            if re.search(r'\bchar\b', field_line):
                size += 1
                continue
            if re.search(r'\b(void\s*\*|char\s*\*)', field_line):
                size += 8
                continue
            size += 4
        size = ((size + 3) // 4) * 4
        if size > 0:
            result[name] = size
    return result


def _parse_alloc_size(func: str, raw_args: str) -> Tuple[int, bool]:
    """解析分配大小, 返回(size, is_dynamic)."""
    if func == 'calloc':
        parts = [p.strip() for p in raw_args.split(',')]
        if len(parts) == 2:
            n = _try_int(parts[0])
            m = _try_int(parts[1])
            if n is not None and m is not None:
                return n * m, False
            if n is not None:
                return n, True
            if m is not None:
                return m, True
            return 0, True

    sizeof_add = re.match(r'sizeof\s*\(.+?\)\s*\+\s*(\d+)', raw_args)
    if sizeof_add:
        return 32 + int(sizeof_add.group(1)), False

    sizeof_m = _SIZEOF_RE.search(raw_args)
    if sizeof_m:
        return -1, False

    mul_m = re.match(r'(\w[\w]*)\s*\*\s*(\d+)', raw_args)
    if mul_m:
        factor = int(mul_m.group(2))
        return -factor, True

    add_m = re.match(r'(\w[\w]*)\s*\+\s*(\d+)', raw_args)
    if add_m:
        return 0, True

    val = _try_int(raw_args)
    if val is not None:
        return val, False
    return 0, True


def _extract_allocs(lines: List[str]) -> List[HeapAllocSite]:
    """提取分配点, 含sizeof结构体大小推断."""
    struct_sizes = _extract_struct_sizes(lines)
    allocs = []
    for i, line in enumerate(lines):
        m = _ALLOC_NESTED_RE.search(line) or _ALLOC_RE.search(line)
        if not m:
            continue
        result_var = m.group(1) or ''
        func = m.group(2).lower()
        raw_args = m.group(3).strip()
        if raw_args.endswith(')'):
            if raw_args.count(')') > raw_args.count('('):
                raw_args = raw_args[:-1].strip()
        size, is_dynamic = _parse_alloc_size(func, raw_args)

        if size == -1:
            sizeof_m = _SIZEOF_RE.search(raw_args)
            if sizeof_m and sizeof_m.group(1) in struct_sizes:
                size = struct_sizes[sizeof_m.group(1)]
            else:
                size = 0
                is_dynamic = True

        sizeof_add = re.match(r'sizeof\s*\(.+?\)\s*\+\s*(\d+)', raw_args)
        if sizeof_add and size == -1:
            size = struct_sizes.get('default', 32) + int(sizeof_add.group(1))

        allocs.append(HeapAllocSite(
            pc=i, alloc_func=func, size_arg=size,
            size_is_dynamic=is_dynamic, result_var=result_var,
        ))
    return allocs


# 上下文提取

def _extract_guard_limits(lines: List[str]) -> Dict[str, int]:
    """提取guard上界: if(n>X) return → {n: X}."""
    result = {}
    for line in lines:
        m = _GUARD_RETURN_RE.search(line)
        if m:
            result[m.group(1)] = int(m.group(2))
        m_lower = re.search(
            r'if\s*\(\s*(\w[\w]*)\s*<\s*(\d+)\s*\)\s*(?:return|exit)', line)
        if m_lower:
            result.setdefault(m_lower.group(1) + '_lower', 0)
            result[m_lower.group(1) + '_has_guard'] = 1
        m = _GUARD_COMPOUND_RE.search(line)
        if m:
            result['_compound'] = int(m.group(1))
        m = _GUARD_NEG_POS_RE.search(line)
        if m:
            result[m.group(1)] = int(m.group(2))
    return result


def _extract_clamp_limits(lines: List[str]) -> Dict[str, int]:
    result = {}
    for m in _CLAMP_RE.finditer('\n'.join(lines)):
        result[m.group(1)] = int(m.group(2))
    return result


def _extract_loop_bounds(lines: List[str]) -> Dict[str, int]:
    result = {}
    for m in _LOOP_BOUND_RE.finditer('\n'.join(lines)):
        result['_loop_'] = int(m.group(1))
    return result


def _extract_reallocs(lines: List[str]) -> Dict[str, int]:
    result = {}
    for m in _REALLOC_RE.finditer('\n'.join(lines)):
        try:
            result[m.group(1)] = int(m.group(2), 0)
        except ValueError:
            pass
    return result


def _extract_alloc_size_var(lines: List[str]) -> Dict[str, str]:
    """从malloc语句中提取: size_var → alloc_var."""
    result = {}
    for line in lines:
        m = _ALLOC_RE.search(line)
        if m and m.group(1):
            raw_args = m.group(3).strip()
            simple_var = re.match(r'^(\w[\w]*)$', raw_args)
            if simple_var:
                result[simple_var.group(1)] = m.group(1)
    return result


def _extract_modulo_protections(lines: List[str]) -> Dict[str, int]:
    result = {}
    mod_re = re.compile(r'(\w[\w]*)\s*\[\s*\w[\w]*\s*%\s*(\d+)\s*\]')
    for m in mod_re.finditer('\n'.join(lines)):
        result[m.group(1)] = int(m.group(2))
    return result


def _extract_path_conditions(lines: List[str]) -> List[Dict[str, int]]:
    """提取if(n>0&&n<=X)路径条件."""
    result = []
    for line in lines:
        m = _PATH_COND_RE.search(line)
        if m:
            result.append({'upper': int(m.group(1))})
        m = _GUARD_RANGE_RE.search(line)
        if m:
            result.append({'upper': int(m.group(1))})
    return result


def _extract_cross_function_writes(
    lines: List[str],
) -> Dict[str, List[Tuple[HeapStore, Optional[int]]]]:
    result = {}
    for i, line in enumerate(lines):
        m = _CALL_RE.search(line)
        if not m:
            continue
        ptr_var = m.group(2)
        size_str = m.group(3)
        if not size_str:
            continue
        size = _parse_size(size_str)
        if size is not None and size > 0:
            if ptr_var not in result:
                result[ptr_var] = []
            result[ptr_var].append((HeapStore(
                pc=i, base_var=ptr_var, offset=0,
                offset_is_dynamic=False,
                store_size=size, mnemonic='memcpy',
            ), size))
    return result


__all__ = [
    '_extract_struct_sizes', '_parse_alloc_size', '_extract_allocs',
    '_extract_guard_limits', '_extract_clamp_limits',
    '_extract_loop_bounds', '_extract_reallocs', '_extract_alloc_size_var',
    '_extract_modulo_protections', '_extract_path_conditions',
    '_extract_cross_function_writes',
]
