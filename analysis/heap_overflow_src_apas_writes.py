"""
堆溢出源级验证 — APAS 别名写入检测器.

find_writes 只匹配 alloc_vars 中的直接写入, 本模块补充
通过 alias→alias→...→root 链路间接进行的写入.
"""
import re
from typing import Dict, List, Set

from analysis.heap_overflow_types import HeapWriteSite
from analysis.heap_overflow_src_patterns import (
    _MEMCPY_HEAP_RE, _MEMSET_HEAP_RE, _STRCPY_HEAP_RE,
    _STRCAT_HEAP_RE, _READ_HEAP_RE, _PTR_WRITE_RE,
    _PTR_VAR_OFFSET_RE, _STRUCT_ARRAY_WRITE_RE,
    _is_comment_or_empty, _base_var, parse_alloc_size)


def find_alias_writes(lines: List[str], alias_map: Dict[str, str],
                      alloc_vars: Set[str],
                      valid: set = None) -> List[HeapWriteSite]:
    """APAS: 检测通过别名变量进行的写入 (find_writes无法捕获)."""
    all_aliases = set(alias_map.keys()) - alloc_vars
    if not all_aliases:
        return []
    writes = []
    for i, line in enumerate(lines, start=1):
        if valid and i not in valid:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        for m in _MEMCPY_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst in all_aliases:
                ws = parse_alloc_size(m.group(3).strip(), lines, i)
                writes.append(HeapWriteSite(
                    line=i, target=dst, kind='memcpy', write_size=ws))
        for m in _MEMSET_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst in all_aliases:
                ws = parse_alloc_size(m.group(2).strip(), lines, i)
                writes.append(HeapWriteSite(
                    line=i, target=dst, kind='memset', write_size=ws))
        for m in _STRCPY_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst in all_aliases:
                writes.append(HeapWriteSite(
                    line=i, target=dst, kind='strcpy', write_size=-1))
        for m in _STRCAT_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst in all_aliases:
                writes.append(HeapWriteSite(
                    line=i, target=dst, kind='strcat', write_size=-1))
        for m in _READ_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst in all_aliases:
                ws = parse_alloc_size(m.group(2).strip(), lines, i)
                writes.append(HeapWriteSite(
                    line=i, target=dst, kind='read', write_size=ws))
        for m in _PTR_WRITE_RE.finditer(text):
            ptr = m.group(1) or m.group(3)
            offset = int(m.group(2) or m.group(4) or 0)
            ptr_base = _base_var(ptr.strip()) if ptr else ""
            if ptr_base in all_aliases:
                writes.append(HeapWriteSite(
                    line=i, target=ptr_base, kind='ptr_write',
                    write_size=8, offset=offset))
        for m in _PTR_VAR_OFFSET_RE.finditer(text):
            ptr = m.group(1)
            var_off = m.group(2)
            ptr_base = _base_var(ptr.strip()) if ptr else ""
            if ptr_base in all_aliases:
                writes.append(HeapWriteSite(
                    line=i, target=ptr_base, kind='ptr_write',
                    write_size=8, offset=-1, src_var=var_off))
        sa = _STRUCT_ARRAY_WRITE_RE.search(text)
        if sa:
            arr = _base_var(sa.group(1).strip())
            idx = int(sa.group(2))
            if arr in all_aliases:
                writes.append(HeapWriteSite(
                    line=i, target=arr, kind='struct_array',
                    write_size=-1, offset=idx, src_var='idx_const'))
        sf = re.search(r'(\w[\w]*)\s*(?:->|\.)\s*\w[\w]*\s*=', text)
        if sf:
            sbase = _base_var(sf.group(1).strip())
            if sbase in all_aliases:
                writes.append(HeapWriteSite(
                    line=i, target=sbase, kind='struct_write',
                    write_size=-1, offset=0))
    return writes


def find_struct_field_writes(lines: List[str],
                             alloc_vars: Set[str],
                             valid: set = None) -> List[HeapWriteSite]:
    """APAS: 检测memcpy/memset到结构体字段的写入.

    find_writes 的 _base_var 对 buf->b 返回 b 而非 buf,
    导致 memcpy(buf->b, ...) 遗漏. 本函数提取 ->/. 前的基变量.
    """
    writes = []
    for i, line in enumerate(lines, start=1):
        if valid and i not in valid:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        for m in _MEMCPY_HEAP_RE.finditer(text):
            dst_raw = m.group(1).strip()
            sm = re.match(r'^(\w[\w]*)\s*(?:->|\.)\s*\w[\w]*', dst_raw)
            if sm:
                base = sm.group(1)
                field_m = re.search(r'(?:->|\.)\s*(\w[\w]*)', dst_raw)
                field = field_m.group(1) if field_m else ""
                if base in alloc_vars:
                    ws = parse_alloc_size(m.group(3).strip(), lines, i)
                    w = HeapWriteSite(
                        line=i, target=base, kind='struct_write',
                        write_size=ws, offset=0)
                    w.src_var = f"field:{field}"
                    writes.append(w)
    return writes


__all__ = ['find_alias_writes', 'find_struct_field_writes']
