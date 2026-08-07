#!/usr/bin/env python3
"""
ASIP写入提取模块 — 从源码中提取分配点后的写入操作.
"""

from typing import List, Optional, Tuple

from core.heap_overflow_detector import HeapAllocSite, HeapStore
from core.asip_source_regex import (
    _MEMCPY_OFF_RE, _LOOP_MEMCPY_OFF_RE, _MEMCPY_RE,
    _STRCPY_RE, _SNPRINTF_RE, _MEMSET_RE,
    _INDEXED_STORE_RE, _PTR_WRITE_RE, _ARRAY_WRITE_RE,
    _parse_size, _var_match, _try_int,
)


def _extract_writes(
    lines: List[str], alloc: HeapAllocSite,
) -> List[Tuple[HeapStore, Optional[int]]]:
    """提取分配点后的所有写入操作."""
    if not alloc.result_var:
        return []
    var = alloc.result_var
    writes = []

    for i in range(alloc.pc + 1, len(lines)):
        line = lines[i]

        m = _MEMCPY_OFF_RE.search(line)
        if m and m.group(1) == var:
            offset = _parse_size(m.group(2))
            size = _parse_size(m.group(3))
            writes.append((HeapStore(
                pc=i, base_var=var,
                offset=offset if offset else 0,
                offset_is_dynamic=(offset is None),
                store_size=size if size else -1,
                mnemonic='memcpy',
            ), size))
            continue

        m = _LOOP_MEMCPY_OFF_RE.search(line)
        if m and m.group(1) == var:
            stride = _try_int(m.group(2))
            copy_size = _try_int(m.group(3))
            if stride is not None and copy_size is not None:
                writes.append((HeapStore(
                    pc=i, base_var=var, offset=0,
                    offset_is_dynamic=True,
                    store_size=copy_size, mnemonic='memcpy',
                ), copy_size))
            continue

        m = _MEMCPY_RE.search(line)
        if m and _var_match(m.group(1), var):
            size = _parse_size(m.group(2))
            writes.append((HeapStore(
                pc=i, base_var=var, offset=0,
                offset_is_dynamic=(size is None),
                store_size=size if size else -1,
                mnemonic='memcpy',
            ), size))
            continue

        m = _STRCPY_RE.search(line)
        if m and _var_match(m.group(1), var):
            writes.append((HeapStore(
                pc=i, base_var=var, offset=0,
                offset_is_dynamic=True,
                store_size=-1, mnemonic='strcpy',
            ), None))
            continue

        m = _SNPRINTF_RE.search(line)
        if m and m.group(1) == var:
            size = _parse_size(m.group(2))
            writes.append((HeapStore(
                pc=i, base_var=var, offset=0,
                offset_is_dynamic=(size is None),
                store_size=size if size else -1,
                mnemonic='snprintf',
            ), size))
            continue

        m = _MEMSET_RE.search(line)
        if m and m.group(1) == var:
            size = _parse_size(m.group(2))
            writes.append((HeapStore(
                pc=i, base_var=var, offset=0,
                offset_is_dynamic=(size is None),
                store_size=size if size else -1,
                mnemonic='memset',
            ), size))
            continue

        m = _INDEXED_STORE_RE.search(line)
        if m and m.group(1) == var:
            offset = int(m.group(2))
            writes.append((HeapStore(
                pc=i, base_var=var, offset=offset,
                offset_is_dynamic=False,
                store_size=1, mnemonic='store',
            ), 1))
            continue

        m = _PTR_WRITE_RE.search(line)
        if m and m.group(1) == var:
            offset = _parse_size(m.group(2))
            writes.append((HeapStore(
                pc=i, base_var=var,
                offset=offset if offset else 0,
                offset_is_dynamic=(offset is None),
                store_size=4, mnemonic='store',
            ), 4))
            continue

        m = _ARRAY_WRITE_RE.search(line)
        if m and m.group(1) == var:
            offset = _parse_size(m.group(2))
            writes.append((HeapStore(
                pc=i, base_var=var,
                offset=offset if offset else 0,
                offset_is_dynamic=(offset is None),
                store_size=1, mnemonic='store',
            ), 1))
            continue

    return writes


__all__ = ['_extract_writes']
