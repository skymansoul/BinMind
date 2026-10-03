#!/usr/bin/env python3
"""
ASIP源码检测正则表达式与工具函数.

所有正则定义和辅助函数集中于此, 供提取模块和检测模块共用.
"""
from __future__ import annotations

import re
from typing import Optional

# 正则表达式

_ALLOC_RE = re.compile(
    r'(?:(\w[\w]*)\s*=\s*)?(?:\(\s*\w+\s*\*\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(\s*(.+?)\s*\)',
    re.IGNORECASE,
)

_ALLOC_NESTED_RE = re.compile(
    r'(?:(\w[\w]*)\s*=\s*)?(?:\(\s*\w+\s*\*\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\((.+)\)',
    re.IGNORECASE,
)

_MEMCPY_RE = re.compile(
    r'(?:memcpy|memmove|strncpy)\s*\(\s*(\w[\w]*(?:\s*->\s*\w[\w]*)?)\s*,\s*[^,]+\s*,\s*'
    r'(0x[0-9a-fA-F]+|\d+|\w[\w]*(?:\s*[\*\+]\s*\d+)?)\s*\)',
    re.IGNORECASE,
)

_MEMCPY_OFF_RE = re.compile(
    r'(?:memcpy|memmove)\s*\(\s*(\w[\w]*)\s*\+\s*(0x[0-9a-fA-F]+|\d+|\w[\w]*)\s*,\s*[^,]+\s*,\s*'
    r'(0x[0-9a-fA-F]+|\d+|\w[\w]*(?:\s*[\*\+]\s*\d+)?)\s*\)',
    re.IGNORECASE,
)

_STRCPY_RE = re.compile(
    r'strcpy\s*\(\s*(\w[\w]*(?:\s*->\s*\w[\w]*)?)\s*,', re.IGNORECASE,
)

_SNPRINTF_RE = re.compile(
    r'snprintf\s*\(\s*(\w[\w]*)\s*,\s*(0x[0-9a-fA-F]+|\d+|\w[\w]*)\s*,',
    re.IGNORECASE,
)

_MEMSET_RE = re.compile(
    r'memset\s*\(\s*(\w[\w]*)\s*,\s*[^,]+\s*,\s*'
    r'(0x[0-9a-fA-F]+|\d+|\w[\w]*)\s*\)',
    re.IGNORECASE,
)

_ARRAY_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(0x[0-9a-fA-F]+|\d+|\w[\w]*(?:\s*%\s*\d+)?)\s*\]\s*=',
)

_INDEXED_STORE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(\d+)\s*\]\s*=\s*',
)

_PTR_WRITE_RE = re.compile(
    r'\*\s*\(\s*\w+\s*\*\s*\)\s*\(\s*(\w[\w]*)\s*\+\s*'
    r'(0x[0-9a-fA-F]+|\d+|\w[\w]*)\s*\)\s*=',
    re.IGNORECASE,
)

_LOOP_BOUND_RE = re.compile(
    r'for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\d+)\s*;',
    re.IGNORECASE,
)

_LOOP_MEMCPY_OFF_RE = re.compile(
    r'memcpy\s*\(\s*(\w[\w]*)\s*\+\s*\w[\w]*\s*\*\s*(\d+)\s*,\s*[^,]+\s*,\s*'
    r'(0x[0-9a-fA-F]+|\d+)\s*\)',
    re.IGNORECASE,
)

_CLAMP_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*>\s*(\d+)\s*\)\s*\1\s*=\s*\2\s*;',
    re.IGNORECASE,
)

_GUARD_RETURN_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*>\s*(\d+)\s*\)\s*(?:return|exit)',
    re.IGNORECASE,
)

_GUARD_COMPOUND_RE = re.compile(
    r'if\s*\(\s*\w[\w]*\s*(?:<=\s*\d+\s*\|\|\s*)?\w[\w]*\s*>\s*(\d+)\s*\)\s*(?:return|exit)',
    re.IGNORECASE,
)

_GUARD_UPPER_RE = re.compile(
    r'if\s*\(\s*\w[\w]*\s*>=?\s*0\s*&&\s*\w[\w]*\s*<=?\s*(\d+)\s*\)',
    re.IGNORECASE,
)

_PATH_COND_RE = re.compile(
    r'if\s*\(\s*\w[\w]*\s*>\s*0\s*&&\s*\w[\w]*\s*<=\s*(\d+)\s*\)',
    re.IGNORECASE,
)

_REALLOC_RE = re.compile(
    r'(\w[\w]*)\s*=\s*realloc\s*\(\s*\1\s*,\s*(\d+|\w[\w]*)\s*\)',
    re.IGNORECASE,
)

_CALL_RE = re.compile(
    r'(\w[\w]*)\s*\(\s*(\w[\w]*)\s*(?:,\s*(\d+|\w[\w]*))?\s*\)',
)

_SIZEOF_RE = re.compile(r'sizeof\s*\(\s*(?:struct\s+)?(\w[\w]*)\s*\)', re.IGNORECASE)

_GUARD_NEG_POS_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*<\s*0\s*\|\|\s*\1\s*>\s*(\d+)\s*\)\s*(?:return|exit)',
    re.IGNORECASE,
)

_GUARD_RANGE_RE = re.compile(
    r'if\s*\(\s*\w[\w]*\s*>=?\s*0\s*&&\s*\w[\w]*\s*<\s*(\d+)\s*\)',
    re.IGNORECASE,
)


# 工具函数

def _try_int(s: str) -> Optional[int]:
    try:
        return int(s, 0) if s.lower().startswith('0x') else int(s)
    except (ValueError, TypeError):
        return None


def _parse_size(s: str) -> Optional[int]:
    if s is None:
        return None
    try:
        return int(s, 0) if s.lower().startswith('0x') else int(s)
    except (ValueError, TypeError):
        return None


def _var_match(target: str, alloc_var: str) -> bool:
    """匹配变量名, 支持struct指针访问(buf->field)."""
    if '->' in target:
        base = target.split('->')[0].strip()
        return base == alloc_var
    return target == alloc_var


__all__ = [
    '_ALLOC_RE', '_ALLOC_NESTED_RE', '_MEMCPY_RE', '_MEMCPY_OFF_RE',
    '_STRCPY_RE', '_SNPRINTF_RE', '_MEMSET_RE', '_ARRAY_WRITE_RE',
    '_INDEXED_STORE_RE', '_PTR_WRITE_RE', '_LOOP_BOUND_RE',
    '_LOOP_MEMCPY_OFF_RE', '_CLAMP_RE', '_GUARD_RETURN_RE',
    '_GUARD_COMPOUND_RE', '_GUARD_UPPER_RE', '_PATH_COND_RE',
    '_REALLOC_RE', '_CALL_RE', '_SIZEOF_RE', '_GUARD_NEG_POS_RE',
    '_GUARD_RANGE_RE',
    '_try_int', '_parse_size', '_var_match',
]
