"""
C源码变量解析 — 模式定义 + 辅助函数。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Tuple


@dataclass
class DefPoint:
    """变量定义点."""
    var: str
    pc: int           # 行号
    value: int = -1   # 常量值, -1=非常量
    expr: str = ""    # 原始表达式 (如 "len", "n*4")
    is_const: bool = False


# 正则模式

_RE_DEFINE = re.compile(r'#define\s+(\w+)\s+(\d+)\b')
_RE_CONST_DECL = re.compile(
    r'(?:int|unsigned|size_t|long|short|char|uint\d+_t|int\d+_t)\s+'
    r'(\w+)\s*=\s*(\d+)\s*;')
_RE_ASSIGN_CONST = re.compile(r'(\w+)\s*=\s*(\d+)\s*;')
_RE_ASSIGN_VAR = re.compile(r'(\w+)\s*=\s*(\w+)\s*;')
_RE_ASSIGN_ADD = re.compile(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)\s*;')
_RE_ASSIGN_SUB = re.compile(r'(\w+)\s*=\s*(\w+)\s*-\s*(\d+)\s*;')
_RE_ASSIGN_MUL = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;')
_RE_ALLOC_CALL = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(([^)]*)\)', re.IGNORECASE)
_RE_MEMCPY_CALL = re.compile(
    r'(?:memcpy|memset|memmove|strncpy)\s*\([^,]+,\s*[^,]+,\s*(\w+|\d+)\s*\)',
    re.IGNORECASE)


def _try_int(s: str) -> Tuple[bool, int]:
    try:
        return True, int(s, 0)
    except (ValueError, TypeError):
        return False, -1
