"""
C源码整数溢出 — 模式定义 + 数据结构。
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class IntOverflowFinding:
    """C源码整数溢出发现."""
    line: int
    pattern: str           # "malloc_mul_overflow", "loop_accum", "unchecked_mul"
    expression: str         # 溢出表达式
    lhs_var: str = ""       # 结果变量
    operand_a: str = ""     # 操作数A
    operand_b: str = ""     # 操作数B
    has_guard: bool = False
    overflow_possible: bool = True
    confidence: float = 0.50
    reason: str = ""


# malloc/calloc/realloc 所有参数形式
_MALLOC_MUL_PAT = re.compile(
    r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(\s*'
    r'(\w+)\s*\*\s*sizeof\s*\(([^)]+)\)',
    re.IGNORECASE)

# malloc(signed_var) — CWE-681: int→size_t unsigned 转换
_MALLOC_SIGNED_PAT = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(\s*\(?(?:int|long)\s*\)?\s*(\w+)\s*\)',
    re.IGNORECASE)

# malloc(var + const) 或 malloc(var - const) — CWE-190/191 加减溢出
_MALLOC_ADDSUB_PAT = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*([+\-])\s*(\d+)\s*\)',
    re.IGNORECASE)

# malloc(non_const_var) — 任何变量直接做malloc参数
_MALLOC_VAR_PAT = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\)',
    re.IGNORECASE)

# n * sizeof(T) 用于任何上下文 (非 malloc 参数)
_BARE_MUL_PAT = re.compile(
    r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(([^)]+)\)',
    re.IGNORECASE)

# 窄类型截断: int n = (int)size_t_var — CWE-680
_TRUNCATION_PAT = re.compile(
    r'(?:int|short|int16_t|uint16_t)\s+(\w+)\s*=\s*\(\s*(?:int|short)\s*\)\s*(\w+)',
    re.IGNORECASE)

# 类型降级乘法: uint16_t count * sizeof(...) — CWE-190 窄类型
_NARROW_MUL_PAT = re.compile(
    r'(?:uint16_t|int16_t|short)\s+(\w+)\s*=\s*\d+\s*;.*'
    r'(?:size_t|int)\s+(\w+)\s*=\s*\1\s*\*\s*sizeof',
    re.IGNORECASE)

# return malloc(n * sizeof(T)) — 无赋值, 用于分配器包装函数
_MALLOC_MUL_RETURN_PAT = re.compile(
    r'return\s+(?:\(\w+\*\)\s*)?(?:malloc|calloc|realloc)\s*\(\s*'
    r'(\w+)\s*\*\s*(?:sizeof\s*\([^)]+\)|(\w+))',
    re.IGNORECASE)

# realloc(ptr, var1 - var2) — CWE-191 有符号减法导致下溢
_REALLOC_SUB_PAT = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(\s*[^,]*,\s*(\w+)\s*-\s*(\w+)\s*\)',
    re.IGNORECASE)

# int idx = a + b; if (idx < N) buf[idx] — CWE-129 加法溢出导致越界
_SIGNED_ADD_IDX_PAT = re.compile(
    r'(?:int|unsigned\s+int)\s+(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;',
    re.IGNORECASE)

# 循环累积: total += size / sum += val
_LOOP_ACCUM_PAT = re.compile(r'(\w+)\s*\+=\s*(\w+)\s*;', re.IGNORECASE)

# atoi/argv → int n → malloc(n * sizeof(T)) — 不可信输入链
_UNTRUSTED_INPUT_PAT = re.compile(
    r'(\w+)\s*=\s*(?:ato[il]|strto[lu]|strtoul)\s*\(([^)]+)\)',
    re.IGNORECASE)

# if (a > INT_MAX / b) — 溢出守卫
_OVERFLOW_GUARD_PAT = re.compile(
    r'if\s*\(\s*(\w+)\s*>\s*(?:INT_MAX|UINT_MAX|SIZE_MAX|0x7[fF]+)'
    r'\s*/\s*(\w+)\s*\)',
    re.IGNORECASE)

# for (i=0; i<n; i++) — 循环 + 可溢出计算
_FOR_LOOP_HEADER = re.compile(
    r'for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;\s*\w+\+{2}\s*\)',
    re.IGNORECASE)
