"""
堆操作IR模式匹配器 — 从伪代码中提取 malloc/memcpy/赋值/条件模式.

保持单一职责: IR模式识别与参数抽取.
"""


import re
from typing import Optional, Tuple


def match_assign(text: str) -> Optional[Tuple[str, str]]:
    """匹配变量赋值: var = expr; (返回var, expr)."""
    m = re.match(r'(\w+)\s*=\s*(.+);?$', text)
    if not m:
        return None
    return m.group(1), m.group(2).rstrip(';')


def match_if(text: str) -> Optional[Tuple[str, bool]]:
    """匹配if/while条件: if(cond) {."""
    m = re.match(r'if\s*\((.+)\)\s*\{?', text)
    if m:
        return m.group(1), True
    m = re.match(r'while\s*\((.+)\)\s*\{?', text)
    if m:
        return m.group(1), True
    return None


def match_alloc(text: str) -> Optional[Tuple[str, str, str]]:
    """匹配malloc/calloc/realloc调用.

    返回 (dst_var, func_name, size_text) 或 None.
      - calloc 自动转换为乘积表达式: "(n) * (size)"
      - realloc 只提取新大小参数 (忽略旧指针)
    """
    for fn in ('malloc', 'calloc', 'realloc'):
        m = re.match(r'(\w+)\s*=\s*' + fn + r'\((.+)\);?', text)
        if m:
            if fn == 'calloc':
                parts = m.group(2).split(',')
                if len(parts) >= 2:
                    size_text = f"({parts[0].strip()}) * ({parts[1].strip()})"
                else:
                    size_text = m.group(2)
            elif fn == 'realloc':
                parts = m.group(2).split(',')
                size_text = parts[1].strip() if len(parts) >= 2 else '0'
            else:
                size_text = m.group(2)
            return m.group(1), fn, size_text
    return None


def match_write(text: str) -> Optional[Tuple[str, str]]:
    """匹配堆写入操作 (memcpy/memmove/memset/strcpy/strncpy).

    返回 (func_name, size_text) 或 None.
      - memcpy 返回第3参数大小
      - strcpy 返回'0' (未知, 保守)
      - strncpy 返回第3参数
    """
    for fn in ('memcpy', 'memmove', 'memset', 'strcpy', 'strncpy'):
        m = re.search(fn + r'\((.+)\)', text)
        if m:
            args = m.group(1).split(',')
            if fn in ('memcpy', 'memmove', 'memset') and len(args) >= 3:
                return fn, args[2].strip()
            if fn == 'strncpy' and len(args) >= 3:
                return fn, args[2].strip()
            if fn == 'strcpy':
                return fn, '0'
    return None


def match_condition(text: str) -> Optional[Tuple[str, str, int]]:
    """从条件文本中提取 (var, op, val).

    支持: var<N, var<=N, var>N, var>=N 及反向形式.
    op 值: 'lt', 'le', 'gt', 'ge'.
    """
    for pat, op in [
        (r'(\w+)\s*<\s*(\d+)', 'lt'),
        (r'(\w+)\s*<=\s*(\d+)', 'le'),
        (r'(\w+)\s*>\s*(\d+)', 'gt'),
        (r'(\w+)\s*>=\s*(\d+)', 'ge'),
        (r'(\d+)\s*<\s*(\w+)', 'gt_rev'),
        (r'(\d+)\s*<=\s*(\w+)', 'ge_rev'),
    ]:
        m = re.match(pat, text)
        if not m:
            continue
        a, b = m.group(1), m.group(2)
        try:
            val = int(b if op in ('lt', 'le', 'gt', 'ge') else a)
            var = a if op in ('lt', 'le', 'gt', 'ge') else b
        except ValueError:
            continue
        return var, op, val
    return None


__all__ = ['match_assign', 'match_if', 'match_alloc',
           'match_write', 'match_condition']
