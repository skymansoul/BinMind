"""
CAAWP表达式解析模块 — 从caawp_interpreter.py拆分.

包含size表达式解析、参数分割、仿射运算等功能.
"""

import re
from typing import Dict, List, Optional, Tuple


def parse_size_expr(expr: str) -> Tuple[Dict[str, float], float]:
    """解析size表达式为(coefs, const).

    "64" -> ({}, 64.0)
    "n" -> ({"n": 1.0}, 0.0)
    "n*2" -> ({"n": 2.0}, 0.0)
    "n+8" -> ({"n": 1.0}, 8.0)
    "2*n+8" -> ({"n": 2.0}, 8.0)
    "nmemb*size" -> ({"nmemb": 1.0, "size": 1.0}, 0.0)
    """
    expr = expr.strip()
    if not expr:
        return {}, 0.0

    try:
        v = float(expr)
        return {}, v
    except ValueError:
        pass

    coefs: Dict[str, float] = {}
    const = 0.0

    parts = re.split(r'\s*([+\-])\s*', expr)
    current_sign = 1.0

    for part in parts:
        if part == '+':
            current_sign = 1.0
        elif part == '-':
            current_sign = -1.0
        elif part.strip():
            term = part.strip()
            m = re.match(r'(\d+\.?\d*)\s*\*\s*(\w+)', term)
            if m:
                coef = float(m.group(1)) * current_sign
                var = m.group(2)
                coefs[var] = coefs.get(var, 0) + coef
                continue
            m = re.match(r'(\w+)\s*\*\s*(\d+\.?\d*)', term)
            if m:
                coef = float(m.group(2)) * current_sign
                var = m.group(1)
                coefs[var] = coefs.get(var, 0) + coef
                continue
            m = re.match(r'(\w+)\s*\*\s*(\w+)', term)
            if m:
                v1, v2 = m.group(1), m.group(2)
                if v1 not in ('sizeof', 'NULL', 'null'):
                    coefs[v1] = coefs.get(v1, 0) + current_sign
                if v2 not in ('sizeof', 'NULL', 'null'):
                    coefs[v2] = coefs.get(v2, 0) + current_sign
                continue
            try:
                const += float(term) * current_sign
                continue
            except ValueError:
                pass
            m = re.match(r'(\w+)', term)
            if m:
                var = m.group(1)
                if var not in ('sizeof', 'NULL', 'null'):
                    coefs[var] = coefs.get(var, 0) + current_sign
                continue
            try:
                const += float(term) * current_sign
            except ValueError:
                pass
            current_sign = 1.0

    return coefs, const


def expand_vars(
    coefs: Dict[str, float],
    const: float,
    var_relations: Dict[str, Tuple[Dict[str, float], float]],
) -> Tuple[Dict[str, float], float]:
    """展开coefs中引用的变量为它们的仿射表达式."""
    result_coefs: Dict[str, float] = {}
    result_const = const

    for var, coef in coefs.items():
        if var in var_relations:
            sub_coefs, sub_const = var_relations[var]
            for sv, sc in sub_coefs.items():
                result_coefs[sv] = result_coefs.get(sv, 0) + sc * coef
            result_const += sub_const * coef
        else:
            result_coefs[var] = result_coefs.get(var, 0) + coef

    return result_coefs, result_const


def multiply_affine(
    expr1: Tuple[Dict[str, float], float],
    expr2: Tuple[Dict[str, float], float],
) -> Tuple[Dict[str, float], float]:
    """仿射乘法, 仅处理常量*变量或常量*常量, 否则保守处理."""
    coefs1, const1 = expr1
    coefs2, const2 = expr2

    if not coefs1 and not coefs2:
        return {}, const1 * const2
    if not coefs1 and coefs2:
        if const1 != 0:
            return {v: c2 * const1 for v, c2 in coefs2.items()}, \
                const2 * const1
        return dict(coefs2), const2
    if not coefs2 and coefs1:
        if const2 != 0:
            return {v: c1 * const2 for v, c1 in coefs1.items()}, \
                const1 * const2
        return dict(coefs1), const1

    result_coefs: Dict[str, float] = {}
    for v, c in coefs1.items():
        result_coefs[v] = result_coefs.get(v, 0) + c
    for v, c in coefs2.items():
        result_coefs[v] = result_coefs.get(v, 0) + c
    return result_coefs, const1 * const2


def parse_write_args(
    args_str: str,
    mnemonic: str,
) -> Tuple[str, Optional[str]]:
    """解析写入函数参数, 返回(dst_var, size_expr_or_None)."""
    parts = split_args(args_str)
    if not parts:
        return "", None

    dst = parts[0].strip()
    dst_var = dst.split('+')[0].split('->')[0].split('.')[0].strip()

    if mnemonic in ('memcpy', 'memmove', 'memset', 'strncpy', 'read', 'recv'):
        if len(parts) >= 3:
            return dst_var, parts[2].strip()
    elif mnemonic in ('strcpy',):
        return dst_var, None

    return dst_var, None


def split_args(s: str) -> List[str]:
    """按逗号分割参数, 忽略括号内的逗号."""
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch == '(':
            depth += 1; cur.append(ch)
        elif ch == ')':
            depth -= 1; cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur))
    return parts


__all__ = [
    'parse_size_expr', 'expand_vars', 'multiply_affine',
    'parse_write_args', 'split_args',
]
