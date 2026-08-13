"""
线性符号表达式基础设施. 供 memcpy 关联等模块使用.

把源码表达式回溯为线性符号表达式 (系数 × 变量 累加 + 常量):
  - 数字 → 常量
  - 变量 → 前文赋值链回溯 (限 6 层防环)
  - var + k / k * var → 线性组合
  - strlen(x) → 独立符号变量 strlen(x)
"""

import re
from typing import Dict, List, Optional

from analysis.heap_overflow_src_patterns import _is_comment_or_empty


class SymExpr:
    """线性符号表达式: coeffs[var] = 系数, const = 常量."""
    __slots__ = ('coeffs', 'const')

    def __init__(self, coeffs=None, const=0):
        self.coeffs = dict(coeffs or {})
        self.const = const

    def __repr__(self):
        parts = ['%d*%s' % (v, k) for k, v in sorted(self.coeffs.items())
                 if v]
        if self.const or not parts:
            parts.append(str(self.const))
        return ' + '.join(parts)

    @staticmethod
    def const_expr(c):
        return SymExpr({}, c)

    @staticmethod
    def var_expr(name):
        return SymExpr({name: 1}, 0)


def trace_expr(expr: str, lines: List[str], around_line: int,
               depth: int = 0) -> Optional[SymExpr]:
    """把表达式回溯为符号表达式 (线性).

    支持:
      - 数字 → SymExpr.const
      - 变量 → 前文赋值链回溯 (限 6 层防环)
      - var + k / k * var / var * k → 线性组合
      - strlen(x) → SymExpr.var_expr('strlen(x)')
    """
    if depth > 6:
        return None
    e = expr.strip()
    if re.match(r'^\d+$', e):
        return SymExpr.const_expr(int(e))
    dm = re.search(r'strlen\s*\(\s*([\w\[\]]+)\s*\)', e)
    if dm:
        # strlen 视为独立符号变量 (线性增长)
        se = SymExpr.var_expr('strlen(' + dm.group(1) + ')')
        rest = re.sub(r'strlen\s*\(\s*[\w\[\]]+\s*\)', '', e).strip()
        rm = re.search(r'^\s*\+\s*(\d+)\s*$', rest)
        if rm:
            se.const = int(rm.group(1))
        return se
    # var + k
    m = re.match(r'(\w[\w]*)\s*\+\s*(\d+)$', e)
    if m:
        base = trace_expr(m.group(1), lines, around_line, depth + 1)
        if base is not None:
            base.const += int(m.group(2))
            return base
    # k * var 或 var * k
    m = re.match(r'(\d+)\s*\*\s*(\w[\w]*)$', e)
    if m:
        base = trace_expr(m.group(2), lines, around_line, depth + 1)
        if base is not None:
            for k in base.coeffs:
                base.coeffs[k] *= int(m.group(1))
            base.const *= int(m.group(1))
            return base
    m = re.match(r'(\w[\w]*)\s*\*\s*(\d+)$', e)
    if m:
        return trace_expr('%s*%s' % (m.group(2), m.group(1)),
                          lines, around_line, depth + 1)
    if re.match(r'^[a-zA-Z_]\w*$', e):
        return _trace_var(e, lines, around_line, depth + 1)
    return None


def _trace_var(name: str, lines: List[str], around_line: int,
               depth: int) -> Optional[SymExpr]:
    """回溯变量赋值链."""
    if depth > 6:
        return None
    for j in range(max(0, around_line - 12), around_line):
        t = lines[j].strip()
        if _is_comment_or_empty(t):
            continue
        am = re.search(rf'\b{re.escape(name)}\s*=\s*([^;]+);', t)
        if am:
            rhs = am.group(1).strip()
            return trace_expr(rhs, lines, j, depth + 1)
    return None


__all__ = ['SymExpr', 'trace_expr', '_trace_var']
