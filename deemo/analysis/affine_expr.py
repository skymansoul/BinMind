"""

AffineExpr: 仿射表达式 base + Σ(coef_i × sym_var_i) 及其运算.
OverfRelation: alloc-write 溢出关系判定结果.
表达式解析: C伪代码 → 仿射表达式的转换函数.
"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AffineExpr:
    """仿射表达式: base + Σ(coef_i × sym_var_i)."""

    base: int = 0
    terms: Dict[str, int] = field(default_factory=dict)

    def eval_bounds(self, var_bounds: Dict[str, Tuple[int, int]]) -> Tuple[int, int]:
        """在给定的变量范围下计算表达式的最小/最大值."""
        lo = self.base
        hi = self.base
        for var, coef in self.terms.items():
            vlo, vhi = var_bounds.get(var, (0, 2**31 - 1))
            if coef > 0:
                lo += coef * vlo
                hi += coef * vhi
            else:
                lo += coef * vhi
                hi += coef * vlo
        return (lo, hi)

    def substitute(self, var: str, expr: AffineExpr) -> AffineExpr:
        """将表达式中的 var 替换为另一个仿射表达式."""
        if var not in self.terms:
            return self
        coef = self.terms.pop(var)
        new_base = self.base + coef * expr.base
        new_terms = dict(self.terms)
        for v, c in expr.terms.items():
            new_terms[v] = new_terms.get(v, 0) + coef * c
        return AffineExpr(new_base, new_terms)

    @property
    def is_constant(self) -> bool:
        """表达式是否为常数 — 所有变量系数为0或terms为空."""
        return len(self.terms) == 0 or all(c == 0 for c in self.terms.values())

    @property
    def constant_value(self) -> Optional[int]:
        return self.base if self.is_constant else None

    def __add__(self, other):
        if isinstance(other, int):
            return AffineExpr(self.base + other, dict(self.terms))
        new_base = self.base + other.base
        new_terms = dict(self.terms)
        for v, c in other.terms.items():
            new_terms[v] = new_terms.get(v, 0) + c
        return AffineExpr(new_base, new_terms)

    def __sub__(self, other):
        if isinstance(other, int):
            return AffineExpr(self.base - other, dict(self.terms))
        new_base = self.base - other.base
        new_terms = dict(self.terms)
        for v, c in other.terms.items():
            new_terms[v] = new_terms.get(v, 0) - c
        return AffineExpr(new_base, new_terms)

    def __mul__(self, factor: int):
        return AffineExpr(self.base * factor,
                         {v: c * factor for v, c in self.terms.items()})

    def shared_vars(self, other: AffineExpr) -> Set[str]:
        return set(self.terms.keys()) & set(other.terms.keys())

    def __repr__(self) -> str:
        parts = []
        if self.base != 0:
            parts.append(str(self.base))
        for v, c in sorted(self.terms.items()):
            if c == 1:
                parts.append(v)
            elif c == -1:
                parts.append(f"-{v}")
            elif c > 0:
                parts.append(f"{c}*{v}")
            else:
                parts.append(f"{c}*{v}")
        return " + ".join(parts) if parts else "0"


@dataclass
class OverfRelation:
    """两个仿射表达式的溢出关系判定."""
    alloc_expr: AffineExpr
    write_expr: AffineExpr
    diff_expr: AffineExpr
    verdict: str = "UNKNOWN"
    condition: str = ""
    shared_vars: Set[str] = field(default_factory=set)

    @property
    def is_conclusive(self) -> bool:
        return self.verdict in ("SAFE", "OVERFLOW")


# 表达式解析

_SIZEOF_TABLE: Dict[str, int] = {
    'char': 1, 'short': 2, 'int': 4, 'long': 8,
    'long long': 8, 'float': 4, 'double': 8,
    'void*': 8, 'char*': 8, 'int*': 8,
    'size_t': 8, 'unsigned int': 4, 'unsigned long': 8,
    'uint32_t': 4, 'uint64_t': 8, 'uint8_t': 1,
}

_SIZEOF_PATTERN = re.compile(r'sizeof\s*\(\s*([^)]+)\s*\)')


def expand_sizeof(expr: str) -> str:
    """展开 sizeof(T) 为数字常量."""
    def _replace(m):
        type_name = m.group(1).strip()
        size = _SIZEOF_TABLE.get(type_name)
        if size is not None:
            return str(size)
        if type_name.endswith('*') or type_name.endswith('**'):
            return '8'
        return '4'
    return _SIZEOF_PATTERN.sub(_replace, expr)


def parse_expression(raw: str, var_expr: Dict[str, AffineExpr]) -> AffineExpr:
    """解析C表达式为仿射表达式, 自动展开已知变量的定义.

    例: 'n * 4 + 8' → AffineExpr(base=8, terms={'n': 4})
        '64' → AffineExpr(base=64, terms={})
    """
    raw = raw.strip()
    raw = expand_sizeof(raw)
    raw = re.sub(r'\(\s*\w+\s*\*?\s*\)', '', raw)  # 去cast

    try:
        val = int(eval(raw, {"__builtins__": {}}, {}))
        return AffineExpr(base=val)
    except Exception:
        pass

    if re.match(r'^[a-zA-Z_]\w*$', raw) and raw in var_expr:
        return var_expr[raw]

    # 位运算符保守替换: | → +, & → + (对size分析, 位运算结果 ≤ 算术和)
    # 必须在去空格和拆分之前完成, 否则 | 会与分隔符冲突
    raw = raw.replace('|', '+').replace('&', '+')
    compact = raw.replace(' ', '')
    # 用 \x01 (SOH) 作为分隔符 — 绝不出现在C表达式中
    marked = ''
    for i, ch in enumerate(compact):
        if ch in ('+', '-') and i > 0:
            marked += '\x01' + ch
        else:
            marked += ch
    parts = [p for p in marked.split('\x01') if p]

    terms: Dict[str, int] = {}
    base = 0

    for part in parts:
        part = part.strip()
        if not part:
            continue
        sign = 1
        if part.startswith('-'):
            sign = -1
            part = part[1:]
        elif part.startswith('+'):
            part = part[1:]
        if not part:
            continue

        try:
            base += sign * int(part)
            continue
        except ValueError:
            pass

        mul_match = re.match(r'(\d+)\*(\w+)', part)
        if mul_match:
            coef = sign * int(mul_match.group(1))
            var = mul_match.group(2)
            if var in var_expr:
                expanded = var_expr[var] * coef
                base += expanded.base
                for v, c in expanded.terms.items():
                    terms[v] = terms.get(v, 0) + c
            else:
                terms[var] = terms.get(var, 0) + coef
            continue

        mul_match2 = re.match(r'(\w+)\*(\d+)', part)
        if mul_match2:
            var = mul_match2.group(1)
            coef = sign * int(mul_match2.group(2))
            if var in var_expr:
                expanded = var_expr[var] * coef
                base += expanded.base
                for v, c in expanded.terms.items():
                    terms[v] = terms.get(v, 0) + c
            else:
                terms[var] = terms.get(var, 0) + coef
            continue

        if re.match(r'^[a-zA-Z_]\w*$', part):
            if part in var_expr:
                expanded = var_expr[part]
                base += expanded.base
                for v, c in expanded.terms.items():
                    terms[v] = terms.get(v, 0) + c
            else:
                terms[part] = terms.get(part, 0) + sign * 1
            continue

    terms = {v: c for v, c in terms.items() if c != 0}
    return AffineExpr(base=base, terms=terms)


__all__ = ['AffineExpr', 'OverfRelation', 'expand_sizeof', 'parse_expression']
