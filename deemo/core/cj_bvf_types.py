"""
DD-BVF数据类型 — 符号表达式与相关性判定结果.

从cj_bvf_tracer.py拆分, 提供SymbolicExpr和CorrelationResult定义.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class SymbolicExpr:
    """线性符号表达式: sum(coef_i * var_i) + const."""
    coefs: Dict[str, float] = field(default_factory=dict)
    const: float = 0.0
    tainted: bool = False
    origin: str = ""

    def is_constant(self) -> bool:
        return not self.coefs and not self.tainted

    def is_tainted(self) -> bool:
        return self.tainted

    def has_var(self, v: str) -> bool:
        return v in self.coefs and self.coefs[v] != 0.0

    def has_vars(self) -> bool:
        return any(c != 0.0 for c in self.coefs.values())

    def vars(self) -> Set[str]:
        return {v for v, c in self.coefs.items() if c != 0.0}

    def eval_const(self) -> Optional[float]:
        if self.is_constant():
            return self.const
        return None

    def __repr__(self) -> str:
        terms = [f"{c:g}*{v}" for v, c in self.coefs.items() if c != 0]
        s = " + ".join(terms)
        if self.const != 0 or not terms:
            s += f" + {self.const:g}" if terms else f"{self.const:g}"
        if self.tainted:
            s += " [tainted]"
        return s.strip(" +")


@dataclass
class CorrelationResult:
    """alloc-write符号相关性判定结果."""
    proven_safe: bool = False
    proven_overflow: bool = False
    reason: str = ""
    alloc_expr: Optional[SymbolicExpr] = None
    write_expr: Optional[SymbolicExpr] = None
    shared_vars: List[str] = field(default_factory=list)
    certificate: str = ""


__all__ = ['SymbolicExpr', 'CorrelationResult']
