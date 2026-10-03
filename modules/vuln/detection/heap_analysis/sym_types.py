# coding: utf-8
"""符号化大小约束传播的数据类型定义.

"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class SymExpr:
    """符号表达式 — 线性形式: base_var * coeff + const"""
    var: Optional[str] = None
    coeff: int = 1
    const: int = 0
    is_const: bool = False

    def eval(self, env: Dict[str, int]) -> Optional[int]:
        """在变量绑定环境下求值"""
        if self.is_const:
            return self.const
        if self.var is None:
            return self.const if self.is_const else None
        val = env.get(self.var)
        if val is None:
            return None
        return val * self.coeff + self.const

    def add(self, other: 'SymExpr') -> 'SymExpr':
        """加法合并同基符号表达式"""
        if self.is_const and other.is_const:
            return SymExpr(is_const=True, const=self.const + other.const)
        if self.is_const:
            return SymExpr(var=other.var, coeff=other.coeff,
                           const=self.const + other.const)
        if other.is_const:
            return SymExpr(var=self.var, coeff=self.coeff,
                           const=self.const + other.const)
        if self.var == other.var:
            return SymExpr(var=self.var, coeff=self.coeff + other.coeff,
                           const=self.const + other.const)
        # 不同变量 — 保守返回无界
        return SymExpr(var=None, coeff=0, const=0)

    def sub(self, other: 'SymExpr') -> 'SymExpr':
        """减法"""
        if self.is_const and other.is_const:
            return SymExpr(is_const=True, const=self.const - other.const)
        neg_other = SymExpr(
            var=other.var, coeff=-other.coeff,
            const=-other.const, is_const=other.is_const)
        return self.add(neg_other)

    def mul_const(self, c: int) -> 'SymExpr':
        """乘以常量"""
        return SymExpr(var=self.var, coeff=self.coeff * c,
                       const=self.const * c,
                       is_const=self.is_const)

    def __repr__(self) -> str:
        if self.is_const:
            return str(self.const)
        parts = []
        if self.coeff != 0 and self.var:
            if self.coeff == 1:
                parts.append(self.var)
            else:
                parts.append(f"{self.coeff}*{self.var}")
        if self.const != 0:
            parts.append(str(self.const))
        return " + ".join(parts) if parts else "0"


@dataclass
class ConstraintRecord:
    """路径约束: var OP value"""
    var: str
    op: str       # lt/le/gt/ge/eq/ne
    value: int


@dataclass
class SymAllocRecord:
    """符号化分配记录"""
    insn_idx: int
    addr: int
    func: str
    size_expr: SymExpr
    return_label: str
    ptr_reg: str = "rax"


@dataclass
class SymWriteRecord:
    """符号化写入记录"""
    insn_idx: int
    addr: int
    func: str
    dst_label: str
    size_expr: SymExpr
    offset_expr: SymExpr
    linked_alloc: Optional[SymAllocRecord] = None


@dataclass
class SymAnalysisResult:
    """符号约束传播分析结果"""
    allocs: List[SymAllocRecord] = field(default_factory=list)
    writes: List[SymWriteRecord] = field(default_factory=list)
    constraints: List[ConstraintRecord] = field(default_factory=list)
    env: Dict[str, int] = field(default_factory=dict)
    proven_safe: List[int] = field(default_factory=list)
    proven_overflow: List[int] = field(default_factory=list)
    uncertain: List[int] = field(default_factory=list)


__all__ = [
    'SymExpr', 'ConstraintRecord', 'SymAllocRecord',
    'SymWriteRecord', 'SymAnalysisResult',
]
