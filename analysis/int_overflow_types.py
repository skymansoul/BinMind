"""
整数溢出源级检测类型定义 — IOSV (Integer Overflow Source Verifier) 共用类型.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class IovVerdict(Enum):
    VULN = "VULN"           # 证实可溢出
    SAFE = "SAFE"           # 证实安全 (有守卫/常量在范围内)
    UNCERTAIN = "UNCERTAIN" # 无法确定


class OverflowKind(Enum):
    MUL = "mul"       # a * b
    ADD = "add"       # a + b
    SHL = "shl"       # a << b
    MIXED = "mixed"   # a * b + c / a * b * c


@dataclass
class AllocSite:
    """内存分配调用点."""
    line: int
    func: str             # malloc/calloc/realloc
    size_expr: str        # 原始大小表达式文本
    size_var: str         # 提取的变量名 (若直接传递变量)
    operands: List[str] = field(default_factory=list)  # 参与运算的操作数
    op_kind: OverflowKind = OverflowKind.MUL


@dataclass
class GuardSite:
    """溢出守卫检测点."""
    line: int
    kind: str             # 'wrap_check' | 'div_guard' | 'bound_check'
    guarded_var: str      # 被守卫的变量
    operand: str = ""     # wrap_check时比较的操作数
    is_effective: bool = True


@dataclass
class IovResult:
    """IOSV判定结果."""
    verdict: IovVerdict
    alloc_line: int = 0
    alloc_func: str = ""
    size_expr: str = ""
    overflow_kind: str = ""
    guarded: bool = False
    guard_line: int = 0
    value_range: str = ""
    reason: str = ""


@dataclass
class VarRange:
    """变量值范围."""
    lo: Optional[int] = None
    hi: Optional[int] = None
    is_signed: bool = True

    def mul(self, other: VarRange) -> VarRange:
        if self.lo is None or self.hi is None: return VarRange()
        if other.lo is None or other.hi is None: return VarRange()
        vals = [self.lo*other.lo, self.lo*other.hi, self.hi*other.lo, self.hi*other.hi]
        return VarRange(lo=min(vals), hi=max(vals))

    def add(self, other: VarRange) -> VarRange:
        if self.lo is None or other.lo is None: return VarRange()
        if self.hi is None or other.hi is None: return VarRange()
        return VarRange(lo=self.lo+other.lo, hi=self.hi+other.hi)

    def may_overflow_32(self) -> bool:
        if self.hi is None: return True
        limit = 0x7FFFFFFF if self.is_signed else 0xFFFFFFFF
        return self.hi > limit

    def __repr__(self) -> str:
        if self.lo is None: return "UNKNOWN"
        return f"[{self.lo}, {self.hi}]"


__all__ = ['IovVerdict', 'OverflowKind', 'AllocSite', 'GuardSite', 'IovResult', 'VarRange']
