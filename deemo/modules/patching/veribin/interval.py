"""VeriBin A/B 级：区间分析与边界检查 —— Z3 降级方案。"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class SafetyLevel(Enum):
    LEVEL_A = "A"
    LEVEL_B = "B"
    LEVEL_C = "C"


@dataclass
class SafetyVerdict:
    level: SafetyLevel
    is_safe: bool
    score: float
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class Interval:
    """整数区间 [lo, hi] —— 轻量值范围分析，Z3 不可用时的替代。"""
    lo: int
    hi: int

    def intersect(self, other: "Interval") -> Optional["Interval"]:
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        return Interval(lo, hi) if lo <= hi else None

    def union(self, other: "Interval") -> "Interval":
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))


def interval_bound_check(
    access_offset: Interval, buffer_size: int, access_size: int = 1
) -> Tuple[bool, str]:
    """
    轻量边界检查 —— 区间分析替代 Z3 约束求解。

    检查 access_offset 所有可能值是否在 [0, buffer_size - access_size] 内。
    保守估计：可能有假阳性（报告不安全），但不会假阴性（不漏真正的越界）。
    """
    valid_lo, valid_hi = 0, buffer_size - access_size
    if access_offset.lo < valid_lo:
        return False, f"可能下溢: offset [{access_offset.lo},{access_offset.hi}], 有效范围 [{valid_lo},{valid_hi}]"
    if access_offset.hi > valid_hi:
        return False, f"可能上溢: offset [{access_offset.lo},{access_offset.hi}], 有效范围 [{valid_lo},{valid_hi}]"
    return True, "区间分析: 边界检查通过"


__all__ = ["SafetyLevel", "SafetyVerdict", "Interval", "interval_bound_check"]
