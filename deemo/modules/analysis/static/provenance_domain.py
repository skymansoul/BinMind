# 来源格 (Provenance Lattice) - PcWBI来源约束写界推断.
#
# 决策逻辑:
#   堆溢出误报的根源是"宽区间回退": 当写入大小操作数无法解析为常量时,
#   现有检测器将其建模为[0, 2^31-1]的最宽区间, 与分配区间必然重叠,
#   于是每个无法定界的memcpy都产生一条"可能溢出"告警.
#   观察: 大多数此类告警的写入大小要么与分配大小同源, 要么受显式边界检查
#   约束, 要么为编译时常量. 把"来源"作为第一等公民参与判定, 而非退化为
#   数值区间, 可在不损失召回的前提下剔除此类系统性误报.
#
#   本模块定义来源类别格与携带边界的来源值, 为后续传播器与写界推断器
#   提供统一的数据结构. 精度序: CONSTANT < GUARDED < ALLOC_LINKED <
#   INPUT_TAINTED < UNKNOWN, 即"对写入上界的确信程度"自高向低.
#

from enum import Enum
from typing import Optional

from .sym_size_correlator import SymExpr


class ProvClass(Enum):
    """写入大小操作数的来源类别."""

    CONSTANT = 0       # 编译时常量, 上界精确已知
    GUARDED = 1        # 经 cmp/jcc 与分配大小比较, 上界被守卫约束
    ALLOC_LINKED = 2   # 与分配大小同源 (共享符号变量或结构相关)
    INPUT_TAINTED = 3  # 来自 read/recv/argv 等外部输入, 无静态上界
    UNKNOWN = 4        # 无法追踪, 保守最不精确


# 精度序: 数值越小越精确. join取两者中较不精确者.
_PROV_PRECISION = {
    ProvClass.CONSTANT: 0,
    ProvClass.GUARDED: 1,
    ProvClass.ALLOC_LINKED: 2,
    ProvClass.INPUT_TAINTED: 3,
    ProvClass.UNKNOWN: 4,
}


def join_class(a: ProvClass, b: ProvClass) -> ProvClass:
    """来源类别的最小上界 (取较不精确者)."""
    if _PROV_PRECISION[a] >= _PROV_PRECISION[b]:
        return a
    return b


class ProvValue:

    __slots__ = ("cls", "expr", "bound", "guard_upper", "note")

    def __init__(self, cls: ProvClass, expr: Optional[SymExpr] = None,
                 bound: Optional[int] = None,
                 guard_upper: Optional[int] = None,
                 note: str = ""):
        self.cls = cls
        self.expr = expr
        self.bound = bound
        self.guard_upper = guard_upper
        self.note = note

    def join(self, other: "ProvValue") -> "ProvValue":
        """合并两条路径上的来源值 (路径合并点)."""
        cls = join_class(self.cls, other.cls)
        expr = self.expr if self.expr is not None else other.expr
        if cls == ProvClass.CONSTANT and self.bound is not None \
                and other.bound is not None:
            bound = max(self.bound, other.bound)
        else:
            bound = None
        guard = self.guard_upper if self.guard_upper is not None \
            else other.guard_upper
        return ProvValue(cls=cls, expr=expr, bound=bound,
                         guard_upper=guard,
                         note=f"join({self.cls.name},{other.cls.name})")

    @staticmethod
    def constant(value: int) -> "ProvValue":
        return ProvValue(ProvClass.CONSTANT, SymExpr(None, 0, value),
                         bound=value, note=f"const {value}")

    @staticmethod
    def param(idx: int) -> "ProvValue":
        return ProvValue(ProvClass.INPUT_TAINTED, SymExpr(var=f"param_{idx}"),
                         note=f"param {idx}")

    @staticmethod
    def unknown() -> "ProvValue":
        return ProvValue(ProvClass.UNKNOWN, note="unknown")

    def describe(self) -> str:
        """生成人类可读的来源描述."""
        if self.expr is not None and not self.expr.is_const():
            expr_s = repr(self.expr)
        elif self.bound is not None:
            expr_s = str(self.bound)
        else:
            expr_s = "?"
        if self.guard_upper is not None:
            expr_s += f" (guarded ≤ {self.guard_upper})"
        return f"{self.cls.name}[{expr_s}]"


__all__ = ["ProvClass", "ProvValue", "join_class"]
