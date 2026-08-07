# coding: utf-8
# 创建: 2026-05-29  |  值域抽象域——堆溢出误报抑制的核心数据结构
#
"""
值域抽象域 (Value Region Domain)。

设计动机:
  现有堆溢出检测对size参数只做"立即数提取", 遇到寄存器/派生表达式即返回0,
  触发保守保留策略, 这是误报的第一大来源。本域将size参数的静态近似从
  "单点常量"升级为"区间值域 [lo, hi] + 来源分类", 使安全判定可基于
  区间上界而非单点, 从根源削减误报。

域结构:
  Region(lo, hi, kind, source_id)
    lo/hi: 区间边界, 使用饱和算术(64位有符号)
    kind:  CONSTANT  编译期确定
          COMPUTED  由算术指令派生
          PARAMETER 来自函数参数(不可控上界, 无上界)
          STACK     来自栈槽/局部变量
          MEMORY    来自内存加载
          UNKNOWN   无法解析
    source_id: 定义链根标识 (寄存器名或参数槽), 用于分配-写入关联

运算:
  shift_add / shift_sub / scale / clamp_widen / join / meet
  所有运算均饱和, 不产生越界回绕, 保证判定保守(不因回绕误判安全)。
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple

NEG_INF: int = -(1 << 63)
POS_INF: int = (1 << 63) - 1

KIND_CONSTANT = "CONSTANT"
KIND_COMPUTED = "COMPUTED"
KIND_PARAMETER = "PARAMETER"
KIND_STACK = "STACK"
KIND_MEMORY = "MEMORY"
KIND_UNKNOWN = "UNKNOWN"

# 无上界的来源类别——上界为 POS_INF
_UNBOUNDED_KINDS = frozenset(
    {KIND_PARAMETER, KIND_STACK, KIND_MEMORY, KIND_UNKNOWN})


@dataclass(frozen=True)
class Region:
    """值域: [lo, hi] 闭区间 + 来源分类 + 根标识.

    root_key: 值链根标识——同一根键表示两个使用点观察到同一运行时值
    (寄存器同一定值等价)。mov 复制链继承根键; 算术派生/新定值重置。
    """
    lo: int = 0
    hi: int = POS_INF
    kind: str = KIND_UNKNOWN
    source_id: str = ""
    root_key: str = ""

# 构造辅助

    @staticmethod
    def constant(v: int) -> "Region":
        return Region(lo=v, hi=v, kind=KIND_CONSTANT, source_id=f"c{v}")

    @staticmethod
    def unbounded(kind: str = KIND_UNKNOWN, source_id: str = "") -> "Region":
        return Region(lo=0, hi=POS_INF, kind=kind, source_id=source_id)

    @staticmethod
    def param(source_id: str = "") -> "Region":
        return Region(lo=0, hi=POS_INF, kind=KIND_PARAMETER,
                      source_id=source_id)

    @staticmethod
    def bottom() -> "Region":
        """空区间——表示约束矛盾."""
        return Region(lo=POS_INF, hi=NEG_INF, kind=KIND_UNKNOWN,
                      source_id="")

# 谓词

    @property
    def is_bottom(self) -> bool:
        return self.lo > self.hi

    @property
    def is_top(self) -> bool:
        return self.lo == 0 and self.hi == POS_INF

    @property
    def is_constant(self) -> bool:
        return self.kind == KIND_CONSTANT

    @property
    def is_bounded(self) -> bool:
        return self.kind not in _UNBOUNDED_KINDS and self.hi != POS_INF

    @property
    def is_unbounded(self) -> bool:
        return self.hi == POS_INF

    @property
    def has_upper_bound(self) -> bool:
        return self.hi != POS_INF

    def width(self) -> Optional[int]:
        """区间宽度; 无限区间返回 None."""
        if self.lo == NEG_INF or self.hi == POS_INF:
            return None
        return self.hi - self.lo

# 运算 (饱和)

    def saturate(self, v: int) -> int:
        return max(NEG_INF, min(POS_INF, v))

    def shift_add(self, imm: int) -> "Region":
        if self.is_bottom:
            return self
        return Region(lo=self.saturate(self.lo + imm),
                      hi=self.saturate(self.hi + imm),
                      kind=self.kind, source_id=self.source_id)

    def shift_sub(self, imm: int) -> "Region":
        if self.is_bottom:
            return self
        return Region(lo=self.saturate(self.lo - imm),
                      hi=self.saturate(self.hi - imm),
                      kind=self.kind, source_id=self.source_id)

    def scale(self, factor: int) -> "Region":
        """乘以因子(含符号). imul 的操作数均视为无符号非负, 因子取绝对值."""
        if self.is_bottom:
            return self
        f = abs(factor)
        if f == 0:
            return Region.constant(0)
        lo = 0 if self.lo <= 0 else self.lo
        lo = self.saturate(lo * f)
        hi = POS_INF if self.hi == POS_INF else self.saturate(self.hi * f)
        return Region(lo=lo, hi=hi, kind=self.kind, source_id=self.source_id)

    def bit_and_mask(self, mask: int) -> "Region":
        """and reg, imm —— 结果上界受掩码约束."""
        if self.is_bottom:
            return self
        return Region(lo=0, hi=self.saturate(mask), kind=self.kind,
                      source_id=self.source_id)

    def widen32(self) -> "Region":
        """movzx 32位→64位: 保持下界, 上界收窄到 2^32-1."""
        if self.is_bottom:
            return self
        return Region(lo=0 if self.lo < 0 else self.lo,
                      hi=min(self.hi, 0xFFFFFFFF) if self.hi != POS_INF
                      else 0xFFFFFFFF,
                      kind=self.kind, source_id=self.source_id)

    def sign_extend32(self) -> "Region":
        """movsx 32位→64位: 符号扩展, 保守放宽到下界 0."""
        return Region(lo=0 if self.lo < 0 else self.lo,
                      hi=self.hi if self.hi != POS_INF else POS_INF,
                      kind=self.kind, source_id=self.source_id)

# 格运算

    def join(self, other: "Region") -> "Region":
        """并——取凸包. 用于不确定路径合并."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        lo = min(self.lo, other.lo)
        hi = max(self.hi, other.hi)
        kind = self.kind if self.kind == other.kind else KIND_COMPUTED
        return Region(lo=lo, hi=hi, kind=kind, source_id=self.source_id)

    def meet(self, other: "Region") -> "Region":
        """交——取交集; 空则 bottom."""
        if self.is_bottom or other.is_bottom:
            return self.bottom()
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        if lo > hi:
            return self.bottom()
        return Region(lo=lo, hi=hi, kind=self.kind,
                      source_id=self.source_id)

    def refine_upper(self, bound: int) -> "Region":
        """守卫细化: 若 hi <= bound 无变化; 否则收窄上界到 bound."""
        if self.is_bottom:
            return self
        return Region(lo=self.lo, hi=min(self.hi, bound),
                      kind=self.kind, source_id=self.source_id)

    def refine_lower(self, bound: int) -> "Region":
        """守卫细化: 下界提升到 bound."""
        if self.is_bottom:
            return self
        return Region(lo=max(self.lo, bound), hi=self.hi,
                      kind=self.kind, source_id=self.source_id)

    def __repr__(self) -> str:
        if self.is_bottom:
            return "⊥"
        lo_s = "-inf" if self.lo == NEG_INF else str(self.lo)
        hi_s = "+inf" if self.hi == POS_INF else str(self.hi)
        return f"[{lo_s},{hi_s}]{self.kind}{':' + self.source_id if self.source_id else ''}"

    def to_dict(self) -> dict:
        return {"lo": self.lo, "hi": self.hi, "kind": self.kind,
                "source_id": self.source_id}


__all__ = [
    "Region", "NEG_INF", "POS_INF",
    "KIND_CONSTANT", "KIND_COMPUTED", "KIND_PARAMETER",
    "KIND_STACK", "KIND_MEMORY", "KIND_UNKNOWN",
]
