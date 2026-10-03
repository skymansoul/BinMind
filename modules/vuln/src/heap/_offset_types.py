# 偏移值域追踪器数据类型 — 从offset_range_tracker.py拆分.
# 提取到独立模块以消除_offset_trace_mixin与主文件之间的循环依赖.
# 增加顶层导入回退, 修复orchestrator sys.path注入导致的
#        "attempted relative import with no known parent package" 崩溃.

from dataclasses import dataclass, field
from typing import List
from enum import Enum, auto


class OffsetProvenance(Enum):
    """偏移来源类型 — 决定区间窄化的可信度."""
    CONSTANT = auto()          # 编译期立即数 → 精确
    REGISTER_CHAIN = auto()    # 从 malloc size 参数派生 → 可信
    BRANCH_GUARDED = auto()    # 分支条件窄化 → 高可信
    LOOP_INDUCTION = auto()    # 循环变量 → 需归纳分析
    UNKNOWN = auto()           # 无法追踪 → 保守


@dataclass
class OffsetRange:
    """偏移值域, 含窄化证据."""
    lo: int = 0
    hi: int = 0xFFFFFFFF
    provenance: OffsetProvenance = OffsetProvenance.UNKNOWN
    narrow_steps: List[str] = field(default_factory=list)

    def is_precise(self) -> bool:
        return self.lo == self.hi and self.provenance == OffsetProvenance.CONSTANT

    def narrowed_by(self, new_lo: int, new_hi: int, reason: str) -> 'OffsetRange':
        return OffsetRange(
            lo=max(self.lo, new_lo), hi=min(self.hi, new_hi),
            provenance=OffsetProvenance.BRANCH_GUARDED,
            narrow_steps=self.narrow_steps + [reason])

    def __repr__(self):
        return f"[{self.lo}, {self.hi}] ({self.provenance.name})"


@dataclass
class AllocToAccessPath:
    """从 malloc 到 heap access 的数据流路径摘要."""
    malloc_addr: int = 0
    alloc_size: int = 0
    access_addr: int = 0
    access_size: int = 0
    offset_range: OffsetRange = field(default_factory=OffsetRange)
    base_reg: str = ""
    offset_reg: str = ""
    branch_constraints: List['BranchConstraint'] = field(default_factory=list)
    can_prove_safe: bool = False
    can_prove_overflow: bool = False
    proof_reason: str = ""
