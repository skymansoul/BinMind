"""
堆安全证明义务 — 共享数据类型.

"""


from dataclasses import dataclass, field
from enum import Enum
from typing import List


class ProofVerdict(Enum):
    PROVED_SAFE = "proved_safe"        # 约束可证安全 → 过滤
    PROVED_OVERFLOW = "proved_overflow"  # 约束可证溢出 → 确认
    INCONCLUSIVE = "inconclusive"       # 约束不足 → 保留


@dataclass
class SizeConstraint:
    """对某个变量的数值约束 (从条件分支或赋值收集)."""
    var: str
    lo: int = -(2**31)       # 下界 (含)
    hi: int = 2**31 - 1      # 上界 (含)
    source_line: int = -1     # 约束来源行号
    constraint_type: str = ""  # 'guard' | 'assignment' | 'loop_bound' | 'macro'


@dataclass
class ProofObligation:
    """一个堆写入安全性的证明义务.

    P: ∀ paths, write_end ≤ alloc_effective_size
    其中 write_end = write_offset + write_size
         alloc_effective_size = chunk_size(alloc_size) - alias_offset
    """
    alloc_var: str
    alloc_size_expr: str      # malloc的参数表达式 (可能含变量)
    write_var: str
    write_offset: int          # 已知偏移量 (-1=动态)
    write_size: int            # 已知写入大小 (-1=动态)
    offset_var: str = ""       # 动态偏移的变量名
    size_var: str = ""         # 动态分配大小的变量名
    offset_constraints: List[SizeConstraint] = field(default_factory=list)
    size_constraints: List[SizeConstraint] = field(default_factory=list)
    verdict: 'ProofVerdict' = field(default_factory=lambda: ProofVerdict.INCONCLUSIVE)
    proof_detail: str = ""
