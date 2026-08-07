"""DP-TVRA 过滤管线共享类型.

创建: 2026-06-20
用途: FilterPhase / FilterDecision 枚举 + FilterResult 数据结构,
      供 HeapFPFilterV2 和 orchestrator 共用。
"""
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

# 前向引用: 在运行时由导入方提供实际类型
# (避免循环导入 — path_value_narrowing 和 taint_propagation 不需要这些类型)


class FilterPhase(Enum):
    """过滤判定阶段."""
    PHASE1_TAINT = auto()
    PHASE2_PATH = auto()
    PHASE3_ALLOC = auto()


class FilterDecision(Enum):
    SAFE_FILTERED = "safe"
    CONFIRMED_VULN = "vuln"
    LIKELY_VULN = "likely"
    UNCERTAIN = "uncertain"
    INCONCLUSIVE = "inconclusive"


@dataclass
class FilterResult:
    """一次过滤判定的完整结果."""
    finding_id: str = ""
    decision: FilterDecision = FilterDecision.UNCERTAIN
    decisive_phase: FilterPhase = FilterPhase.PHASE3_ALLOC
    taint_label: Optional[object] = None       # TaintLabel (避免循环导入)
    narrowed_range: Optional[object] = None    # ValueRange
    alloc_usable: int = 0
    offset_value: int = 0
    access_size: int = 0
    reasoning: str = ""
    fp_probability: float = 0.5
