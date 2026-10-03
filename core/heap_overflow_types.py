"""
堆溢出验证裁决类型定义 — 按值流分配大小+分配器宽松+守卫支配三类证据给出裁决。
类型与枚举集中于本文件, 其余堆溢出验证模块仅做逻辑, 避免循环导入。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Verdict(Enum):
    """裁决结果. FILTERED 项从最终输出移除, CONFIRMED/UNCERTAIN 保留."""
    CONFIRMED = 'CONFIRMED'
    FILTERED = 'FILTERED'
    UNCERTAIN = 'UNCERTAIN'


@dataclass
class ValueInterval:
    """整数区间 [lo, hi]. lo 为下界, hi 为上界, 均为闭边界."""
    lo: int
    hi: int

    def width(self) -> int:
        return self.hi - self.lo

    def contains(self, value: int) -> bool:
        return self.lo <= value <= self.hi

    def __str__(self) -> str:
        if self.lo == self.hi:
            return str(self.lo)
        return f'[{self.lo}, {self.hi}]'


@dataclass
class EvidenceRecord:
    """单候选的裁决证据. 理由链与数值支撑均保留, 供审计."""
    verdict: Verdict
    reasons: List[str] = field(default_factory=list)
    alloc_requested: int = 0
    alloc_resolved: ValueInterval = None
    slack_usable: int = 0
    write_extent: ValueInterval = None
    guard_bound: int = -1
    confidence: float = 0.0
    provenance: str = ''

    def to_dict(self) -> dict:
        return {
            'verdict': self.verdict.value,
            'reasons': self.reasons,
            'alloc_requested': self.alloc_requested,
            'alloc_resolved': str(self.alloc_resolved) if self.alloc_resolved else '',
            'slack_usable': self.slack_usable,
            'write_extent': str(self.write_extent) if self.write_extent else '',
            'guard_bound': self.guard_bound,
            'confidence': round(self.confidence, 3),
            'provenance': self.provenance,
        }


@dataclass
class HovfStats:
    """堆溢出验证阶段统计. fp_reduction 与 recall_added 用于评估方法有效性."""
    base_candidates: int = 0
    new_channel_added: int = 0
    confirmed: int = 0
    filtered: int = 0
    uncertain: int = 0
    fp_reduction_ratio: float = 0.0
    recall_added: int = 0
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            'base_candidates': self.base_candidates,
            'new_channel_added': self.new_channel_added,
            'confirmed': self.confirmed,
            'filtered': self.filtered,
            'uncertain': self.uncertain,
            'fp_reduction_ratio': round(self.fp_reduction_ratio, 4),
            'recall_added': self.recall_added,
            'elapsed_ms': round(self.elapsed_ms, 1),
        }
