"""
UAF 使用点验证 类型定义.

UAF 使用点验证 (Use-after-free re-verification with Value-Flow) 对 UAF 检测的
误报做复核: 基于分配-释放-使用事件链与值流门控, 给出
CONFIRMED/FILTERED/UNCERTAIN 三值裁决. 类型集中于此, 逻辑模块
只做分析, 避免循环导入.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class UafVerdict(Enum):
    """裁决结果. FILTERED 从输出移除, CONFIRMED/UNCERTAIN 保留."""
    CONFIRMED = 'CONFIRMED'
    FILTERED = 'FILTERED'
    UNCERTAIN = 'UNCERTAIN'


class EventKind(Enum):
    """事件类型. NULLIFY 指 free 后置 NULL, REASSIGN 指重新分配."""
    ALLOC = 'ALLOC'
    FREE = 'FREE'
    USE = 'USE'
    NULLIFY = 'NULLIFY'
    REASSIGN = 'REASSIGN'
    CALL = 'CALL'


@dataclass
class PtrEvent:
    """单条指针事件. operand 为变量名或 base.field 伪变量."""
    kind: EventKind
    operand: str
    pc: int
    detail: str = ''


@dataclass
class UafChain:
    """一次 free→use 事件链, 是 UAF 复核的最小单位."""
    operand: str
    free_pc: int
    use_pc: int
    free_line: str = ''
    use_line: str = ''
    aliases: List[str] = field(default_factory=list)


@dataclass
class UafEvidence:
    """单链复核证据. 记录裁决依据与数值支撑."""
    verdict: UafVerdict
    chain: UafChain
    reasons: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            'operand': self.chain.operand,
            'free_pc': self.chain.free_pc,
            'use_pc': self.chain.use_pc,
            'verdict': self.verdict.value,
            'reasons': self.reasons,
            'confidence': round(self.confidence, 3),
        }


@dataclass
class UovfStats:
    """UAF 使用点验证 阶段统计."""
    chains: int = 0
    confirmed: int = 0
    filtered: int = 0
    uncertain: int = 0
    fp_reduction_ratio: float = 0.0
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            'chains': self.chains,
            'confirmed': self.confirmed,
            'filtered': self.filtered,
            'uncertain': self.uncertain,
            'fp_reduction_ratio': round(self.fp_reduction_ratio, 4),
            'elapsed_ms': round(self.elapsed_ms, 1),
        }
