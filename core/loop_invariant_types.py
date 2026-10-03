"""循环不变式分层证明数据类型 — 分层安全证明器的类型与证明结果定义。
循环不变式分层证明在后向值流返回INCONCLUSIVE时触发，追加路径条件传播/谓词不变式推导/
分配器语义对齐三层证明；无法判定时返回INCONCLUSIVE_RETAIN，不影响召回率。"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class LSPVerdict(Enum):
    PROVEN_SAFE = "lsp_safe"
    PROVEN_OVERFLOW = "lsp_overflow"
    INCONCLUSIVE_RETAIN = "lsp_inconclusive"


class LSPProofLayer(Enum):
    PATH_CONDITION = "path_condition"
    INVARIANT_INFERENCE = "invariant"
    ALLOCATOR_ALIGNMENT = "allocator_align"


@dataclass
class PathPredicate:
    """路径谓词: 变量上的单变量线性约束."""
    var: str
    bound: float
    operator: str  # '<=', '<', '>=', '>'
    origin_line: int
    condition_text: str = ""

    def implies_upper_bound(self, var: str) -> Optional[float]:
        """若谓词约束了var的上界, 返回上界值."""
        if self.var != var:
            return None
        if self.operator in ('<=', '<'):
            return self.bound
        return None

    def implies_lower_bound(self, var: str) -> Optional[float]:
        if self.var != var:
            return None
        if self.operator in ('>=', '>'):
            return self.bound
        return None


@dataclass
class LSPProofResult:
    """分层安全证明器的判定结果."""
    verdict: LSPVerdict = LSPVerdict.INCONCLUSIVE_RETAIN
    proven_layer: Optional[LSPProofLayer] = None
    reason: str = ""
    confidence_delta: float = 0.0
    proof_chain: List[str] = field(default_factory=list)
    predicates_collected: List[PathPredicate] = field(default_factory=list)
    invariants_derived: Dict[str, str] = field(default_factory=dict)


@dataclass
class LSPStats:
    """循环不变式分层证明运行统计."""
    total_triggered: int = 0
    proven_safe: int = 0
    proven_overflow: int = 0
    inconclusive: int = 0
    layer_counts: Dict[str, int] = field(default_factory=dict)

    def record(self, result: LSPProofResult) -> None:
        self.total_triggered += 1
        if result.verdict == LSPVerdict.PROVEN_SAFE:
            self.proven_safe += 1
        elif result.verdict == LSPVerdict.PROVEN_OVERFLOW:
            self.proven_overflow += 1
        else:
            self.inconclusive += 1
        layer = result.proven_layer
        if layer is not None:
            key = layer.value
            self.layer_counts[key] = self.layer_counts.get(key, 0) + 1


__all__ = [
    'LSPVerdict', 'LSPProofLayer', 'PathPredicate',
    'LSPProofResult', 'LSPStats',
]
