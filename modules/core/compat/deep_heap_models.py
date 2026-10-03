# coding: utf-8
"""
深度堆检测数据模型 — DeepHeapReport + LayerStats 纯数据类.

"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class LayerStats:
    """单层过滤统计."""
    name: str
    input_count: int = 0
    filtered: int = 0
    retained: int = 0
    duration_ms: float = 0.0
    details: List[str] = field(default_factory=list)


@dataclass
class DeepHeapReport:
    """深度堆溢出检测的完整报告."""
    sample_path: str = ''
    total_candidates: int = 0
    final_candidates: int = 0
    exploitable: int = 0
    layer_stats: List[LayerStats] = field(default_factory=list)
    total_duration_ms: float = 0.0
    reduction_rate: float = 0.0
    candidates: List[Dict] = field(default_factory=list)
    filtered_out: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sample': self.sample_path,
            'total_candidates': self.total_candidates,
            'final_candidates': self.final_candidates,
            'exploitable': self.exploitable,
            'reduction_rate': f'{self.reduction_rate:.1%}',
            'total_duration_ms': self.total_duration_ms,
            'layers': [
                {'name': s.name, 'in': s.input_count, 'filtered': s.filtered,
                 'retained': s.retained, 'ms': s.duration_ms}
                for s in self.layer_stats
            ],
            'exploitable_candidates': [
                {'addr': c.get('overflow_site', ''), 'confidence': c.get('confidence', 0),
                 'reason': c.get('reason', '')}
                for c in self.candidates if c.get('exploitable')
            ],
        }
