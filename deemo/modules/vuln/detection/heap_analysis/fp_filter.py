"""
堆溢出误报过滤器 — 基于 size_tracker 的数据流证据做最终判定。

策略:
  1. 从 size_tracker 接收带约束证据的发现列表
  2. can_prove_safe=True → 直接筛除 (高置信误报)
  3. constraint_evidence="size unknown" → 保留但不标 confirmed
  4. 输出过滤后的发现 + 过滤统计

与 false_positive_filter.py 的分工:
  false_positive_filter: 基于汇编模式的统计评分 (先验知识)
  本模块: 基于数据流约束的逻辑判定 (程序语义)

修改记录:
  创建 2026-08-05
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from modules.vuln.detection.heap_analysis.size_tracker import (
    HeapOverflowWithTrace, track_allocation_to_write
)


@dataclass
class FilterResult:
    kept: List[HeapOverflowWithTrace] = field(default_factory=list)
    filtered: List[HeapOverflowWithTrace] = field(default_factory=list)
    total_raw: int = 0
    fp_reduction_pct: float = 0.0

    def summary(self) -> Dict[str, Any]:
        return {
            'raw_findings': self.total_raw,
            'kept': len(self.kept),
            'filtered_as_fp': len(self.filtered),
            'fp_reduction_rate': round(self.fp_reduction_pct, 1),
        }


def filter_heap_findings(
    instructions: List[str],
    known_constants: Optional[Dict[str, int]] = None,
) -> FilterResult:
    """
    运行 size_tracker → 过滤可证明安全的 → 返回 FilterResult。
    """
    traces = track_allocation_to_write(instructions, known_constants)
    result = FilterResult(total_raw=len(traces))

    for t in traces:
        if t.can_prove_safe:
            result.filtered.append(t)
        else:
            result.kept.append(t)

    if result.total_raw > 0:
        result.fp_reduction_pct = round(
            len(result.filtered) / result.total_raw * 100, 1)

    return result
