"""堆溢出FP过滤 — 三级级联: strided interval → path condition → heap shape.

在 core/heap_false_positive_filter 之上增加路径敏感和堆形状维度.
"""


from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_unbounded,
)


class FilterVerdict(Enum):
    KEEP = "KEEP"              # 确认真阳性
    FILTER = "FILTER"          # 确认为误报
    DEMOTE = "DEMOTE"          # 降置信度但不删除
    UNCERTAIN = "UNCERTAIN"    # 无法判定


@dataclass
class FilterDecision:
    """过滤决策 — 含多级推理链."""
    verdict: FilterVerdict
    confidence: float          # 真阳性置信度 [0, 1]
    fp_likelihood: float       # 误报概率 [0, 1]
    level: int                 # 做出决策的级数
    reasoning: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


class EnhancedHeapFPFilter:
    """增强堆溢出误报过滤器.

    三级级联, 每级独立可禁用.
    与 core/heap_false_positive_filter.py 互补, 不替代.
    """

    def __init__(self,
                 enable_interval: bool = True,
                 enable_path: bool = True,
                 enable_shape: bool = True,
                 platform: str = "x86_64"):
        self._enable_interval = enable_interval
        self._enable_path = enable_path
        self._enable_shape = enable_shape
        self._platform = platform

    def filter(self, alloc_size: int, write_size: int,
               pseudocode: str = "",
               func_name: str = "",
               alloc_sites: Optional[List[Dict]] = None,
               size_var: str = "size",
               write_offset: int = 0) -> FilterDecision:
        """执行三级级联过滤。

        pseudocode/alloc_sites 用于路径与堆形状分析;
        返回含 verdict/confidence/reasoning 链的 FilterDecision。
        """
        reasoning = []
        evidence = {}
        fp_accum = 0.0

# Level 1: Strided Interval
        if self._enable_interval:
            l1_result = self._filter_interval(alloc_size, write_size)
            evidence['L1_interval'] = l1_result
            reasoning.append(f"L1(interval): {l1_result['reason']}")
            if l1_result['verdict'] == 'FILTER':
                return FilterDecision(
                    FilterVerdict.FILTER, 0.10, 0.90, 1,
                    reasoning, evidence)
            fp_accum += l1_result.get('fp_contribution', 0.0)

# Level 2: Path Condition
        if self._enable_path and pseudocode:
            l2_result = self._filter_path(
                alloc_size, write_size, pseudocode, func_name, size_var)
            evidence['L2_path'] = l2_result
            reasoning.append(f"L2(path): {l2_result['reason']}")
            fp_accum += l2_result.get('fp_contribution', 0.0)

# Level 3: Heap Shape
        if self._enable_shape and alloc_sites:
            l3_result = self._filter_shape(
                alloc_size, write_size, alloc_sites, func_name,
                size_var, write_offset)
            evidence['L3_shape'] = l3_result
            reasoning.append(f"L3(shape): {l3_result['reason']}")
            fp_accum += l3_result.get('fp_contribution', 0.0)

        # 综合判定
        fp_likelihood = min(1.0, max(0.0, fp_accum))
        confidence = 1.0 - fp_likelihood

        if fp_likelihood >= 0.75:
            verdict = FilterVerdict.FILTER
        elif fp_likelihood >= 0.50:
            verdict = FilterVerdict.DEMOTE
        elif fp_likelihood <= 0.15:
            verdict = FilterVerdict.KEEP
        else:
            verdict = FilterVerdict.UNCERTAIN

        return FilterDecision(verdict, confidence, fp_likelihood, 3,
                              reasoning, evidence)

    # Level implementations

    def _filter_interval(self, alloc_size: int,
                         write_size: int) -> Dict[str, Any]:
        """Level 1: strided interval 分析.

        考虑分配器对齐后的有效大小.
        """
        try:
            from core.allocator_constraints import AllocSize
            actual = AllocSize.from_request(alloc_size, self._platform)
            effective = actual.effective
        except ImportError:
            effective = alloc_size + (16 - alloc_size % 16) % 16  # 简化对齐

        if write_size <= effective:
            return {
                'verdict': 'FILTER',
                'reason': (f"write({write_size}B) ≤ effective_chunk({effective}B) "
                           f"[req={alloc_size}B, align=16]"),
                'fp_contribution': 0.55,
                'effective_size': effective,
            }
        elif write_size <= alloc_size:
            return {
                'verdict': 'FILTER',
                'reason': f"write({write_size}B) ≤ requested({alloc_size}B)",
                'fp_contribution': 0.40,
                'effective_size': effective,
            }
        else:
            overflow = write_size - effective
            return {
                'verdict': 'KEEP',
                'reason': f"write({write_size}B) > effective({effective}B) by {overflow}B",
                'fp_contribution': 0.0,
                'effective_size': effective,
                'overflow_bytes': overflow,
            }

    def _filter_path(self, alloc_size: int, write_size: int,
                     pseudocode: str, func_name: str,
                     size_var: str) -> Dict[str, Any]:
        """Level 2: 路径条件分析."""
        try:
            from analysis.path_condition_tracker import (
                PathConditionTracker, path_sensitive_check)
            is_overflow, reason, fp_like = path_sensitive_check(
                pseudocode, alloc_size, write_size, size_var)
            return {
                'verdict': 'KEEP' if is_overflow else 'FILTER',
                'reason': reason,
                'fp_contribution': fp_like * 0.30,
                'is_overflow': is_overflow,
            }
        except ImportError:
            return {
                'verdict': 'UNCERTAIN',
                'reason': 'path_condition_tracker unavailable',
                'fp_contribution': 0.15,
                'is_overflow': True,
            }

    def _filter_shape(self, alloc_size: int, write_size: int,
                      alloc_sites: List[Dict], func_name: str,
                      source_var: str,
                      write_offset: int) -> Dict[str, Any]:
        """Level 3: 堆形状分析."""
        try:
            from analysis.heap_shape_model import HeapShapeModel
            model = HeapShapeModel()
            shape = model.build_shape(func_name, alloc_sites)
            assess = model.assess_overflow(
                shape, source_var, write_offset, write_size)

            fp_contrib = (1.0 - assess.exploitability) * 0.25
            return {
                'verdict': 'FILTER' if assess.is_false_positive else 'KEEP',
                'reason': assess.reasoning,
                'fp_contribution': fp_contrib,
                'exploitability': assess.exploitability,
            }
        except ImportError:
            return {
                'verdict': 'UNCERTAIN',
                'reason': 'heap_shape_model unavailable',
                'fp_contribution': 0.10,
                'exploitability': 0.5,
            }


def enhanced_filter_batch(
    findings: List[Dict[str, Any]],
    decompiled_map: Dict[str, str],
    platform: str = "x86_64",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """批量增强过滤 — 兼容现有 findings 格式."""
    filt = EnhancedHeapFPFilter(platform=platform)
    stats = {'total': len(findings), 'filtered': 0, 'kept': 0,
             'demoted': 0, 'uncertain': 0}

    for f in findings:
        func = f.get('function', f.get('func_name', ''))
        code = decompiled_map.get(func, '')
        alloc_sz = f.get('allocation_size', f.get('alloc_size', 0))
        write_sz = f.get('write_size', 0)
        size_var = f.get('size_var', f.get('result_var', ''))
        write_off = f.get('write_offset', 0)

        decision = filt.filter(
            alloc_sz, write_sz, code, func,
            size_var=size_var, write_offset=write_off,
        )

        f['enhanced_filter'] = {
            'verdict': decision.verdict.value,
            'confidence': decision.confidence,
            'fp_likelihood': decision.fp_likelihood,
            'level': decision.level,
            'reasoning': decision.reasoning,
        }

        if decision.verdict == FilterVerdict.FILTER:
            f['confidence'] = round(f.get('confidence', 0.5) * 0.25, 3)
            stats['filtered'] += 1
        elif decision.verdict == FilterVerdict.DEMOTE:
            f['confidence'] = round(f.get('confidence', 0.5) * 0.55, 3)
            stats['demoted'] += 1
        elif decision.verdict == FilterVerdict.KEEP:
            stats['kept'] += 1
        else:
            stats['uncertain'] += 1

    return findings, stats


__all__ = [
    'FilterVerdict', 'FilterDecision', 'EnhancedHeapFPFilter',
    'enhanced_filter_batch',
]
