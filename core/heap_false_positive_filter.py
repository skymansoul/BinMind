"""
堆溢出误报过滤器 — value-flow + 分配器约束两级过滤。
第一级追踪 size 的 value-flow 得类型/约束/上界, 第二级应用 glibc 分配器语义
判 KEEP/FILTER; 静态分析结合分配器语义, 在不降召回的前提下压缩误报。
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.heap_flow_tracker import HeapFlowTracker, SizeSource, TraceResult
from core.allocator_constraints import (
    AllocSize, AllocatorConstraintChecker, ReallocCheck,
)

@dataclass
class FilteredFinding:
    """过滤后的单个堆操作评估。"""
    trace: TraceResult
    write_size: int
    verdict: str        # "KEEP" | "FILTER" | "UNCERTAIN"
    reason: str
    actual_alloc: int    # 分配器实际分配的可用字节数
    fp_likelihood: float  # 误报概率 [0,1], 0=确定真阳性, 1=确定误报

class HeapFalsePositiveFilter:
    """堆溢出误报过滤器 — 按来源分流: 常量约束→分配器容量检查, 用户输入未约束→KEEP。"""

    def __init__(self, platform: str = "x86_64"):
        self._tracker = HeapFlowTracker()
        self._checker = AllocatorConstraintChecker(platform)

    def filter(
        self, pseudocode: str, write_size: int = 0, func_name: str = "",
    ) -> List[FilteredFinding]:
        """过滤伪代码中的堆溢出候选; write_size 为0表示未知, 过滤层退化为 PASS-THROUGH。"""
        traces = self._tracker.trace(pseudocode)
        findings = []

        for t in traces:
            if write_size <= 0:
                # 未知写入大小 → 无法过滤, 保留
                findings.append(FilteredFinding(
                    trace=t, write_size=0, verdict="KEEP",
                    reason="write_size unknown, pass-through",
                    actual_alloc=0, fp_likelihood=0.5,
                ))
                continue

            # 核心决策逻辑
            if t.source_type == SizeSource.CONSTANT:
                size_val = int(t.size_var.strip()) if t.size_var.strip().isdigit() else 0
                if size_val <= 0:
                    findings.append(self._uncertain(t, write_size, "constant parse failed"))
                    continue
                actual = AllocSize.from_request(size_val)
                verdict = self._checker.check_overflow(size_val, write_size, t.alloc_func)
                reason = (
                    f"CONSTANT alloc={size_val}B effective={actual.effective}B "
                    f"write={write_size}B → {verdict}"
                )
                fp = 0.05 if verdict == "KEEP" else (0.85 if verdict == "FILTER" else 0.40)
                findings.append(FilteredFinding(
                    trace=t, write_size=write_size, verdict=verdict,
                    reason=reason, actual_alloc=actual.effective,
                    fp_likelihood=fp,
                ))

            elif t.is_constrained and t.upper_bound is not None:
                actual = AllocSize.from_request(t.upper_bound)
                verdict = self._checker.check_upper_bound(t.upper_bound, write_size, t.alloc_func)
                reason = (
                    f"CONSTRAINED upper_bound={t.upper_bound}B "
                    f"effective={actual.effective}B write={write_size}B → {verdict}"
                )
                fp = 0.10 if verdict == "KEEP" else (0.80 if verdict == "FILTER" else 0.35)
                findings.append(FilteredFinding(
                    trace=t, write_size=write_size, verdict=verdict,
                    reason=reason, actual_alloc=actual.effective,
                    fp_likelihood=fp,
                ))

            elif t.source_type == SizeSource.USER_INPUT:
                findings.append(FilteredFinding(
                    trace=t, write_size=write_size, verdict="KEEP",
                    reason="USER_INPUT not constrained → potential true positive",
                    actual_alloc=0, fp_likelihood=0.05,
                ))

            else:
                findings.append(self._uncertain(t, write_size, "unknown source type"))

        return findings

    def _uncertain(self, t: TraceResult, ws: int, msg: str) -> FilteredFinding:
        return FilteredFinding(
            trace=t, write_size=ws, verdict="UNCERTAIN",
            reason=msg, actual_alloc=0, fp_likelihood=0.50,
        )

    def filter_batch(
        self, functions: Dict[str, str], write_sizes: Dict[str, int],
    ) -> Dict[str, List[FilteredFinding]]:
        """批量过滤多个函数。"""
        return {
            fname: self.filter(code, write_sizes.get(fname, 0), fname)
            for fname, code in functions.items()
        }

    @staticmethod
    def summarize(findings: List[FilteredFinding]) -> Dict[str, int]:
        """统计过滤结果。"""
        counts = {"KEEP": 0, "FILTER": 0, "UNCERTAIN": 0}
        for f in findings:
            counts[f.verdict] += 1
        return counts

__all__ = ['FilteredFinding', 'HeapFalsePositiveFilter']
