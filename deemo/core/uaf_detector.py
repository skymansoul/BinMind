"""
UAF detector — static pointer lifecycle analysis.

Tracks heap pointer lifecycle (alloc→free→use) in decompiled code.
A use (dereference of the pointer or its derivatives) on a code path
after a free constitutes a UAF.

Unlike dynamic UAF detection (DangSan/FreeSentry), this does not require
program execution — pure static analysis suitable for binary auditing
without test cases. Cross-function tracking is limited by function-summary
completeness.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.pointer_state_machine import (
    PointerStateMachine, HeapPointer, PtrState, FunctionSummary,
)


@dataclass
class UAFFinding:
    function_name: str
    pointer_name: str
    alloc_site: str
    free_sites: List[str] = field(default_factory=list)
    use_after_free_sites: List[str] = field(default_factory=list)
    is_double_free: bool = False
    confidence: float = 0.0
    severity: str = "HIGH"


class UAFDetector:
    """UAF detector — static pointer lifecycle analysis.

    用法:
      uaf = UAFDetector()
      findings = uaf.detect(decompiled_code, function_name='process_request')
    """

    def __init__(self):
        self._psm = PointerStateMachine()

    def detect(self, code: str, function_name: str = "",
               callee_summaries: Optional[Dict[str, FunctionSummary]] = None
               ) -> List[UAFFinding]:
        """检测反编译代码中的UAF漏洞."""
        if callee_summaries:
            for summary in callee_summaries.values():
                self._psm.register_summary(summary)

        pointers = self._psm.analyze(code, function_name)
        findings = []

        for ptr in pointers:
            if ptr.state == PtrState.DANGLING:
                # 区分 UAF 和 double-free
                is_df = self._is_double_free(code, ptr)
                vuln_type = "double_free" if is_df else "use_after_free"

                # 找 free 之后的使用点
                free_max_idx = max(
                    [self._extract_line_idx(fs) for fs in ptr.free_sites],
                    default=-1,
                )
                uaf_sites = [
                    us for us in ptr.use_sites
                    if self._extract_line_idx(us) > free_max_idx
                ]

                findings.append(UAFFinding(
                    function_name=function_name,
                    pointer_name=ptr.name,
                    alloc_site=ptr.alloc_site,
                    free_sites=ptr.free_sites,
                    use_after_free_sites=uaf_sites,
                    is_double_free=is_df,
                    confidence=self._compute_confidence(ptr, uaf_sites),
                    severity="CRITICAL" if is_df else "HIGH",
                ))

        findings.sort(key=lambda f: f.confidence, reverse=True)
        return findings

    def _is_double_free(self, code: str, ptr: HeapPointer) -> bool:
        """判断是否为 double-free (同一指针被 free 两次)."""
        if len(ptr.free_sites) >= 2:
            return True
        return False

    def _extract_line_idx(self, site_label: str) -> int:
        try:
            return int(site_label.split('_')[1].split(':')[0])
        except (IndexError, ValueError):
            return -1

    def _compute_confidence(self, ptr: HeapPointer,
                            uaf_sites: List[str]) -> float:
        """基于证据强度计算置信度."""
        base = 0.50
        if uaf_sites:
            base += 0.20
        if ptr.alloc_site and ptr.free_sites:
            base += 0.15
        if len(ptr.free_sites) >= 2:
            base += 0.10  # double-free 证据更强
        return min(0.95, base)

    def batch_detect(self, functions: Dict[str, str],
                     summaries: Optional[Dict[str, FunctionSummary]] = None
                     ) -> Dict[str, List[UAFFinding]]:
        """批量检测多个函数."""
        return {
            fname: self.detect(code, fname, summaries)
            for fname, code in functions.items()
        }
