# coding: utf-8
"""
扫描调度. 对每个样本运行堆溢出验证器组合 (原 HOSV + 写模式扩展),
记录检出/漏报/误报状态与耗时, 供收集模块聚合.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_types import HoVerdict
from analysis.hosv_ext_verifier import HosvExtVerifier


@dataclass
class ScanOutcome:
    """单个样本的扫描结果."""
    sample_id: str = ""
    expected: str = ""           # 期望判定 VULN/SAFE
    any_heap_vuln: bool = False   # 任一套验证器报 VULN
    hosv_vuln: bool = False
    ext_vuln: bool = False
    vuln_reasons: List[str] = field(default_factory=list)
    time_ms: float = 0.0
    error: str = ""

    @property
    def is_true_positive(self) -> bool:
        return self.expected == "VULN" and self.any_heap_vuln

    @property
    def is_false_positive(self) -> bool:
        return self.expected == "SAFE" and self.any_heap_vuln

    @property
    def is_false_negative(self) -> bool:
        return self.expected == "VULN" and not self.any_heap_vuln

    @property
    def is_true_negative(self) -> bool:
        return self.expected == "SAFE" and not self.any_heap_vuln


class HosvScanScheduler:
    """堆溢出扫描调度器 — 串行扫描全部样本."""

    def __init__(self) -> None:
        self._hosv = HeapOverflowSrcVerifier()
        self._ext = HosvExtVerifier()

    def scan_source(self, sample_id: str, expected: str,
                    source: str) -> ScanOutcome:
        """扫描单一样本, 聚合两个验证器结果."""
        t0 = time.time()
        out = ScanOutcome(sample_id=sample_id, expected=expected)
        try:
            hosv_results = self._hosv.verify(source)
            ext_results = self._ext.verify(source)
        except Exception as e:  # noqa: BLE001
            out.error = str(e)
            out.time_ms = (time.time() - t0) * 1000
            return out
        out.time_ms = (time.time() - t0) * 1000

        seen = set()
        for r in hosv_results:
            if r.verdict != HoVerdict.VULN:
                continue
            key = (r.alloc_line, r.write_line, r.var_name)
            if key in seen:
                continue
            seen.add(key)
            out.hosv_vuln = True
            out.vuln_reasons.append("[HOSV] " + r.reason)
        for r in ext_results:
            if r.verdict != "VULN":
                continue
            key = (r.alloc_line, r.write_line, r.var_name)
            if key in seen:
                continue
            seen.add(key)
            out.ext_vuln = True
            out.vuln_reasons.append("[EXT:%s] %s" % (r.kind, r.reason))

        out.any_heap_vuln = out.hosv_vuln or out.ext_vuln
        return out


def scan_all(specs) -> List[ScanOutcome]:
    """扫描全部样本."""
    scheduler = HosvScanScheduler()
    outcomes = []
    for spec in specs:
        source = open(spec.src_path, "r", encoding="utf-8",
                      errors="replace").read()
        outcomes.append(scheduler.scan_source(
            spec.sample_id, spec.verdict, source))
    return outcomes


__all__ = ['ScanOutcome', 'HosvScanScheduler', 'scan_all']
