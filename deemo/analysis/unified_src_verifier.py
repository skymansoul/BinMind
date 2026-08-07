"""
统一源级验证器 (USV). 单入口整合5个验证器 → 并行检测 + 置信度融合 + 交叉验证.
输入一段C源码, 输出所有漏洞判定结果.
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from analysis.fmt_taint_verifier import FmtTaintVerifier
from analysis.fmt_taint_types import FmtVerdict
from analysis.int_overflow_src_verifier import IntOverflowSrcVerifier
from analysis.int_overflow_types import IovVerdict
from analysis.double_free_src_verifier import DoubleFreeSrcVerifier
from analysis.double_free_types import DfVerdict
from analysis.stack_overflow_src_verifier import StackOverflowSrcVerifier
from analysis.stack_overflow_types import SoVerdict
from analysis.sgav_pipeline import SGAVVerifier
from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_types import HoVerdict
from analysis.hosv_ext_verifier import HosvExtVerifier


class UsvVulnType(Enum):
    FMT = "format_string"
    IOV = "integer_overflow"
    DF = "double_free"
    SO = "stack_overflow"
    UAF = "use_after_free"
    HEAP = "heap_overflow"


@dataclass
class UsvFinding:
    vuln_type: UsvVulnType
    is_vuln: bool
    confidence: float = 0.0
    line: int = 0
    reason: str = ""
    cross_validated: bool = False  # 多验证器交叉确认


@dataclass
class UsvReport:
    source_file: str = ""
    findings: List[UsvFinding] = field(default_factory=list)
    vuln_count: int = 0
    safe_count: int = 0
    cross_validations: int = 0

    @property
    def has_critical(self) -> bool:
        return any(f.is_vuln and f.confidence >= 0.85 for f in self.findings)

    @property
    def summary(self) -> str:
        vulns = [f for f in self.findings if f.is_vuln]
        if not vulns: return "no vulnerabilities detected"
        return f"{len(vulns)} vuln(s): " + \
            ", ".join(f"{v.vuln_type.value}@L{v.line}({v.confidence:.0%})"
                       for v in sorted(vulns, key=lambda x: -x.confidence))


class UnifiedSrcVerifier:
    """统一源级验证 — 单次调用并行检测4类源码级漏洞 (UAF需二进制分析, 单独调用)."""

    def __init__(self):
        self._fmt = FmtTaintVerifier()
        self._iov = IntOverflowSrcVerifier()
        self._df = DoubleFreeSrcVerifier()
        self._so = StackOverflowSrcVerifier()
        self._sgav = SGAVVerifier()
        self._heap = HeapOverflowSrcVerifier()
        self._heap_ext = HosvExtVerifier()

    def verify(self, source: str, source_file: str = "") -> UsvReport:
        """并行检测4类源码级漏洞, 返回统一报告."""
        findings: List[UsvFinding] = []

        for r in self._fmt.verify(source):
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.FMT,
                is_vuln=r.verdict == FmtVerdict.VULN,
                confidence=self._fmt_conf(r), line=r.sink_line,
                reason=r.reason))

        for r in self._iov.verify(source):
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.IOV,
                is_vuln=r.verdict == IovVerdict.VULN,
                confidence=self._iov_conf(r), line=r.alloc_line,
                reason=r.reason))

        for r in self._df.verify(source):
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.DF,
                is_vuln=r.verdict == DfVerdict.VULN,
                confidence=r.confidence, line=r.free_line,
                reason=r.reason))

        # SGAV 为栈溢出主检测器; SOSV 作为补充保留
        sgav_results = self._sgav.verify(source)
        so_seen = set()
        for r in sgav_results:
            is_vuln = r.verdict.value == "VULN"
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.SO,
                is_vuln=is_vuln,
                confidence=max(r.confidence, 0.85) if is_vuln else r.confidence,
                line=r.write_line or r.buffer_line,
                reason=r.reason))
            so_seen.add((r.write_line, r.buf_name))
        # SOSV 补充: SGAV 未覆盖的检测结果
        for r in self._so.verify(source):
            key = (r.write_line, r.buf_name)
            if key in so_seen:
                continue
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.SO,
                is_vuln=r.verdict == SoVerdict.VULN,
                confidence=r.confidence, line=r.write_line or r.buffer_line,
                reason=r.reason))

        self._cross_validate(findings, source)

        # 堆溢出: 原验证器 + 写模式扩展, 仅保留明确 VULN
        heap_results = self._heap.verify(source)
        ext_results = self._heap_ext.verify(source)
        self._merge_heap(findings, heap_results, ext_results)

        vuln = [f for f in findings if f.is_vuln]
        return UsvReport(
            source_file=source_file, findings=findings,
            vuln_count=len(vuln),
            safe_count=len(findings) - len(vuln),
            cross_validations=sum(1 for f in findings if f.cross_validated))

    # 置信度映射

    @staticmethod
    def _fmt_conf(r) -> float:
        if r.verdict == FmtVerdict.SAFE: return 0.95
        if r.taint_paths: return min(0.95, 0.7 + 0.05 * len(r.taint_paths))
        return 0.60

    @staticmethod
    def _iov_conf(r) -> float:
        if r.guarded: return 0.95
        if r.verdict == IovVerdict.VULN:
            if r.value_range and r.value_range != 'UNKNOWN': return 0.90
            return 0.70
        return 0.80

    # 交叉验证

    def _merge_heap(self, findings: List[UsvFinding],
                    heap_results, ext_results) -> None:
        """合并两套堆溢出验证器的判定.

        两个验证器的 VULN 均保留. 扩展模块覆盖原 HOSV 缺失的
        写模式 (walk/struct_idx/unbounded_io/factory), 按告警点去重.
        """
        # 扩展结果优先 (覆盖更广)
        seen_keys = set()
        for r in ext_results:
            if r.verdict != "VULN":
                continue
            key = (r.alloc_line, r.write_line, r.var_name)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.HEAP,
                is_vuln=True,
                confidence=max(r.confidence, 0.75),
                line=r.write_line or r.alloc_line,
                reason="[HOSV-Ext:%s] %s" % (r.kind, r.reason)))
        for r in heap_results:
            if r.verdict != HoVerdict.VULN:
                continue
            key = (r.alloc_line, r.write_line, r.var_name)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(UsvFinding(
                vuln_type=UsvVulnType.HEAP,
                is_vuln=True,
                confidence=r.confidence,
                line=r.write_line or r.alloc_line,
                reason="[HOSV] %s" % r.reason))

    def _cross_validate(self, findings: List[UsvFinding], source: str) -> None:
        """IOV+SO联动: malloc(n*sizeof(T)) → stack copy → 双重风险."""
        iov_vulns = [f for f in findings if f.vuln_type == UsvVulnType.IOV and f.is_vuln]
        so_vulns = [f for f in findings if f.vuln_type == UsvVulnType.SO and f.is_vuln]
        if not iov_vulns or not so_vulns: return
        lines = source.splitlines()
        for iv in iov_vulns:
            for sv in so_vulns:
                if abs(iv.line - sv.line) <= 5:
                    iv.confidence = min(1.0, iv.confidence + 0.1)
                    iv.cross_validated = True
                    sv.confidence = min(1.0, sv.confidence + 0.05)
                    sv.cross_validated = True
                # malloc溢出 + memcpy到栈: 整数溢出导致栈溢出
                if sv.line > iv.line and sv.line - iv.line <= 20:
                    for l in lines[iv.line:sv.line]:
                        if re.search(r'\b(memcpy|strcpy|strncpy)\s*\(', l):
                            iv.confidence = min(1.0, iv.confidence + 0.1)
                            iv.cross_validated = True
                            sv.cross_validated = True
                            break


__all__ = ['UnifiedSrcVerifier', 'UsvReport', 'UsvFinding', 'UsvVulnType']
