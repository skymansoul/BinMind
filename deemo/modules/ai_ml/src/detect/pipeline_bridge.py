# 检测管线桥接——旧3阶段粗过滤 + 新4阶段精过滤 + UAF/FMT/INTOVF独立管线
# 组合逻辑: 旧CONFIRMED+新TRUE_POSITIVE→置信提升; 旧CONFIRMED+新FALSE_POSITIVE→降级
# 新增FINDING: 旧FILTERED+新TRUE_POSITIVE→旧漏检提升

from __future__ import annotations

import sys
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# analysis/包路径
_AI_ML_ROOT = Path(__file__).parent.parent.parent
if str(_AI_ML_ROOT) not in sys.path:
    sys.path.insert(0, str(_AI_ML_ROOT))

from .heap_overflow_filter import (
    HeapOverflowFilter, HeapOverflowReport, FilterVerdict)
from analysis.heap_fp_filter import (
    HeapFalsePositiveFilter, FilterDecision, FilterEvidence)
from .crt_function_filter import is_crt_function
from .analysis.enhanced_uaf_filter import (
    EnhancedUafFilter, UafVerdict, EnhancedUafReport)
from .analysis.enhanced_fmt_filter import (
    EnhancedFmtFilter, FmtVerdict, EnhancedFmtReport)
from .analysis.int_overflow_deep import (
    IntOverflowDeepAnalyzer, OverflowRisk, DeepOverflowReport)
from .analysis.cross_function_tracker import (
    CrossFunctionTracker, CrossFunctionMap)
from .analysis.cross_function_heap_tracker import (
    CrossFunctionHeapTracker, FuncSummary)
try:
    from analysis.dcg_post_filter import (
        DCGPostFilter, DCGFilterDecision, DCGFilterReport)
except ImportError:
    # dcg_post_filter 尚未实现——占位
    DCGPostFilter = None  # type: ignore
    DCGFilterDecision = None  # type: ignore
    DCGFilterReport = None  # type: ignore

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class CombinedVerdict(Enum):
    CONFIRMED = 'confirmed'       # 双管线确认——高置信真漏洞
    LIKELY = 'likely'             # 单管线确认——值得关注
    UNCERTAIN = 'uncertain'       # 无法确定——建议人工审查
    FILTERED = 'filtered'         # 双管线排除——确认为误报
    NEW_FINDING = 'new_finding'   # 旧管线漏检, 新管线发现
    UAF_CONFIRMED = 'uaf_confirmed'       # UAF三阶段管线确认
    UAF_LIKELY = 'uaf_likely'             # UAF两阶段通过
    UAF_CROSS_FUNC = 'uaf_cross_func'     # UAF跨函数检测
    HEAP_CROSS_FUNC = 'heap_cross_func'   # 堆跨函数alloc-copy配对检测
    FMT_CONFIRMED = 'fmt_confirmed'       # 格式串三阶段管线确认
    FMT_LIKELY = 'fmt_likely'             # 格式串两阶段通过
    INTOVF_CONFIRMED = 'intovf_confirmed'   # 整数溢出确认
    INTOVF_LIKELY = 'intovf_likely'         # 整数溢出可能


@dataclass
class CombinedReport:
    """旧3阶段+新4阶段+UAF/FMT/INTOVF组合报告"""
    func_name: str
    sink_instr_idx: int
    sink_func: str
    old_report: Optional[HeapOverflowReport] = None
    old_verdict: FilterVerdict = FilterVerdict.FILTERED
    new_decision: FilterDecision = FilterDecision.INCONCLUSIVE
    new_evidence: Optional[FilterEvidence] = None
    uaf_report: Optional[EnhancedUafReport] = None
    fmt_report: Optional[EnhancedFmtReport] = None
    intovf_report: Optional[DeepOverflowReport] = None
    combined_verdict: CombinedVerdict = CombinedVerdict.UNCERTAIN
    confidence: float = 0.0
    reason: str = ""


class DetectionPipeline:
    """完整检测管线——旧3阶段+新4阶段+UAF/FMT/INTOVF 6管线组合"""

    def __init__(self):
        self._old_filter = HeapOverflowFilter()
        self._new_filter = HeapFalsePositiveFilter(arch='x86_64')
        self._uaf_filter = EnhancedUafFilter()
        self._fmt_filter = EnhancedFmtFilter()
        self._intovf_filter = IntOverflowDeepAnalyzer()
        self._dcg_post = DCGPostFilter(safety_margin=16) if DCGPostFilter else None

    def scan_function(self, instructions: List[str],
                      bb_boundaries: List[Tuple[int, int]],
                      cfg_edges: List[Tuple[int, int]],
                      func_name: str = "") -> List[CombinedReport]:
        """6管线并行检测:旧3阶段+新4阶段+UAF+FMT+INTOVF+新sink扫描"""
        if is_crt_function(func_name):
            return []
        old_reports = self._old_filter.analyze_function(instructions, bb_boundaries, cfg_edges, func_name)
        combined = [self._evaluate_sink(r, instructions, bb_boundaries, cfg_edges) for r in old_reports]
        combined.extend(self._scan_new_sinks(instructions, bb_boundaries, cfg_edges, func_name, old_reports))
        combined.extend(self._scan_uaf(instructions, bb_boundaries, cfg_edges, func_name))
        combined.extend(self._scan_fmt(instructions, bb_boundaries, cfg_edges, func_name))
        combined.extend(self._scan_int_overflow(instructions, bb_boundaries, cfg_edges, func_name))
        return combined

    def _evaluate_sink(self, old_r: HeapOverflowReport,
                       instructions: List[str],
                       bb_boundaries: List[Tuple[int, int]],
                       cfg_edges: List[Tuple[int, int]]) -> CombinedReport:
        """双管线评估:旧3阶段+新4阶段→组合裁决"""
        cr = CombinedReport(func_name=old_r.func_name, sink_instr_idx=old_r.sink_instr_idx,
                            sink_func=old_r.sink_func, old_report=old_r, old_verdict=old_r.verdict)
        if old_r.alloc_site is None or old_r.copy_site is None:
            cr.combined_verdict = self._map_verdict(old_r.verdict)
            cr.reason = "no alloc-copy pair→old verdict only"
            return cr
        alloc_func = self._identify_alloc_func(old_r.alloc_site, instructions)
        if alloc_func is None:
            cr.combined_verdict = self._map_verdict(old_r.verdict)
            cr.reason = "alloc func not identified"
            return cr
        try:
            decision, evidence = self._new_filter.evaluate(
                old_r.alloc_site, old_r.copy_site, alloc_func, old_r.sink_func,
                instructions, bb_boundaries, cfg_edges)
        except Exception as e:
            logger.debug("4-stage filter error: %s", e)
            decision, evidence = FilterDecision.INCONCLUSIVE, None
        cr.new_decision, cr.new_evidence = decision, evidence
        # 组合裁决表: (old_verdict, new_decision)→(combined_verdict, confidence, reason)
        is_pos = old_r.verdict in (FilterVerdict.CONFIRMED, FilterVerdict.LIKELY)
        new_d = decision
        if is_pos and new_d == FilterDecision.TRUE_POSITIVE:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.CONFIRMED, 0.9, "dual pipeline confirm"
        elif is_pos and new_d == FilterDecision.FALSE_POSITIVE:
            basis = (evidence.decision_basis[-1] if evidence and evidence.decision_basis else "false positive")
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.FILTERED, 0.1, f"4-stage overrides: {basis}"
        elif is_pos:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.LIKELY, 0.6, "old positive, new inconclusive"
        elif old_r.verdict == FilterVerdict.UNCERTAIN and new_d == FilterDecision.TRUE_POSITIVE:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.LIKELY, 0.7, "old uncertain, new confirms"
        elif old_r.verdict == FilterVerdict.UNCERTAIN and new_d == FilterDecision.FALSE_POSITIVE:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.FILTERED, 0.2, "old uncertain, new filters"
        elif old_r.verdict == FilterVerdict.UNCERTAIN:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.UNCERTAIN, 0.4, "both uncertain"
        elif new_d == FilterDecision.TRUE_POSITIVE:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.NEW_FINDING, 0.65, "old filtered, new finds"
        else:
            cr.combined_verdict, cr.confidence, cr.reason = CombinedVerdict.FILTERED, 0.05, "both pipelines filter"

        # DCG后过滤——对仍为正向的堆溢出报告做二次验证
        # 当4-stage管线未能过滤(INCONCLUSIVE/TRUE_POSITIVE)时, DCG独立验证
        _POS = (CombinedVerdict.CONFIRMED, CombinedVerdict.LIKELY, CombinedVerdict.NEW_FINDING)
        if (self._dcg_post is not None and cr.combined_verdict in _POS
                and old_r.alloc_site is not None and old_r.copy_site is not None):
            try:
                dcg_r = self._dcg_post.verify(
                    old_r.alloc_site, old_r.copy_site, alloc_func, old_r.sink_func,
                    instructions, bb_boundaries, cfg_edges)
                if dcg_r.is_safe:
                    cr.combined_verdict = CombinedVerdict.FILTERED
                    cr.confidence = 0.08
                    cr.reason = f"DCG post-filter: {'; '.join(dcg_r.evidence[-3:])}"
            except Exception:
                pass

        return cr

    def _scan_new_sinks(self, instructions, bb_boundaries, cfg_edges, func_name, old_reports):
        """新管线独立扫描——旧管线已覆盖所有copy sink, 暂无扩展逻辑"""
        return []

    def _scan_uaf(self, instructions, bb_boundaries, cfg_edges, func_name):
        """UAF三阶段管线(别名+路径+严重性)——含free()函数触发"""
        if not any('call' in i.lower() and 'free' in i.lower() for i in instructions):
            return []
        try:
            uaf_reports = self._uaf_filter.analyze(instructions, bb_boundaries, cfg_edges, func_name)
        except Exception:
            return []
        combined = []
        for ur in uaf_reports:
            if ur.verdict in (UafVerdict.CONFIRMED, UafVerdict.LIKELY):
                cv = CombinedVerdict.UAF_CONFIRMED if ur.verdict == UafVerdict.CONFIRMED else CombinedVerdict.UAF_LIKELY
                sidx = ur.alias_sets[0].free_sites[0] if ur.alias_sets and ur.alias_sets[0].free_sites else 0
                combined.append(CombinedReport(func_name=func_name, sink_instr_idx=sidx,
                    sink_func='free', uaf_report=ur, combined_verdict=cv,
                    confidence=ur.confidence, reason=f"UAF: {'; '.join(ur.evidence[:3])}"))
        return combined

    def _scan_fmt(self, instructions, bb_boundaries, cfg_edges, func_name):
        """格式串三阶段管线——含printf系列调用触发"""
        _FMT_SET = {'printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf', 'vprintf',
                    'vfprintf', 'vsprintf', 'syslog', '__printf_chk', '__fprintf_chk'}
        if not any('call' in i.lower() and any(f in i.lower() for f in _FMT_SET) for i in instructions):
            return []
        try:
            fmt_reports = self._fmt_filter.analyze(instructions, bb_boundaries, cfg_edges, func_name)
        except Exception:
            return []
        combined = []
        for fr in fmt_reports:
            if fr.verdict in (FmtVerdict.CONFIRMED, FmtVerdict.LIKELY):
                cv = CombinedVerdict.FMT_CONFIRMED if fr.verdict == FmtVerdict.CONFIRMED else CombinedVerdict.FMT_LIKELY
                sidx = fr.fmt_calls[0].call_idx if fr.fmt_calls else 0
                combined.append(CombinedReport(func_name=func_name, sink_instr_idx=sidx,
                    sink_func='printf', fmt_report=fr, combined_verdict=cv,
                    confidence=fr.confidence, reason=f"FMT: {'; '.join(fr.evidence[:3])}"))
        return combined

    def _scan_int_overflow(self, instructions, bb_boundaries, cfg_edges, func_name):
        """整数溢出深层分析——含算术运算+分配触发"""
        instr_text = ' '.join(instructions).lower()
        if not (any(op in instr_text for op in ('add', 'sub', 'imul', 'shl'))
                and any(af in instr_text for af in ('malloc', 'calloc', 'realloc'))):
            return []
        try:
            intovf_reports = self._intovf_filter.analyze_function(instructions, func_name)
        except Exception:
            return []
        combined = []
        for ir in intovf_reports:
            if ir.risk in (OverflowRisk.CONFIRMED, OverflowRisk.LIKELY):
                cv = CombinedVerdict.INTOVF_CONFIRMED if ir.risk == OverflowRisk.CONFIRMED else CombinedVerdict.INTOVF_LIKELY
                ctx = ir.contexts[0] if ir.contexts else None
                combined.append(CombinedReport(func_name=func_name,
                    sink_instr_idx=ctx.op_idx if ctx else 0, sink_func='malloc',
                    intovf_report=ir, combined_verdict=cv,
                    confidence=ir.confidence, reason=f"INTOVF: {'; '.join(ir.evidence[:3])}"))
        return combined

    def scan_cross_function(self, cmap: CrossFunctionMap) -> List[CombinedReport]:
        """跨函数全局UAF检测——同一全局指针在不同函数中free+use"""
        if not cmap or not cmap.globals:
            return []
        tracker = CrossFunctionTracker()
        findings = tracker.detect_cross_function_uaf(cmap)
        combined = []
        for f in findings:
            free_funcs = f['free_funcs']
            use_funcs = f['use_funcs']
            combined.append(CombinedReport(
                func_name=use_funcs[0] if use_funcs else 'unknown',
                sink_instr_idx=0, sink_func='free',
                combined_verdict=CombinedVerdict.UAF_CROSS_FUNC,
                confidence=f['confidence'],
                reason=f"cross-func UAF: global {f['global_ref']}; "
                       f"{'; '.join(f['evidence'][:3])}"))
        return combined

    def scan_cross_function_heap(self, functions: List) -> List[CombinedReport]:
        """跨函数堆溢出检测——alloc/copy wrapper配对 + 调用点数据流合成"""
        if not functions:
            return []
        tracker = CrossFunctionHeapTracker()
        summaries = tracker.build_summaries(functions)
        if not summaries:
            return []
        findings = tracker.detect(functions, summaries)
        combined = []
        for f in findings:
            combined.append(CombinedReport(
                func_name=f.get('func_name', 'unknown'),
                sink_instr_idx=0, sink_func=f.get('copy_func', 'memcpy'),
                combined_verdict=CombinedVerdict.HEAP_CROSS_FUNC,
                confidence=f['confidence'],
                reason=f"cross-func heap: {f.get('alloc_wrapper','')}(alloc)→"
                       f"{f.get('copy_wrapper','')}(copy); "
                       f"{'; '.join(f.get('evidence', [])[:3])}"))
        return combined

    def _identify_alloc_func(self, idx: int, instructions: List[str]) -> Optional[str]:
        if 0 <= idx < len(instructions):
            instr = instructions[idx].lower()
            for af in ('malloc', 'calloc', 'realloc', 'alloca'):
                if af in instr:
                    return af
        return None

    _VERDICT_MAP = {FilterVerdict.CONFIRMED: CombinedVerdict.LIKELY,
                    FilterVerdict.LIKELY: CombinedVerdict.UNCERTAIN,
                    FilterVerdict.UNCERTAIN: CombinedVerdict.UNCERTAIN,
                    FilterVerdict.FILTERED: CombinedVerdict.FILTERED}

    def _map_verdict(self, old_v: FilterVerdict) -> CombinedVerdict:
        return self._VERDICT_MAP.get(old_v, CombinedVerdict.UNCERTAIN)

    def get_statistics(self, results: List[CombinedReport]) -> Dict[str, int]:
        stats = {v.value: 0 for v in CombinedVerdict}
        for r in results:
            stats[r.combined_verdict.value] += 1
        stats['total'] = len(results)
        stats['old_fp_count'] = sum(1 for r in results if r.old_verdict == FilterVerdict.FILTERED)
        stats['new_fp_count'] = sum(1 for r in results if r.combined_verdict == CombinedVerdict.FILTERED)
        return stats
