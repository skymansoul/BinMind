# 增强检测调度器-整合4个新检测模块到现有管线中
# 不改动任何现有文件，通过封装+增强实现检测精度提升
#
# 与原有gnn_vulnerability_detector.py的关系:
#   原有: PatternVulnerabilityDetector → 函数名匹配 → 高召回低精度
#   增强: 在原有输出上叠加taint/状态机/格式串/缓冲区验证 →
#         过滤误报 → 保持召回+提升精度
#
# 过滤策略(AND逻辑):
#   原有检测器报告为漏洞 AND 增强模块验证通过 → 保留
#   原有检测器报告为漏洞 AND 增强模块验证不通过 → 降级为"suspicious"
#   原有检测器未报告 → 不处理(保持召回率)

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

from ..taint.backward_taint import (
    BackwardTaintEngine, TaintLevel, TaintResult)
from .uaf_state_machine import (
    UAFStateMachine, PointerTracker)
from .format_string_check import (
    FormatStringChecker, FormatVulnLevel, FormatStringVerdict)
from .buffer_size_infer import (
    BufferSizeInferer, OverflowVerdict, BufferOverflowVerdict)

logger = logging.getLogger(__name__)


@dataclass
class EnhancedVulnReport:
    func_name: str
    vuln_type: str                # buffer_overflow / use_after_free / format_string
    original_score: float         # 原有检测器分数
    enhanced_score: float         # 增强后分数(验证通过=原分数, 未通过=原分数*0.3)
    is_verified: bool             # 是否通过增强验证
    evidence: List[str] = field(default_factory=list)
    taint_result: Optional[TaintResult] = None
    uaf_tracker: Optional[PointerTracker] = None
    format_verdict: Optional[FormatStringVerdict] = None
    overflow_verdict: Optional[BufferOverflowVerdict] = None


class EnhancedScanner:
    """增强检测调度器-整合污点传播+UAF状态机+格式串检查+缓冲区推断。

    使用方式:
      scanner = EnhancedScanner()
      results = scanner.scan_function(instructions, bb_boundaries, cfg_edges)
      # results是EnhancedVulnReport列表，可直接替换原有检测器的输出
    """

    def __init__(self):
        self._taint_engine = BackwardTaintEngine(max_trace_depth=5)
        self._uaf_sm = UAFStateMachine()
        self._fmt_checker = FormatStringChecker()
        self._buf_inferer = BufferSizeInferer(safety_margin=8)

    def scan_function(self,
                       instructions: List[str],
                       bb_boundaries: List[Tuple[int, int]],
                       cfg_edges: List[Tuple[int, int]],
                       func_name: str = "",
                       func_args: Optional[List[str]] = None,
                       original_alerts: Optional[List[Dict[str, Any]]] = None
                       ) -> List[EnhancedVulnReport]:
        """对单个函数执行增强检测。"""
        reports = []
        if original_alerts is None:
            original_alerts = []

        # 构建告警查找表
        alert_map: Dict[str, Dict] = {}
        for alert in original_alerts:
            vtype = alert.get('vuln_type', alert.get('type', ''))
            alert_map[vtype] = alert

        # 堆/栈溢出增强
        if 'buffer_overflow' in alert_map or not original_alerts:
            overflow_report = self._check_buffer_overflow(
                instructions, func_name,
                alert_map.get('buffer_overflow', {}))
            if overflow_report:
                reports.append(overflow_report)

        # UAF增强
        if 'use_after_free' in alert_map or not original_alerts:
            uaf_report = self._check_uaf(
                instructions, bb_boundaries, cfg_edges, func_args,
                alert_map.get('use_after_free', {}))
            if uaf_report:
                reports.append(uaf_report)

        # 格式化字符串增强
        if 'format_string' in alert_map or not original_alerts:
            fmt_report = self._check_format_string(
                instructions, func_name,
                alert_map.get('format_string', {}))
            if fmt_report:
                reports.append(fmt_report)

        return reports

    def _check_buffer_overflow(self,
                                instructions: List[str],
                                func_name: str,
                                original_alert: Dict
                                ) -> Optional[EnhancedVulnReport]:
        """增强堆/栈溢出检测-污点传播+缓冲区大小验证"""
        evidence = []
        taint_result = None
        overflow_verdict = None
        is_verified = False

        # 找所有危险拷贝函数调用
        copy_funcs = {'memcpy', 'strcpy', 'strncpy', 'sprintf', 'memmove'}
        for i, instr in enumerate(instructions):
            for cf in copy_funcs:
                if cf in instr.lower() and 'call' in instr.lower():
                    # a: 污点追踪-检查dst参数是否TAINTED
                    taint_result = self._taint_engine.trace_param(
                        i, 'rdi', instructions)
                    if self._taint_engine.is_vulnerable_sink(taint_result):
                        evidence.append(
                            f"copy dst tainted: {taint_result.source_origin}")
                        is_verified = True

                    # b: 缓冲区大小验证-比较分配大小和拷贝大小
                    # 向前查找最近的malloc调用
                    alloc_idx = self._find_nearest_alloc(instructions, i)
                    if alloc_idx >= 0:
                        for af in ('malloc', 'calloc', 'realloc'):
                            if af in instructions[alloc_idx].lower():
                                overflow_verdict = self._buf_inferer.check_overflow(
                                    alloc_idx, af, i, cf, instructions)
                                if overflow_verdict.verdict in (
                                    OverflowVerdict.CONFIRMED_OVERFLOW,
                                    OverflowVerdict.POTENTIAL_OVERFLOW):
                                    evidence.append(overflow_verdict.evidence)
                                    is_verified = True
                    break

        orig_score = original_alert.get('confidence', 0.5)
        return EnhancedVulnReport(
            func_name=func_name,
            vuln_type='buffer_overflow',
            original_score=orig_score,
            enhanced_score=orig_score if is_verified else orig_score * 0.3,
            is_verified=is_verified,
            evidence=evidence,
            taint_result=taint_result,
            overflow_verdict=overflow_verdict)

    def _check_uaf(self,
                    instructions: List[str],
                    bb_boundaries: List[Tuple[int, int]],
                    cfg_edges: List[Tuple[int, int]],
                    func_args: Optional[List[str]],
                    original_alert: Dict
                    ) -> Optional[EnhancedVulnReport]:
        """增强UAF检测-状态机验证"""
        trackers = self._uaf_sm.analyze_function(
            instructions, bb_boundaries, cfg_edges, func_args)
        vuln_trackers = [t for t in trackers if t.is_vulnerable]

        orig_score = original_alert.get('confidence', 0.5)
        is_verified = len(vuln_trackers) > 0
        evidence = []
        uaf_tracker = None

        if is_verified:
            uaf_tracker = vuln_trackers[0]
            evidence.append(
                f"UAF: {uaf_tracker.ptr_name} alloc@{uaf_tracker.alloc_site} "
                f"free@{uaf_tracker.free_site} use@{uaf_tracker.use_sites}")
        elif trackers:
            # 有free但无use-降级
            freed = [t for t in trackers if t.state.name == 'FREED']
            if freed:
                evidence.append(
                    f"free detected but no post-free use found ({len(freed)} ptrs freed)")

        return EnhancedVulnReport(
            func_name=instructions[0].split()[0] if instructions else 'unknown',
            vuln_type='use_after_free',
            original_score=orig_score,
            enhanced_score=orig_score if is_verified else orig_score * 0.2,
            is_verified=is_verified,
            evidence=evidence,
            uaf_tracker=uaf_tracker)

    def _check_format_string(self,
                              instructions: List[str],
                              func_name: str,
                              original_alert: Dict
                              ) -> Optional[EnhancedVulnReport]:
        """增强格式化字符串检测-参数来源验证"""
        evidence = []
        fmt_verdict = None
        is_verified = False

        for i, instr in enumerate(instructions):
            for ff in FormatStringChecker._FORMAT_FUNCS:
                if ff in instr.lower() and 'call' in instr.lower():
                    fmt_verdict = self._fmt_checker.check_call(
                        i, instructions, ff)
                    if fmt_verdict.vuln_level == FormatVulnLevel.VULNERABLE:
                        is_verified = True
                        evidence.extend(fmt_verdict.evidence)
                    elif fmt_verdict.vuln_level == FormatVulnLevel.SUSPICIOUS:
                        evidence.extend(fmt_verdict.evidence)
                        evidence.append('降级为suspicious-无法确认fmt来源')
                    else:
                        evidence.append(f'fmt is const → safe: {fmt_verdict.fmt_origin}')
                    break

        orig_score = original_alert.get('confidence', 0.5)
        return EnhancedVulnReport(
            func_name=func_name,
            vuln_type='format_string',
            original_score=orig_score,
            enhanced_score=orig_score if is_verified else orig_score * 0.1,
            is_verified=is_verified,
            evidence=evidence,
            format_verdict=fmt_verdict)

    def _find_nearest_alloc(self,
                             instructions: List[str],
                             copy_idx: int) -> int:
        """在copy指令之前查找最近的内存分配调用"""
        for j in range(copy_idx - 1, max(-1, copy_idx - 30), -1):
            if j < 0 or j >= len(instructions):
                continue
            instr = instructions[j].lower()
            if 'call' in instr and any(
                af in instr for af in ('malloc', 'calloc', 'realloc')):
                return j
        return -1
