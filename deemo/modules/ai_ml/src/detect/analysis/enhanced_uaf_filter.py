# 增强UAF过滤器——整合别名追踪+路径分析+状态机的三阶段UAF检测管线
# 原有uaf_state_machine.py: 单函数mov rdi, reg匹配free目标
#   缺陷1: 寄存器别名丢失——ptr→rbx→free(rbx)后使用ptr不检测
#   缺陷2: 无条件假设free必然执行——条件分支内free误报
#   缺陷3: 无跨函数use检测——free后传递给其他函数的指针未追踪
#
# 改进(三阶段管线):
#   阶段1(UafAliasTracker): 寄存器别名图+传递闭包→间接free/use检测
#   阶段2(UafPathAnalyzer): 条件free识别+置信度降级→减少误报
#   阶段3(UAFDeepAnalyzer): 跨函数use+堆上下文→提升召回
#
# 判定规则: 三阶段综合→CONFIRMED/LIKELY/UNCERTAIN/FILTERED

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .uaf_alias_tracker import (
    UafAliasTracker, AliasSet)
from .uaf_path_analyzer import (
    UafPathAnalyzer, PathContext, FreeCertainty)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class UafVerdict(Enum):
    CONFIRMED = 'confirmed'     # 三阶段全部通过
    LIKELY = 'likely'           # 两阶段通过
    UNCERTAIN = 'uncertain'     # 一阶段通过
    FILTERED = 'filtered'       # 全部未通过


@dataclass
class EnhancedUafReport:
    func_name: str
    verdict: UafVerdict
    confidence: float              # 0.0-1.0
    alias_sets: List[AliasSet] = field(default_factory=list)
    path_contexts: Dict[int, PathContext] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    fp_likelihood: float = 0.0     # 是误报的概率(0=确定漏洞, 1=确定误报)


class EnhancedUafFilter:
    """三阶段增强UAF过滤管线。

    使用方式:
      euf = EnhancedUafFilter()
      reports = euf.analyze(instructions, bb_boundaries, cfg_edges)
    """

    def __init__(self):
        self._alias_tracker = UafAliasTracker(max_trace_dist=40)
        self._path_analyzer = UafPathAnalyzer()

    def analyze(self,
                instructions: List[str],
                bb_boundaries: Optional[List[Tuple[int, int]]] = None,
                cfg_edges: Optional[List[Tuple[int, int]]] = None,
                func_name: str = ""
                ) -> List[EnhancedUafReport]:
        n = len(instructions)
        if n < 5:
            return []

        # 阶段1: 别名感知追踪
        alias_sets = self._alias_tracker.analyze(
            instructions, bb_boundaries)

        # 阶段2: 路径敏感分析——对所有free点
        free_sites = []
        for aset in alias_sets:
            free_sites.extend(aset.free_sites)
        path_ctx = self._path_analyzer.analyze_free_sites(
            instructions, bb_boundaries or [], free_sites)

        # 阶段3: 综合判定
        reports = []
        for aset in alias_sets:
            # 跳过不可疑的别名集合
            if not aset.is_freed and not aset.is_vulnerable:
                continue

            report = self._synthesize_verdict(
                aset, path_ctx, instructions, func_name)
            if report:
                reports.append(report)

        return reports or self._make_empty_report(func_name, alias_sets)

    def filter_confirmed(self,
                          reports: List[EnhancedUafReport]
                          ) -> List[EnhancedUafReport]:
        return [r for r in reports
                if r.verdict in (UafVerdict.CONFIRMED, UafVerdict.LIKELY)]

    def filter_actionable(self,
                           reports: List[EnhancedUafReport]
                           ) -> List[EnhancedUafReport]:
        return [r for r in reports
                if r.verdict != UafVerdict.FILTERED]

    def get_statistics(self,
                        reports: List[EnhancedUafReport]
                        ) -> Dict[str, int]:
        counts = {v.value: 0 for v in UafVerdict}
        for r in reports:
            counts[r.verdict.value] += 1
        counts['total'] = len(reports)
        return counts

    def _synthesize_verdict(self,
                             aset: AliasSet,
                             path_ctx: Dict[int, PathContext],
                             instructions: List[str],
                             func_name: str
                             ) -> Optional[EnhancedUafReport]:
        evidence = []
        passed_stages = 0
        fp_score = 0.0

        # 阶段1打分: 别名传播是否成功关联free和use
        stage1_pass = (aset.is_freed and aset.is_vulnerable
                       and len(aset.use_sites) > 0)
        if stage1_pass:
            passed_stages += 1
            evidence.append(
                f"别名追踪: {aset.canonical}→{aset.members} "
                f"free@{aset.free_sites} use@{aset.use_sites}")
        elif aset.is_freed:
            evidence.append(
                f"别名追踪: {aset.canonical} free@{aset.free_sites} "
                f"但未检测到危险use")
            fp_score += 0.4
        else:
            evidence.append(
                f"别名追踪: {aset.canonical} 未free或无别名use")
            fp_score += 0.3

        # 阶段2打分: 路径条件分析
        stage2_pass = False
        for free_idx in aset.free_sites:
            ctx = path_ctx.get(free_idx)
            if ctx is None:
                continue
            if ctx.certainty == FreeCertainty.UNCONDITIONAL:
                stage2_pass = True
                evidence.append(f"路径: free@{free_idx} 无条件→必然执行")
            elif ctx.certainty == FreeCertainty.CONDITIONAL:
                fp_score += 0.3
                evidence.append(
                    f"路径: free@{free_idx} 条件执行({ctx.cond_type})→可能不触发")
            elif ctx.certainty == FreeCertainty.UNREACHABLE_AFTER:
                fp_score += 0.5
                evidence.append(
                    f"路径: free@{free_idx} 清理代码(free后return)→use不可达")

        if stage2_pass:
            passed_stages += 1

        # 阶段3: use的严重性评估
        stage3_pass = False
        max_severity = 0
        for use_idx in aset.use_sites:
            if use_idx >= len(instructions):
                continue
            instr = instructions[use_idx].strip().lower()
            severity = self._assess_use_severity(instr)
            max_severity = max(max_severity, severity)
            if severity >= 2:
                stage3_pass = True
                evidence.append(
                    f"严重use@{use_idx}(severity={severity}): {instr[:60]}")

        if not stage3_pass and aset.use_sites:
            fp_score += 0.2
            evidence.append("use严重性低(仅copy级别)")

        if stage3_pass:
            passed_stages += 1

        # 综合判定
        if passed_stages >= 3:
            verdict = UafVerdict.CONFIRMED
            confidence = 0.9 * (1.0 - fp_score)
        elif passed_stages >= 2:
            verdict = UafVerdict.LIKELY
            confidence = 0.65 * (1.0 - fp_score)
        elif passed_stages >= 1:
            verdict = UafVerdict.UNCERTAIN
            confidence = 0.35 * (1.0 - fp_score)
        else:
            verdict = UafVerdict.FILTERED
            confidence = 0.1

        return EnhancedUafReport(
            func_name=func_name,
            verdict=verdict,
            confidence=min(1.0, max(0.0, confidence)),
            alias_sets=[aset],
            path_contexts={
                fi: path_ctx[fi] for fi in aset.free_sites
                if fi in path_ctx},
            evidence=evidence,
            fp_likelihood=fp_score)

    def _assess_use_severity(self, instr: str) -> int:
        """评估use的严重性: 3=解引用, 2=call参数, 1=copy/mov"""
        if f'[' in instr and 'lea' not in instr:
            return 3  # 内存读写——最可能触发崩溃
        if 'call' in instr:
            return 2  # 作为参数传递——可能被其他函数解引用
        return 1     # 普通mov——可能只是copy值

    def _make_empty_report(self,
                            func_name: str,
                            alias_sets: List[AliasSet]
                            ) -> List[EnhancedUafReport]:
        """当没有可疑别名集合时生成空报告"""
        if not alias_sets:
            return []
        freed = [a for a in alias_sets if a.is_freed]
        if freed:
            return [EnhancedUafReport(
                func_name=func_name,
                verdict=UafVerdict.UNCERTAIN,
                confidence=0.2,
                alias_sets=freed,
                evidence=["仅有free, 未发现危险use——可能是安全清理"],
                fp_likelihood=0.8)]
        return []
