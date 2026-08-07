# 增强格式串过滤器——将format_string_deep.py的三阶段分析接入检测管线
# 原有format_string_check.py: 仅检查fmt是否来自函数参数
#   缺陷1: 不区分printf(gettext("hello")) vs printf(user_input)
#   缺陷2: 无格式符vs参数计数一致性验证
#   缺陷3: 无%n写内存检测
#
# 改进(三阶段管线):
#   阶段1(FormatStringDeepAnalyzer): fmt来源分类(const/stack/arg/heap) + %n检测
#   阶段2: 参数计数一致性——格式符>参数→栈泄露, 格式符<参数→信息泄露
#   阶段3: 综合风险评估——SAFE/SUSPICIOUS/DANGEROUS/CRITICAL
#
# 判定规则: DANGEROUS/CRITICAL→CONFIRMED, SUSPICIOUS→LIKELY, SAFE→FILTERED
# created: 2026-06-08

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .format_string_deep import (
    FormatStringDeepAnalyzer, DeepFmtVerdict, FmtSource, FmtRisk)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class FmtVerdict(Enum):
    CONFIRMED = 'confirmed'     # 可变fmt+%n或参数严重不匹配
    LIKELY = 'likely'           # 非rodata来源但无%n
    UNCERTAIN = 'uncertain'     # 无法确定fmt来源
    FILTERED = 'filtered'       # 常量fmt + 参数匹配→安全


@dataclass
class EnhancedFmtReport:
    func_name: str
    verdict: FmtVerdict
    confidence: float              # 0.0-1.0
    fmt_calls: List[DeepFmtVerdict] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    fp_likelihood: float = 0.0


class EnhancedFmtFilter:
    """增强格式串过滤管线——包装FormatStringDeepAnalyzer并输出统一裁决。

    使用方式:
      eff = EnhancedFmtFilter()
      reports = eff.analyze(instructions, func_name)
    """

    _FMT_FUNCS = {'printf', 'fprintf', 'sprintf', 'snprintf',
                  'dprintf', 'vprintf', 'vfprintf', 'vsprintf',
                  'syslog', '__printf_chk', '__fprintf_chk'}

    def __init__(self):
        self._deep = FormatStringDeepAnalyzer()

    def analyze(self,
                instructions: List[str],
                bb_boundaries: Optional[List[Tuple[int, int]]] = None,
                cfg_edges: Optional[List[Tuple[int, int]]] = None,
                func_name: str = "",
                rodata_refs: Optional[Dict[int, str]] = None
                ) -> List[EnhancedFmtReport]:
        """扫描函数中所有printf系列调用, 对每个fmt做三阶段分析"""
        n = len(instructions)
        if n < 3:
            return []

        # 找所有fmt函数调用点
        fmt_calls = []
        for i in range(n):
            instr = instructions[i].strip().lower()
            if 'call' not in instr:
                continue
            for ff in self._FMT_FUNCS:
                if ff in instr:
                    v = self._deep.analyze_call(
                        i, instructions, ff, rodata_refs or {})
                    if v.risk != FmtRisk.SAFE:
                        fmt_calls.append(v)
                    break

        if not fmt_calls:
            return []

        return self._synthesize(func_name, fmt_calls)

    def _synthesize(self,
                    func_name: str,
                    calls: List[DeepFmtVerdict]
                    ) -> List[EnhancedFmtReport]:
        """综合所有fmt调用→统一裁决"""
        evidence = []
        max_risk = FmtRisk.SAFE
        max_confidence = 0.0

        for v in calls:
            evidence.extend(v.evidence)
            # 风险排序: CRITICAL > DANGEROUS > SUSPICIOUS > SAFE
            risk_order = {FmtRisk.CRITICAL: 3, FmtRisk.DANGEROUS: 2,
                         FmtRisk.SUSPICIOUS: 1, FmtRisk.SAFE: 0}
            if risk_order.get(v.risk, 0) > risk_order.get(max_risk, 0):
                max_risk = v.risk

        # 风险→裁决映射
        if max_risk == FmtRisk.CRITICAL:
            verdict = FmtVerdict.CONFIRMED
            max_confidence = 0.9
        elif max_risk == FmtRisk.DANGEROUS:
            verdict = FmtVerdict.CONFIRMED
            max_confidence = 0.8
        elif max_risk == FmtRisk.SUSPICIOUS:
            verdict = FmtVerdict.LIKELY
            max_confidence = 0.55
        else:
            verdict = FmtVerdict.FILTERED
            max_confidence = 0.1

        # 减分项: 若fmt来自CONST_RODATA且无%n→大概率安全
        fp_score = 0.0
        safe_count = sum(1 for v in calls if v.risk == FmtRisk.SAFE)
        const_count = sum(1 for v in calls
                         if v.fmt_source == FmtSource.CONST_RODATA)
        if const_count > 0 and safe_count > 0:
            fp_score += 0.3

        return [EnhancedFmtReport(
            func_name=func_name,
            verdict=verdict,
            confidence=max_confidence * (1.0 - fp_score),
            fmt_calls=calls,
            evidence=evidence[:8],
            fp_likelihood=fp_score)]

    def filter_confirmed(self,
                          reports: List[EnhancedFmtReport]
                          ) -> List[EnhancedFmtReport]:
        return [r for r in reports
                if r.verdict in (FmtVerdict.CONFIRMED, FmtVerdict.LIKELY)]

    def get_statistics(self,
                        reports: List[EnhancedFmtReport]
                        ) -> Dict[str, int]:
        counts = {v.value: 0 for v in FmtVerdict}
        for r in reports:
            counts[r.verdict.value] += 1
        counts['total'] = len(reports)
        return counts
