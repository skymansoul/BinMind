# coding: utf-8
# 创建: 2026-07-02  |  ICHRA编排引擎
# 修改: 2026-07-02  |  审计后补充文件头与错误处理
#
"""
间接调用劫持风险评估——编排引擎+CFI加固建议生成。

管线流程:
  1. 输入: 函数反汇编+CFI策略信息+漏洞分析管线产出
  2. 调用点分析: IndirectCallAnalyzer→提取间接调用点+可达性评估
  3. 风险评估: 三维评分(可达性+替换面+影响)→综合风险排序
  4. 加固建议: 按风险优先级生成逐调用点的CFI加固方案
  5. 输出: ICHRA报告——风险排序+防护优先级+部署指导

CFI加固策略推荐(按风险等级):
  CRITICAL: FineIBT paranoid(caller-side hash) + kCFI type-signature check
  HIGH:     kCFI type-signature check 或 Clang CFI + 允许集最小化
  MEDIUM:   审查CFI允许集, 移除不必要目标, 考虑fsanitize=cfi
  LOW:      标准CFI策略(Clang CFI / Windows CFG)

与cfi_integrity_analyzer的集成:
  cfi_integrity_analyzer → CFI是否存在+是否完整
  ichra_engine → 在CFI存在的前提下, 哪些调用点最脆弱
  互补: 前者检查CFI覆盖, 后者评估CFI内的残余风险

技术依据:
  SACK: 函数替换攻击可绕过精确CFI
  FineIBT paranoid: caller-side hash可防御但需选择性部署
  本模块: 提供选择依据——哪些调用点最需要额外防护
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ichra_call_analyzer import (
    IndirectCallSite, CallSiteRiskAssessment, IndirectCallAnalyzer,
    CallSiteRisk,
)

_log = logging.getLogger(__name__)


# 加固方案


@dataclass
class HardeningRecommendation:
    """单调用点的CFI加固方案"""
    call_site_addr: int
    risk_level: str
    priority: int
    # 推荐技术
    primary_technique: str = ""       # FineIBT paranoid / kCFI / Clang CFI
    fallback_technique: str = ""      # 备选方案
    # 实施参数
    expected_overhead_pct: float = 0.0  # 预期性能开销(%)
    deployment_complexity: str = ""     # LOW/MEDIUM/HIGH
    # 验证方法
    verification_test: str = ""


@dataclass
class IchraReport:
    """ICHRA完整报告——间接调用劫持风险全景"""
    binary_name: str
    # 调用点统计
    total_call_sites: int = 0
    critical_sites: int = 0
    high_sites: int = 0
    medium_sites: int = 0
    low_sites: int = 0
    # 排序后的评估
    ranked_assessments: List[CallSiteRiskAssessment] = field(
        default_factory=list)
    # 加固方案
    hardening_recommendations: List[HardeningRecommendation] = field(
        default_factory=list)
    # 总体风险
    overall_binary_risk: float = 0.0       # 二进制整体的间接调用劫持风险
    cfi_effectiveness_gap: float = 0.0     # 当前CFI vs 最优CFI之间的防护差距


# ICHRA引擎


class IchraEngine:
    """间接调用劫持风险评估引擎。

    使用示例:
        engine = IchraEngine()
        report = engine.analyze(
            instructions_by_function={'func_a': [...], 'func_b': [...]},
            binary_name='/bin/target',
            cfi_enabled=True,
            vtable_info={0x4010: ['target_a','target_b']})
    """

    def __init__(self):
        self._analyzer = IndirectCallAnalyzer()

    def analyze(self, instructions_by_function: Dict[str, List[str]],
                 binary_name: str = "",
                 cfi_enabled: bool = False,
                 cfi_type: str = "",      # clang_cfi / kcfi / fineibt / cfg
                 vtable_info: Dict[int, List[str]] = None,
                 vulnerability_info: Dict = None
                 ) -> IchraReport:
        """执行间接调用劫持风险评估。

        参数:
          instructions_by_function: {函数名: [反汇编行]}
          binary_name: 二进制文件名
          cfi_enabled: 是否启用CFI
          cfi_type: CFI类型
          vtable_info: 虚表信息(辅助CFI允许集推断)

        返回IchraReport。
        """
        all_call_sites = []
        for func_name, insns in instructions_by_function.items():
            sites = self._analyzer.analyze(
                insns, func_name, cfi_enabled=cfi_enabled,
                vtable_info=vtable_info)
            all_call_sites.extend(sites)

        if not all_call_sites:
            return IchraReport(binary_name=binary_name)

        # 风险评估
        assessments = self._analyzer.assess_risk(
            all_call_sites, vulnerability_info)

        # 生成加固方案
        hardening = []
        for a in assessments:
            if a.risk_level in (CallSiteRisk.CRITICAL, CallSiteRisk.HIGH):
                hardening.append(self._build_hardening(a, cfi_type))

        # 统计
        critical = sum(1 for a in assessments
                       if a.risk_level == CallSiteRisk.CRITICAL)
        high = sum(1 for a in assessments
                   if a.risk_level == CallSiteRisk.HIGH)
        medium = sum(1 for a in assessments
                     if a.risk_level == CallSiteRisk.MEDIUM)
        low = sum(1 for a in assessments
                  if a.risk_level == CallSiteRisk.LOW)

        # 整体风险——加权平均
        weights = {CallSiteRisk.CRITICAL: 1.0, CallSiteRisk.HIGH: 0.7,
                   CallSiteRisk.MEDIUM: 0.4, CallSiteRisk.LOW: 0.1}
        overall = (sum(weights.get(a.risk_level, 0.0) for a in assessments) /
                   max(len(assessments), 1))

        # CFI防护差距——当前vs最优(所有CRITICAL/HIGH加固后)
        current_protected = 1.0 if cfi_enabled else 0.0
        optimal_protected = 0.9  # 最优CFI仍无法防御所有替换攻击
        gap = optimal_protected - current_protected

        return IchraReport(
            binary_name=binary_name,
            total_call_sites=len(all_call_sites),
            critical_sites=critical, high_sites=high,
            medium_sites=medium, low_sites=low,
            ranked_assessments=assessments,
            hardening_recommendations=hardening,
            overall_binary_risk=round(overall, 3),
            cfi_effectiveness_gap=round(gap, 3))

    def _build_hardening(self, assessment: CallSiteRiskAssessment,
                           existing_cfi: str) -> HardeningRecommendation:
        """为单个调用点构建CFI加固方案"""
        cs = assessment.call_site

        if assessment.risk_level == CallSiteRisk.CRITICAL:
            primary = "FineIBT paranoid (caller-side hash validation)"
            fallback = "kCFI type-signature check + Clang CFI"
            overhead = 2.5
            complexity = "MEDIUM"
            verify = "SACK-style function substitution test on this call site"
        elif assessment.risk_level == CallSiteRisk.HIGH:
            primary = "kCFI type-signature check"
            fallback = "Clang CFI with minimized allowlist"
            overhead = 1.0
            complexity = "LOW"
            verify = "Verify allowed target set ≤ 5 functions"
        else:
            primary = "Clang CFI / Windows CFG (standard)"
            fallback = "N/A"
            overhead = 0.5
            complexity = "LOW"
            verify = "Baseline CFI coverage check"

        return HardeningRecommendation(
            call_site_addr=cs.address,
            risk_level=assessment.risk_level,
            priority=assessment.hardening_priority,
            primary_technique=primary,
            fallback_technique=fallback,
            expected_overhead_pct=overhead,
            deployment_complexity=complexity,
            verification_test=verify)


# 便捷入口


def assess_indirect_call_risk(
    instructions_by_function: Dict[str, List[str]],
    binary_name: str = "",
    cfi_enabled: bool = False
) -> IchraReport:
    """间接调用劫持风险评估便捷入口"""
    return IchraEngine().analyze(
        instructions_by_function, binary_name, cfi_enabled=cfi_enabled)


__all__ = [
    "HardeningRecommendation",
    "IchraReport",
    "IchraEngine",
    "assess_indirect_call_risk",
]
