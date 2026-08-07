# coding: utf-8
# 创建: 2026-07-17  |  VDDA编排引擎
# 修改: 2026-07-17  |  审计后补充文件头与错误处理
#
"""
漏洞发现增量分析——编排引擎与CI/CD集成。

管线流程:
  1. 加载两次运行的finding(当前+基线)
  2. DeltaEngine→跨运行配对+差异分类+显著性检验
  3. 回归检测——高置信度finding消失→标记为REGRESSION
  4. 聚合统计——新增/修复/严重度变化/噪声比
  5. CI/CD集成——通过/失败判定(可配置阈值)

CI/CD门控:
  regression_count > 0 → FAIL(阻止合并)
  new_critical_count > threshold → WARN(需要审查)
  noise_ratio > 0.7 → WARN(检测器可能异常)

与现有模块集成:
  作为分析管线的最后一步——消费所有finding输出,
  产出一个可操作的增量报告, 集成至CI/CD决策流程。
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .vdda_delta import (
    DeltaEngine, DeltaReport, DeltaType, FindingSnapshot,
)

_log = logging.getLogger(__name__)


class CICDGateResult(str):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class CICDDecision:
    """CI/CD门控决策"""
    gate_result: str            # PASS/FAIL/WARN
    fail_reasons: List[str] = field(default_factory=list)
    warn_reasons: List[str] = field(default_factory=list)
    delta_report: Optional[DeltaReport] = None


@dataclass
class VddaReport:
    """VDDA完整报告——面向CI/CD集成"""
    delta: Optional[DeltaReport] = None
    cicd_decision: Optional[CICDDecision] = None
    # 人类可读摘要
    summary: str = ""


# VDDA引擎


class VddaEngine:
    """漏洞发现增量分析引擎——CI/CD集成。

    使用示例:
        engine = VddaEngine()
        report = engine.run(
            current_findings=[...],
            previous_findings=[...],
            run_id_current='ci_build_142',
            run_id_previous='ci_build_141')
    """

    def __init__(self,
                 max_new_critical: int = 3,
                 max_regression: int = 0,
                 max_noise_ratio: float = 0.6):
        """
        参数:
          max_new_critical: 新增CRITICAL/HIGH finding的上限(超出→WARN)
          max_regression: 允许的回归数量上限(超出→FAIL)
          max_noise_ratio: 噪声比上限(超出→WARN)
        """
        self._delta_engine = DeltaEngine()
        self._max_new_critical = max_new_critical
        self._max_regression = max_regression
        self._max_noise = max_noise_ratio

    def run(self, current_findings: List[Dict],
             previous_findings: List[Dict],
             run_id_current: str = "",
             run_id_previous: str = ""
             ) -> VddaReport:
        """执行增量分析+CI/CD门控判定。

        返回VddaReport。
        """
        delta = self._delta_engine.analyze(
            current_findings, previous_findings,
            run_id_current, run_id_previous)

        decision = self._evaluate_gate(delta)
        summary = self._build_summary(delta, decision)

        return VddaReport(delta=delta, cicd_decision=decision, summary=summary)

    def _evaluate_gate(self, delta: DeltaReport) -> CICDDecision:
        """CI/CD门控判定——基于可配置阈值"""
        fail_reasons = []
        warn_reasons = []

        # FAIL条件——回归(高置信度finding消失)
        if delta.regression_count > self._max_regression:
            fail_reasons.append(
                f"检测到{delta.regression_count}个修复回归"
                f"(上限{self._max_regression})")

        # 新增critical/high
        new_critical = sum(1 for s in delta.snapshots
                           if s.delta_type == DeltaType.NEW
                           and s.current_severity >= 0.7)
        if new_critical > self._max_new_critical:
            warn_reasons.append(
                f"新增{new_critical}个高危finding"
                f"(上限{self._max_new_critical})")

        # 噪声比
        if delta.noise_ratio > self._max_noise:
            warn_reasons.append(
                f"分析噪声比{delta.noise_ratio:.0%}"
                f"(上限{self._max_noise:.0%})")

        # 严重度上升
        sev_ups = sum(1 for s in delta.snapshots
                      if s.delta_type == DeltaType.SEVERITY_UP
                      and s.is_significant)
        if sev_ups > 5:
            warn_reasons.append(
                f"{sev_ups}个finding严重度显著上升")

        if fail_reasons:
            gate = CICDGateResult.FAIL
        elif warn_reasons:
            gate = CICDGateResult.WARN
        else:
            gate = CICDGateResult.PASS

        return CICDDecision(
            gate_result=gate,
            fail_reasons=fail_reasons,
            warn_reasons=warn_reasons,
            delta_report=delta)

    def _build_summary(self, delta: DeltaReport,
                         decision: CICDDecision) -> str:
        """构建人类可读摘要"""
        lines = [
            f"VDDA: {delta.run_id_previous} → {delta.run_id_current}",
            f"  Total: {delta.total_current} current / {delta.total_previous} previous",
            f"  New: +{delta.new_count}  Resolved: -{delta.resolved_count}",
            f"  Regressions: {delta.regression_count}  Severity changes: {delta.severity_changes}",
            f"  Significant changes: {delta.significant_changes}  Noise ratio: {delta.noise_ratio:.1%}",
            f"  Gate: {decision.gate_result}",
        ]
        for reason in decision.fail_reasons:
            lines.append(f"  FAIL: {reason}")
        for reason in decision.warn_reasons:
            lines.append(f"  WARN: {reason}")
        if delta.review_recommendations:
            lines.append("  Recommendations:")
            for rec in delta.review_recommendations:
                lines.append(f"    - {rec}")
        return "\n".join(lines)


# 便捷入口


def analyze_delta(current_findings: List[Dict],
                   previous_findings: List[Dict],
                   run_id_current: str = "current",
                   run_id_previous: str = "previous",
                   fail_on_regression: bool = True
                   ) -> VddaReport:
    """增量分析便捷入口——单行调用"""
    engine = VddaEngine(max_regression=0 if fail_on_regression else 999)
    return engine.run(current_findings, previous_findings,
                       run_id_current, run_id_previous)


__all__ = [
    "CICDGateResult",
    "CICDDecision",
    "VddaReport",
    "VddaEngine",
    "analyze_delta",
]
