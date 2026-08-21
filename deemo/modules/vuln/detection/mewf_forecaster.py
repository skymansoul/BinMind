# coding: utf-8
#
"""
多因子漏洞武器化预测-时态预测编排器。

集成复杂度量化+时态生存分析+外部信号融合，
产出漏洞武器化的多维概率预测。

管线流程:
  1. 复杂度量化: ExploitComplexityEstimator-代码级利用难度
  2. 时态预测: WeibullAFT-生存曲线+关键时间点+风险率
  3. 信号融合: PoC活动/CISA KEV/社交媒体信号-先验修正
  4. 武器化分级: IMMINENT/WEEKS/MONTHS/UNLIKELY
  5. 优先级排序: Top-K最可能被武器化的漏洞

与现有评分系统对比:
  CVSS: 严重度(静态)-本模块包含
  EPSS: 30天概率(黑盒)-本模块输出全时域生存曲线(白盒)
  LEV: 已被利用概率(回顾)-本模块预测未来武器化(前瞻)
  AEAS: exploit代码成熟度(需代码)-本模块预测武器化(代码之前)
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .mewf_complexity import ExploitComplexity, ExploitComplexityEstimator
from .mewf_temporal import TemporalForecast, WeibullAFT

_log = logging.getLogger(__name__)


# 武器化预测


class WeaponizationTier(str):
    IMMINENT = "IMMINENT"       # <7天-已有活跃利用信号
    WEEKS = "WEEKS"             # 7-30天-PoC开发中
    MONTHS = "MONTHS"           # 30-90天-需要显著开发
    UNLIKELY = "UNLIKELY"       # >90天-利用条件苛刻
    UNKNOWN = "UNKNOWN"


@dataclass
class WeaponizationForecast:
    """漏洞武器化完整预测"""
    cve_id: str
    function_name: str
    # 复杂度
    exploit_complexity: Optional[ExploitComplexity] = None
    # 时态预测
    temporal: Optional[TemporalForecast] = None
    # 信号融合
    poc_activity_score: float = 0.0
    kev_listed: bool = False
    exploitdb_referenced: bool = False
    # 武器化判定
    weaponization_tier: str = WeaponizationTier.UNKNOWN
    weaponization_probability_30d: float = 0.0
    priority_score: float = 0.0        # [0, 1]
    # 推荐
    recommended_action: str = ""


# 武器化预测引擎


class WeaponizationForecaster:
    """多因子漏洞武器化预测引擎-复杂度+时态+信号的完整预测管线。

    使用示例:
        forecaster = WeaponizationForecaster()
        result = forecaster.forecast(
            vuln_type='stack_buffer_overflow',
            overflow_size=64,
            cvss_score=8.5,
            protections={'NX':'yes','ASLR':'yes','PIE':'yes'},
            poc_activity=0.3,
            kev_listed=False)

    信号来源:
      poc_activity: GitHub PoC仓库数/Exploit-DB引用/社交媒体讨论量
        聚合为[0, 1]分数-0.5约等于平均活动量
      kev_listed: CISA Known Exploited Vulnerabilities目录收录
      exploitdb_referenced: Exploit-DB是否有相关条目
    """

    def __init__(self):
        self._complexity_estimator = ExploitComplexityEstimator()
        self._temporal_model = WeibullAFT()

    def forecast(self, vuln_type: str = "",
                  cve_id: str = "",
                  function_name: str = "",
                  overflow_size: int = 0,
                  cvss_score: float = 5.0,
                  protections: Dict[str, str] = None,
                  info_leak: bool = False,
                  stack_addr_leak: int = 0,
                  libc_base_leak: int = 0,
                  poc_activity: float = 0.0,
                  kev_listed: bool = False,
                  exploitdb_ref: bool = False,
                  disclosure_days: float = 0.0
                  ) -> WeaponizationForecast:
        """执行完整武器化预测。

        返回WeaponizationForecast含所有中间产物与最终判定。
        """
        # 复杂度量化
        complexity = self._complexity_estimator.estimate(
            vuln_type=vuln_type,
            overflow_size=overflow_size,
            protections=protections,
            info_leak=info_leak,
            stack_addr_leak=stack_addr_leak,
            libc_base_leak=libc_base_leak)

        # 时态生存分析
        temporal = self._temporal_model.forecast(
            complexity=complexity,
            cvss_score=cvss_score,
            poc_activity_score=poc_activity,
            kev_listed=kev_listed,
            disclosure_days=disclosure_days)

        # 武器化分级
        tier = self._assign_tier(temporal, kev_listed, poc_activity,
                                  disclosure_days)

        # 30天武器化概率-1 - S(30)
        prob_30d = 1.0 - temporal.survival_30d
        if kev_listed:
            prob_30d = max(prob_30d, 0.85)
        if exploitdb_ref:
            prob_30d = max(prob_30d, 0.65)

        # 优先级评分-多维加权
        priority = self._compute_priority(complexity, temporal, prob_30d,
                                           kev_listed, cvss_score)

        # 建议
        action = self._recommend(tier, prob_30d, temporal)

        return WeaponizationForecast(
            cve_id=cve_id,
            function_name=function_name,
            exploit_complexity=complexity,
            temporal=temporal,
            poc_activity_score=poc_activity,
            kev_listed=kev_listed,
            exploitdb_referenced=exploitdb_ref,
            weaponization_tier=tier,
            weaponization_probability_30d=round(prob_30d, 4),
            priority_score=round(priority, 4),
            recommended_action=action)

    def _assign_tier(self, temporal: TemporalForecast,
                      kev: bool, poc: float,
                      disclosure_days: float) -> str:
        """武器化分级-结合生存分析+外部信号"""
        if kev:
            return WeaponizationTier.IMMINENT
        if temporal.survival_7d < 0.7:
            return WeaponizationTier.IMMINENT
        if temporal.survival_30d < 0.5 or poc > 0.7:
            return WeaponizationTier.WEEKS
        if temporal.survival_90d < 0.4:
            return WeaponizationTier.MONTHS
        if temporal.survival_90d < 0.7:
            return WeaponizationTier.MONTHS
        return WeaponizationTier.UNLIKELY

    def _compute_priority(self, complexity: ExploitComplexity,
                           temporal: TemporalForecast,
                           prob_30d: float, kev: bool,
                           cvss: float) -> float:
        """优先级评分-0(低)~1(高)"""
        score = 0.0
        score += 0.35 * prob_30d
        score += 0.25 * (cvss / 10.0)
        score += 0.20 * (1.0 - complexity.overall_complexity)
        score += 0.15 * (1.0 if kev else 0.0)
        score += 0.05 * (1.0 if temporal.hazard_trend == "increasing" else 0.5)
        return min(1.0, score)

    def _recommend(self, tier: str, prob_30d: float,
                    temporal: TemporalForecast) -> str:
        if tier == WeaponizationTier.IMMINENT:
            return (f"紧急: 武器化概率{prob_30d:.0%}, "
                    f"中位利用时间{temporal.median_time_to_exploit:.0f}天。"
                    f"建议立即修复并部署IDS规则。")
        if tier == WeaponizationTier.WEEKS:
            return (f"高: {prob_30d:.0%}概率在30天内武器化。"
                    f"建议纳入当前迭代修复。")
        if tier == WeaponizationTier.MONTHS:
            return (f"中: 预计{temporal.median_time_to_exploit:.0f}天内出现利用代码。"
                    f"建议季度计划中安排修复。")
        return (f"低: 利用条件苛刻(复杂度{self._complexity_estimator})。"
                f"可延后至下一发布周期。")

    def batch_forecast(self, vulnerabilities: List[Dict]
                        ) -> List[WeaponizationForecast]:
        """批量预测-按优先级降序返回。

        vulnerabilities中的每条记录可含id/cve_id等元数据字段,
        这些字段不会传递给forecast()-仅提取匹配的参数。
        """
        # forecast()接受的参数-过滤掉元数据字段
        _valid_params = {'vuln_type', 'cve_id', 'function_name',
                         'overflow_size', 'cvss_score', 'protections',
                         'info_leak', 'stack_addr_leak', 'libc_base_leak',
                         'poc_activity', 'kev_listed', 'exploitdb_ref',
                         'disclosure_days'}
        results = []
        for v in vulnerabilities:
            filtered = {k: v[k] for k in _valid_params if k in v}
            results.append(self.forecast(**filtered))
        results.sort(key=lambda r: r.priority_score, reverse=True)
        return results


# 便捷入口


def forecast_weaponization(vuln_type: str, cvss_score: float = 5.0,
                            overflow_size: int = 0,
                            protections: Dict[str, str] = None,
                            poc_activity: float = 0.0,
                            kev_listed: bool = False
                            ) -> WeaponizationForecast:
    """武器化预测便捷入口-单行调用"""
    return WeaponizationForecaster().forecast(
        vuln_type=vuln_type, cvss_score=cvss_score,
        overflow_size=overflow_size, protections=protections,
        poc_activity=poc_activity, kev_listed=kev_listed)


__all__ = [
    "WeaponizationTier",
    "WeaponizationForecast",
    "WeaponizationForecaster",
    "forecast_weaponization",
]
