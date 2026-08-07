# coding: utf-8
# 创建: 2026-04-18  |  时态生存分析
# 修改: 2026-04-18  |  审计后补充文件头与错误处理
#
"""
多因子漏洞武器化预测——时态生存分析模型。

技术问题:
  现有系统(EPSS/LEV)输出"未来30天被利用的概率"这一单一数值，
  但安全团队需要更细粒度的时态信息:
    - 漏洞披露后第1周/第1月/第1季度的利用概率分别是多少？
    - 给定已过N天未被利用，剩余风险如何衰减？
    - 何时可以降低此漏洞的监控优先级？

解决方案:
  威布尔加速失效时间(AFT)模型——协变量(漏洞复杂度+CVSS+PoC活动)
  影响尺度参数λ，形状参数k捕获风险率时变特性。
    S(t|X) = exp(-(t/λ(X))^k)
    λ(X) = exp(β₀ + β₁×complexity + β₂×CVSS + β₃×PoC_activity)
    h(t|X) = (k/λ) × (t/λ)^(k-1)  —— 风险率函数

  k>1: 风险递增(随着时间推移利用概率加速上升——漏洞自动化工具开发)
  k<1: 风险递减(初始关注度过后利用概率下降——漏洞难以武器化)
  k=1: 指数分布(恒定风险——基准情况)

与EPSS的差异:
  EPSS: 30天单体概率，黑盒ML，仅CVSS元数据
  本模块: 全时域生存曲线+风险率，可解释协变量模型，含代码级特征

理论基础:
  Cox比例风险模型(AFT参数化)在生存分析中的标准应用，
  适配至漏洞利用时域——首次PoC公开时间等效于生物统计的"事件时间"。
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .mewf_complexity import ExploitComplexity

_log = logging.getLogger(__name__)


@dataclass
class TemporalForecast:
    """时态利用预测——生存曲线+风险率+关键时间点"""
    # 生存概率 S(t)
    survival_7d: float = 1.0       # 7天内存活(未被利用)概率
    survival_30d: float = 1.0
    survival_90d: float = 1.0
    survival_180d: float = 1.0
    # 关键分位数
    median_time_to_exploit: float = 0.0    # 中位利用时间(天)
    time_to_10pct_risk: float = 0.0        # 10%利用概率时间(天)
    time_to_50pct_risk: float = 0.0        # 50%利用概率时间(天)
    # 风险率
    hazard_30d: float = 0.0       # 30天时的瞬时风险率
    hazard_trend: str = "stable"   # increasing | decreasing | stable
    # 模型参数
    weibull_lambda: float = 0.0    # 尺度参数
    weibull_k: float = 1.2         # 形状参数(k>1=风险递增)
    # 置信度
    model_confidence: str = "MEDIUM"


# 威布尔AFT模型


class WeibullAFT:
    """威布尔加速失效时间模型——协变量驱动的漏洞利用时域预测。

    参数估计:
      基准尺度λ₀ = 180天(中位漏洞在180天内出现PoC)
      协变量效应: β系数乘子，exp(Σ βᵢXᵢ)缩放基准尺度

    协变量定义:
      X₁ = exploit_complexity.overall_complexity ([-1, 1]标准化)
          → 复杂度越高→λ越大→生存更长(更难利用)
      X₂ = cvss_normalized ([-1, 1])
          → CVSS越高→λ越小→生存更短(更快被利用)
      X₃ = poc_activity ([-1, 1])
          → GitHub/Exploit-DB活动越多→λ越小→更快武器化
      X₄ = kev_listed (0或1)
          → CISA KEV收录→λ×0.3(大幅加速)

    形状参数k:
      k=1.3(默认): 温和递增——大部分漏洞展示"逐渐升温"的利用模式
      k=0.8(低复杂度): 递减——容易利用的漏洞初期即被攻击
      k=1.8(高复杂度): 陡增——需工具化后利用率才上升
    """

    # 协变量系数——log(λ) = β₀ + Σ βᵢXᵢ
    _BETA = {
        'intercept': math.log(180.0),   # β₀→基准λ=180天
        'complexity': 1.2,              # β₁: 复杂度正相关
        'cvss': -0.8,                   # β₂: CVSS负相关
        'poc_activity': -0.6,           # β₃: PoC活动负相关
        'kev_listed': -1.2,             # β₄: KEV大幅加速
    }

    def __init__(self):
        pass

    def forecast(self, complexity: ExploitComplexity,
                  cvss_score: float = 5.0,
                  poc_activity_score: float = 0.0,
                  kev_listed: bool = False,
                  disclosure_days: float = 0.0
                  ) -> TemporalForecast:
        """预测漏洞利用的时态生存曲线。

        参数:
          complexity: 利用复杂度估计
          cvss_score: CVSS评分[0, 10]
          poc_activity_score: PoC活动信号[0, 1]
          kev_listed: 是否在CISA KEV中
          disclosure_days: 漏洞已公开天数(条件生存分析)

        返回TemporalForecast。
        """
        # 协变量标准化至[-1, 1]
        x_complex = (complexity.overall_complexity - 0.5) * 2.0
        x_cvss = (cvss_score - 5.0) / 5.0
        x_poc = (poc_activity_score - 0.5) * 2.0
        x_kev = 1.0 if kev_listed else 0.0

        # 尺度参数λ
        log_lam = (self._BETA['intercept'] +
                   self._BETA['complexity'] * x_complex +
                   self._BETA['cvss'] * x_cvss +
                   self._BETA['poc_activity'] * x_poc +
                   self._BETA['kev_listed'] * x_kev)
        lam = max(1.0, math.exp(log_lam))

        # 形状参数k——基于复杂度调整
        if complexity.complexity_tier == "EXTREME":
            k = 1.8
        elif complexity.complexity_tier == "HIGH":
            k = 1.4
        elif complexity.complexity_tier == "LOW":
            k = 0.8
        else:
            k = 1.2

        # 条件生存——若已过disclosure_days天未被利用
        base_survival = {t: self._survival(t, lam, k)
                         for t in [7, 30, 90, 180]}
        if disclosure_days > 0:
            s_given = self._survival(disclosure_days, lam, k)
            for t in base_survival:
                if t > disclosure_days:
                    base_survival[t] = (self._survival(t, lam, k) /
                                        max(s_given, 1e-10))
                else:
                    base_survival[t] = 1.0

        # 分位数
        t_median = lam * (math.log(2)) ** (1.0 / k)
        t_10pct = lam * (-math.log(0.9)) ** (1.0 / k)
        t_50pct = t_median

        # 风险率 h(t) = (k/λ) × (t/λ)^(k-1)
        eval_t = max(disclosure_days, 30.0)
        hazard = (k / lam) * ((eval_t / lam) ** (k - 1)) if lam > 0 else 0.0

        hazard_trend = "increasing" if k > 1.1 else (
            "decreasing" if k < 0.9 else "stable")

        return TemporalForecast(
            survival_7d=round(base_survival[7], 4),
            survival_30d=round(base_survival[30], 4),
            survival_90d=round(base_survival[90], 4),
            survival_180d=round(base_survival[180], 4),
            median_time_to_exploit=round(t_median, 1),
            time_to_10pct_risk=round(t_10pct, 1),
            time_to_50pct_risk=round(t_50pct, 1),
            hazard_30d=round(hazard, 6),
            hazard_trend=hazard_trend,
            weibull_lambda=round(lam, 1),
            weibull_k=round(k, 2),
            model_confidence=self._confidence(complexity, cvss_score))

    @staticmethod
    def _survival(t: float, lam: float, k: float) -> float:
        """威布尔生存函数 S(t) = exp(-(t/λ)^k)"""
        if lam <= 0:
            return 0.0
        return math.exp(-((t / lam) ** k))

    @staticmethod
    def _confidence(complexity: ExploitComplexity, cvss: float) -> str:
        if complexity.overall_complexity > 0.7 and cvss > 7.0:
            return "HIGH"
        if complexity.overall_complexity < 0.3:
            return "HIGH"
        return "MEDIUM"


__all__ = [
    "TemporalForecast",
    "WeibullAFT",
]
