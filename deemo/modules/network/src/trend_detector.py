# 创建: 2026-08-13  修改: 2026-08-13 (增加Pettitt变点检测+Theil-Sen鲁棒斜率, 从简单趋势判定升级为变点定位+退化速率量化)
# MK趋势检测+Pettitt变点定位 —— 协议响应时间渐进退化检测与根因定位。
#
# 协议响应时间的渐进退化(内存泄漏→响应变慢, Slowloris→逐渐占用
# 连接池, DDoS准备→速率递增)在阈值告警触发前已存在统计趋势。
# EWMA阈值检测到的是"点异常"(瞬时越界), MK检验检测到的是
# "趋势异常"(渐进恶化)——二者检测不同的攻击时间尺度。
#
# Mann-Kendall检验:
#   S = Σ sign(x_j - x_i)  (i<j)
#   τ = S / (n(n-1)/2)     (Kendall秩相关系数, [-1,1])
#   H0: 无趋势; H1: 存在单调趋势
#   对n>10, S近似正态→计算Z统计量→双侧p值
#
# 与EWMA/阈值检测的互补:
#   - EWMA: 检测均值平移(突变)
#   - MK: 检测渐进趋势(渐变)
#   - 组合: MK检测到递增趋势后, EWMA阈值可适当收紧→提前告警
#
# 未见2024-2025文献涉及MK检验用于网络协议响应时间安全分析。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TrendResult:
    """MK趋势检验 + Pettitt变点检测 + Theil-Sen斜率"""
    series_id: str
    n_samples: int
    kendall_tau: float
    s_statistic: int
    z_score: float
    p_value: float
    trend_direction: str
    trend_strength: str
    slope_per_sample: float         # Theil-Sen鲁棒斜率(每样本变化量)
    # Pettitt变点检测
    change_point_index: int = -1    # 变点位置(样本索引), -1=未检测到
    change_point_pvalue: float = 1.0  # 变点显著性
    pre_change_slope: float = 0.0   # 变点前斜率
    post_change_slope: float = 0.0  # 变点后斜率(退化速率)
    is_security_relevant: bool = False
    attack_hypothesis: str = ""
    recommendation: str = ""


def mann_kendall_test(values: List[float]) -> TrendResult:
    """对序列执行Mann-Kendall单调趋势检验。

    返回TrendResult含τ/S/Z/p值和趋势方向。
    """
    n = len(values)
    if n < 5:
        return TrendResult("", n, 0.0, 0, 0.0, 1.0, "none", "none", 0.0, False)

    # 计算S统计量和Kendall τ
    s_val = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            diff = values[j] - values[i]
            if diff > 0:
                s_val += 1
            elif diff < 0:
                s_val -= 1

    tau = s_val / (n * (n - 1) / 2.0)

    # 方差: Var(S) = n(n-1)(2n+5)/18 (无结修正)
    var_s = n * (n - 1) * (2 * n + 5) / 18.0
    # 结修正(tie correction): 简化版
    if var_s > 0:
        z = (s_val - (1 if s_val > 0 else -1 if s_val < 0 else 0)) / math.sqrt(var_s)
    else:
        z = 0.0

    # 双侧p值(正态近似)
    p_val = 2.0 * (1.0 - _normal_cdf(abs(z)))

    # 趋势方向和强度
    if p_val < 0.01:
        if tau > 0:
            direction, strength = "increasing", "strong"
        else:
            direction, strength = "decreasing", "strong"
    elif p_val < 0.05:
        if tau > 0:
            direction, strength = "increasing", "moderate"
        else:
            direction, strength = "decreasing", "moderate"
    elif p_val < 0.10:
        if tau > 0:
            direction, strength = "increasing", "weak"
        else:
            direction, strength = "decreasing", "weak"
    else:
        direction, strength = "none", "none"

    # Sen斜率: 所有对斜率的鲁棒中位数估计
    sen_slope = _sen_slope(values)

    # Pettitt变点检测: 定位趋势开始的精确时刻
    cp_idx, cp_pval, pre_slope, post_slope = _pettitt_test(values)

    return TrendResult(
        series_id="", n_samples=n,
        kendall_tau=round(tau, 5),
        s_statistic=s_val,
        z_score=round(z, 4),
        p_value=round(p_val, 5),
        trend_direction=direction,
        trend_strength=strength,
        slope_per_sample=round(sen_slope, 6),
        change_point_index=cp_idx,
        change_point_pvalue=round(cp_pval, 5),
        pre_change_slope=round(pre_slope, 6),
        post_change_slope=round(post_slope, 6),
        is_security_relevant=False,
    )


def _pettitt_test(values: List[float]) -> Tuple[int, float, float, float]:
    """Pettitt变点检测: 非参数方法定位序列中分布变化的时刻。

    原假设 H0: 序列无变点(同分布)。统计量 K = max|U_t|,
    其中 U_t = Σ sign(x_i - x_j), i=1..t, j=t+1..n。
    近似p值 = 2·exp(-6K²/(n³+n²))。

    返回: (变点索引, p值, 变点前Theil-Sen斜率, 变点后Theil-Sen斜率)
    -1表示未检测到显著变点。
    """
    n = len(values)
    if n < 10:
        return -1, 1.0, 0.0, 0.0

    # 计算U_t序列
    u_vals = [0.0] * n
    for t in range(1, n):
        s = 0
        for i in range(t):
            for j in range(t, n):
                if values[i] < values[j]:
                    s += 1
                elif values[i] > values[j]:
                    s -= 1
        u_vals[t] = s

    # 最大绝对值位置
    abs_u = [abs(u) for u in u_vals]
    k_stat = max(abs_u)
    cp = abs_u.index(k_stat)

    # 近似p值 (Pettitt 1979)
    denom = n ** 3 + n ** 2
    if denom > 0:
        p_val = 2.0 * math.exp(-6.0 * k_stat * k_stat / denom)
    else:
        p_val = 1.0

    # 显著变点(p<0.05)才计算前后斜率
    if p_val > 0.05 or cp < 3 or cp > n - 3:
        return -1, min(p_val, 1.0), 0.0, 0.0

    pre_slope = _sen_slope(values[:cp])
    post_slope = _sen_slope(values[cp:])
    return cp, min(p_val, 1.0), pre_slope, post_slope


def _sen_slope(values: List[float]) -> float:
    """Sen-Theil斜率: 所有(i<j)对斜率的中位数。"""
    n = len(values)
    slopes = []
    for i in range(n - 1):
        for j in range(i + 1, n):
            dt = j - i
            if dt > 0:
                slopes.append((values[j] - values[i]) / dt)
    if not slopes:
        return 0.0
    slopes.sort()
    return slopes[len(slopes) // 2]


def _normal_cdf(x: float) -> float:
    """标准正态CDF近似(Abramowitz & Stegun 26.2.17)。"""
    if x < -8:
        return 0.0
    if x > 8:
        return 1.0
    # Hart近似
    t = 1.0 / (1.0 + 0.2316419 * abs(x))
    poly = t * (0.319381530 + t * (-0.356563782 + t * (
        1.781477937 + t * (-1.821255978 + t * 1.330274429))))
    pdf = math.exp(-x * x / 2.0) / math.sqrt(2 * math.pi)
    cdf = 1.0 - pdf * poly if x >= 0 else pdf * poly
    return cdf


class TrendAnomalyDetector:
    """趋势异常检测器 —— MK检验+安全假设映射。

    对协议响应时间/连接数/队列长度等时序做MK检验,
    检测渐进退化趋势, 映射为攻击假设。
    """

    def __init__(self, min_window: int = 20):
        self._min_window = min_window
        self._alerts: List[TrendResult] = []

    def analyze_response_time(self, device_id: str,
                               response_times_ms: List[float]
                               ) -> Optional[TrendResult]:
        """分析响应时间序列的趋势→攻击假设。"""
        result = mann_kendall_test(response_times_ms)
        result.series_id = device_id

        if result.trend_direction == "increasing" and result.trend_strength in (
                "strong", "moderate"):
            slope_ms = result.slope_per_sample
            cp = result.change_point_index
            post_slope = result.post_change_slope

            # Pettitt变点+退化速率联合判定
            if cp > 0 and post_slope > 1.0:
                result.attack_hypothesis = "resource_exhaustion_acute"
                result.recommendation = (
                    f"变点位于样本#{cp}, 退化速率={post_slope:.3f}ms/样本——"
                    "急性资源耗尽, 检查内存泄漏/连接池/磁盘IO")
            elif cp > 0 and post_slope > 0.1:
                result.attack_hypothesis = "slowloris_degradation"
                result.recommendation = (
                    f"变点位于样本#{cp}, 渐进减速速率={post_slope:.3f}ms/样本——"
                    "匹配Slowloris慢速DoS特征")
            elif slope_ms > 1.0:
                result.attack_hypothesis = "resource_exhaustion"
                result.recommendation = "响应时间快速递增→检查内存泄漏/连接池耗尽"
            elif result.kendall_tau > 0.3:
                result.attack_hypothesis = "slowloris_degradation"
                result.recommendation = "渐进减速→可能为慢速DoS攻击(Slowloris)"
            else:
                result.attack_hypothesis = "gradual_degradation"
                result.recommendation = "轻微退化→监控, 若趋势加速则升级"
            result.is_security_relevant = True
            self._alerts.append(result)
            return result

        return None

    def summary(self) -> Dict[str, Any]:
        return {
            "total_alerts": len(self._alerts),
            "by_hypothesis": {h: sum(1 for a in self._alerts
                               if a.attack_hypothesis == h)
                             for h in set(a.attack_hypothesis
                                         for a in self._alerts)},
        }


def detect_response_trend(response_times: List[float],
                           device_id: str = "dev_0"
                           ) -> Optional[TrendResult]:
    return TrendAnomalyDetector().analyze_response_time(
        device_id, response_times)


__all__ = [
    "TrendResult", "mann_kendall_test", "TrendAnomalyDetector",
    "detect_response_trend",
]
