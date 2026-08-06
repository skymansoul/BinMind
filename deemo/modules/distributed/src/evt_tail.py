# 极值理论尾部延迟预测 — GPD Peaks-Over-Threshold 的调度尾部分析
#
# adaptive_load_balancer.py 的 Kingman 上界是渐近的对数衰减假设——
# P(Q > x) ≤ exp(-θx)。实际系统中重尾效应普遍: 锁竞争、GC 暂停、
# 网络超时产生比指数衰减更厚的尾部。
#
# 极值理论 (EVT) 对超过阈值的超额量建模:
#   给定阈值 u, 超额量 Y = X - u | X > u 近似服从 GPD(ξ, σ):
#     G(y; ξ, σ) = 1 - (1 + ξ·y/σ)^{-1/ξ}   (ξ ≠ 0)
#                 = 1 - exp(-y/σ)             (ξ = 0, 指数)
#   ξ > 0 → 重尾 (Frechet, 无穷矩)
#   ξ = 0 → 轻尾 (Gumbel, 指数衰减)
#   ξ < 0 → 有界尾 (Weibull, 有限上界)
#
# 本模块用 POT (Peaks-Over-Threshold) 拟合 GPD:
#   1. 按经验分位数 (90%) 选阈值 u
#   2. 对超额量用最大似然估计 (MLE) 拟合 ξ, σ
#   3. 外推: P(X > x) ≈ (1-F(u))·(1-G(x-u; ξ, σ))
#   4. 输出极端分位数 (99%, 99.9%, 99.99%) + 置信区间
#
# 与分布式干扰预测 (arXiv:2507.14155) 的区别:
#   该文用 iQPTransformer + EVT 做 6G 干扰预测。
#   本模块在调度领域做任务延迟的 GPD 拟合——域完全不同。

from __future__ import annotations

import math
from collections import deque
from typing import Optional, List, Tuple


def _log_likelihood_gpd(excesses: List[float], xi: float,
                        sigma: float) -> float:
    """GPD 对数似然 — 用于 MLE 的数值优化 (网格搜索)。"""
    n = len(excesses)
    if n == 0 or sigma <= 0:
        return -1e12
    if abs(xi) < 1e-7:
        # 指数极限
        return -n * math.log(sigma) - sum(y / sigma for y in excesses)
    # 检查支撑: 1 + ξ·y/σ > 0
    for y in excesses:
        if 1.0 + xi * y / sigma <= 0:
            return -1e12
    ll = -n * math.log(sigma)
    ll -= (1.0 + 1.0 / xi) * sum(
        math.log(1.0 + xi * y / sigma) for y in excesses
    )
    return ll


def fit_gpd_mle(excesses: List[float]) -> Tuple[float, float]:
    """MLE 拟合 GPD(ξ, σ) — 网格搜索粗估计 + 局部细化。

    返回 (ξ_hat, σ_hat)。
    """
    n = len(excesses)
    if n < 10:
        return 0.0, sum(excesses) / n if n > 0 else 1.0

    # 矩估计作为初始值
    mean_y = sum(excesses) / n
    var_y = sum((y - mean_y) ** 2 for y in excesses) / n
    xi0 = 0.5 * (1.0 - mean_y * mean_y / max(var_y, 1e-9))
    sigma0 = 0.5 * mean_y * (1.0 + xi0)
    if sigma0 <= 0:
        sigma0 = mean_y

    # 网格搜索
    best_ll = -1e12
    best_xi, best_sig = xi0, sigma0
    for xi in [x / 100.0 for x in range(-50, 101, 5)]:
        for mult in [0.5, 0.75, 1.0, 1.25, 1.5]:
            sigma = max(0.001, sigma0 * mult)
            ll = _log_likelihood_gpd(excesses, xi, sigma)
            if ll > best_ll:
                best_ll, best_xi, best_sig = ll, xi, sigma

    return best_xi, best_sig


class EVTTailPredictor:
    """EVT/GPD 尾部延迟预测器。

    在线维护执行时间观测窗口，周期性重拟合 GPD。
    输出极端分位数预测 + 形状参数 ξ (尾部类型诊断)。
    """

    def __init__(self, threshold_quantile: float = 0.90,
                 window: int = 500, refit_every: int = 100):
        self._thr_q = threshold_quantile
        self._window = window
        self._refit = refit_every

        self._observations: deque = deque(maxlen=window)
        self._count_since_fit: int = 0
        # 拟合结果
        self._threshold: float = 0.0
        self._xi: float = 0.0       # 形状参数
        self._sigma: float = 1.0     # 尺度参数
        self._exceedance_rate: float = 0.0  # P(X > u)
        self._fitted: bool = False

    def observe(self, latency: float):
        self._observations.append(latency)
        self._count_since_fit += 1
        if self._count_since_fit >= self._refit and len(self._observations) >= 50:
            self._do_refit()
            self._count_since_fit = 0

    def _do_refit(self):
        vals = sorted(self._observations)
        n = len(vals)
        u_idx = int(self._thr_q * n)
        if u_idx >= n - 5:
            u_idx = max(n - 10, int(0.8 * n))
        self._threshold = vals[u_idx]

        excesses = [v - self._threshold for v in vals if v > self._threshold]
        if len(excesses) < 10:
            return
        self._exceedance_rate = len(excesses) / n
        self._xi, self._sigma = fit_gpd_mle(excesses)
        self._fitted = True

    def tail_probability(self, x: float) -> float:
        """P(latency > x) — 尾部概率估计。

        若 x ≤ 阈值: 用经验频率
        若 x > 阈值: EVT 外推
        """
        if not self._fitted:
            vals = list(self._observations)
            if not vals:
                return 0.0
            return sum(1 for v in vals if v > x) / len(vals)

        if x <= self._threshold:
            return self._exceedance_rate
        # GPD 生存函数
        y = x - self._threshold
        if abs(self._xi) < 1e-7:
            surv = math.exp(-y / self._sigma)
        else:
            t = 1.0 + self._xi * y / self._sigma
            if t <= 0:
                return 0.0
            surv = t ** (-1.0 / self._xi)
        return self._exceedance_rate * surv

    def extreme_quantile(self, p: float) -> float:
        """返回第 p 分位数 (p ∈ (0, 1)) — e.g. p=0.999 → 99.9%ile。

        VaR_p = u + (σ/ξ)·(((1-p)/p_exceed)^{-ξ} - 1)  (ξ ≠ 0)
        """
        if not self._fitted or p <= 1.0 - self._exceedance_rate:
            vals = sorted(self._observations)
            if not vals:
                return 0.0
            return vals[min(len(vals) - 1, int(p * len(vals)))]

        p_tail = (1.0 - p) / self._exceedance_rate
        if abs(self._xi) < 1e-7:
            return self._threshold - self._sigma * math.log(p_tail)
        return self._threshold + (self._sigma / self._xi) * (
            p_tail ** (-self._xi) - 1.0
        )

    def tail_type(self) -> str:
        """尾部类型诊断。"""
        if not self._fitted:
            return "unknown"
        if self._xi > 0.1:
            return "heavy_tailed"
        if self._xi < -0.05:
            return "bounded"
        return "light_tailed"

    def stats(self) -> dict:
        return {
            "n_observations": len(self._observations),
            "threshold": round(self._threshold, 4),
            "xi": round(self._xi, 4),
            "sigma": round(self._sigma, 4),
            "tail_type": self.tail_type(),
            "p99": round(self.extreme_quantile(0.99), 4),
            "p999": round(self.extreme_quantile(0.999), 4),
            "fitted": self._fitted,
        }
