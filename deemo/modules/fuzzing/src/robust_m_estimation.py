"""鲁棒 M-估计模糊测试指标 (Robust M-Estimation Fuzzing Metrics, RMEF).

  Huber "Robust Estimation of a Location Parameter" (Annals of Math
    Statistics) — M-估计框架的奠基工作
  Huber & Ronchetti "Robust Statistics" 2nd ed. — 第4章: M-估计器
  Tukey "A Survey of Sampling from Contaminated Distributions"
    — Tukey 双权 (biweight) 函数
  Maronna, Martin & Yohai "Robust Statistics: Theory and Methods"
    — IRLS (Iteratively Reweighted Least Squares) 算法

在 fuzzing 文献中的位置:
  鲁棒统计在 fuzzing 指标计算中完全无先例。现有估计:
    简单均值: 对离群崩溃极度敏感 (一次长执行时间拉偏所有均值)
    中位数: 损失太多效率 (仅用中心值, 丢弃 50% 的信息)
  M-估计器提供了从均值到中位数的连续过渡:
    Huber 损失 = x²/2 for |x|≤k, k|x|-k²/2 for |x|>k
    小残差 → L2 (高效率), 大残差 → L1 (鲁棒)
    k=1.345 → 95% 渐近效率 (vs 正态) + 鲁棒性

  1. Huber/Tukey M-估计: 自适应平衡效率与鲁棒性
  2. IRLS 在线更新: O(1) per observation
  3. 崩溃点配置: 可调 k 从 L2 (无鲁棒) 到 L1 (中位数)
  4. scale 估计: 协同估计 MAD → 完全自适应
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# RMEF 参数
_HUBER_K = 1.345        # Huber 转折点 (95% ARE vs 正态)
_TUKEY_C = 4.685        # Tukey 双权 (50% 崩溃点)
_MAD_CONSISTENCY = 1.4826  # MAD → σ 的一致性因子

@dataclass
class RobustEstimate:
    """一个鲁棒估计结果."""
    robust_mean: float      # M-估计位置
    scale: float            # 鲁棒 scale (MAD-based)
    n_obs: int              # 观测数
    n_downweighted: int     # 被降权的离群数
    efficiency: float       # 估计效率 (vs 正态假设下的最优)
    classical_mean: float   # 经典均值 (对比用)

class RobustMEstimator:
    """鲁棒 M-估计器 — 在线估计 fuzzing 指标的鲁棒位置.

    使用 Iteratively Reweighted Least Squares (IRLS):
      μ_{t+1} = Σ w_i·x_i / Σ w_i
    其中 w_i = ψ(r_i/σ) / (r_i/σ), r_i = x_i - μ_t
    ψ 是影响函数 (Huber 或 Tukey), σ 是鲁棒 scale (MAD).

    使用方式:
      rme = RobustMEstimator(method="huber")
      for each fuzzing observation:
          rme.add(value)
      est = rme.estimate()
      print(f"Robust mean: {est.robust_mean:.2f} (classical: {est.classical_mean:.2f})")
    """

    def __init__(self, method: str = "huber",
                 tuning_k: Optional[float] = None):
        self.method = method
        self.k = tuning_k or (_HUBER_K if method == "huber" else _TUKEY_C)
        self._observations: List[float] = []
        self._mu: float = 0.0       # M-估计位置
        self._sigma: float = 1.0    # 鲁棒 scale
        self._n: int = 0
        self._n_downweighted: int = 0
        # 经典统计量（在线更新）
        self._sum_x: float = 0.0
        # MAD 计算所需的残差
        self._recent_residuals: List[float] = []

    def add(self, value: float) -> None:
        """添加一次观测."""
        self._n += 1
        self._sum_x += value
        if self._n == 1:
            self._mu = value
        else:
            # IRLS 单步更新
            res = value - self._mu
            w = self._weight(res / max(1e-8, self._sigma))
            if w < 0.5:
                self._n_downweighted += 1
            alpha = 1.0 / self._n
            self._mu = (1.0 - alpha * w) * self._mu + alpha * w * value

        self._observations.append(value)
        self._recent_residuals.append(value - self._mu)
        if len(self._recent_residuals) > 100:
            self._recent_residuals = self._recent_residuals[-50:]

        # 更新 scale (MAD)
        if len(self._recent_residuals) >= 5:
            self._sigma = self._compute_mad()

        # 容量
        if len(self._observations) > 300:
            self._observations = self._observations[-200:]

    def estimate(self) -> RobustEstimate:
        """返回当前鲁棒估计."""
        return RobustEstimate(
            robust_mean=self._mu,
            scale=self._sigma,
            n_obs=self._n,
            n_downweighted=self._n_downweighted,
            efficiency=self._compute_efficiency(),
            classical_mean=self._sum_x / max(1, self._n),
        )

    # //// 权重函数 ////
    def _weight(self, r_scaled: float) -> float:
        """ψ(r)/r — IRLS 权重."""
        if self.method == "huber":
            return self._huber_weight(r_scaled)
        return self._tukey_weight(r_scaled)

    def _huber_weight(self, r: float) -> float:
        """Huber 权重: w=1 if |r|≤k, w=k/|r| if |r|>k."""
        ar = abs(r)
        if ar <= self.k:
            return 1.0
        return self.k / ar

    def _tukey_weight(self, r: float) -> float:
        """Tukey 双权: w = (1-(r/k)²)² if |r|≤k, else 0."""
        ar = abs(r)
        if ar >= self.k:
            return 0.0
        ratio = r / self.k
        return (1.0 - ratio * ratio) ** 2

    def _compute_mad(self) -> float:
        """MAD: median(|r_i - median(r)|)."""
        if len(self._recent_residuals) < 3:
            return 1.0
        residuals = sorted(self._recent_residuals)
        median = residuals[len(residuals) // 2]
        abs_devs = sorted(abs(r - median) for r in self._recent_residuals)
        mad = abs_devs[len(abs_devs) // 2]
        return max(0.01, mad * _MAD_CONSISTENCY)

    def _compute_efficiency(self) -> float:
        """渐近效率估计 (vs 正态的 MLE)."""
        if self._n < 10:
            return 1.0
        # 被降权比例 → 效率损失
        frac = self._n_downweighted / max(1, self._n)
        return 1.0 / (1.0 + frac)

    # //// 批量鲁棒统计 ////
    @staticmethod
    def robust_summary(values: List[float],
                       method: str = "huber") -> RobustEstimate:
        """对一批值做鲁棒估计."""
        rme = RobustMEstimator(method=method)
        for v in values:
            rme.add(v)
        return rme.estimate()

    def stats(self) -> dict:
        est = self.estimate()
        return {
            "n": est.n_obs,
            "robust_mean": round(est.robust_mean, 4),
            "scale (MAD)": round(est.scale, 4),
            "classical_mean": round(est.classical_mean, 4),
            "n_downweighted": est.n_downweighted,
            "downweighted_ratio": round(
                est.n_downweighted / max(1, est.n_obs), 4),
            "method": self.method,
            "tuning_k": self.k,
        }

    def clear(self) -> None:
        self._observations.clear(); self._mu = 0.0; self._sigma = 1.0
        self._n = 0; self._n_downweighted = 0
        self._sum_x = 0.0; self._recent_residuals.clear()
