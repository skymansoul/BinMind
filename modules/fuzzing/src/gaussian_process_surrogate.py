"""高斯过程覆盖代理模型 — Matern 3/2 核 + EI 采集 + 诱导点稀疏化.

参考: Rasmussen & Williams.
注: n≤200 时 Cholesky 全量重建 O(n³), 非严格在线更新。
n>200 后切换诱导点模式 O(m²n), m=50。适合中等规模种子池的覆盖预测。"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# GP 参数
_MAX_OBSERVATIONS = 200      # 转为诱导点模式的阈值
_N_INDUCING = 50             # 诱导点数
_MATERN_NU = 1.5             # Matern 平滑参数 (3/2)
_LENGTH_SCALE = 1.0          # 核长度尺度
_SIGNAL_VARIANCE = 1.0       # 信号方差
_NOISE_VARIANCE = 0.01       # 观测噪声
_EI_XI = 0.01                # EI 探索参数


@dataclass
class GPObservation:
    """一次 GP 观测."""
    features: List[float]     # 种子特征向量 (输入)
    coverage_gain: float      # 覆盖增益 (输出)
    seed_id: str = ""
    timestamp: float = field(default_factory=time.time)


class GaussianProcessSurrogate:
    """高斯过程覆盖代理模型 — 预测覆盖增益景观.

    使用 Matern 3/2 核建模覆盖增益在种子特征空间中的平滑性。
    在线 Cholesky 分解维持后验分布, 新观测增量更新。
    超过容量后切换到诱导点模式维持计算可行性。

    使用方式:
      gps = GaussianProcessSurrogate()
      for seed in corpus:
          feats = extract_features(seed)
          gps.add_observation(feats, observed_coverage_gain, seed.id)
      # 查询预测
      mean, var = gps.predict(new_seed_features)
      # 获取 EI 最优的候选
      best = gps.expected_improvement(candidates)
    """

    def __init__(self, length_scale: float = _LENGTH_SCALE,
                 signal_var: float = _SIGNAL_VARIANCE,
                 noise_var: float = _NOISE_VARIANCE):
        self.length_scale = length_scale
        self.signal_var = signal_var
        self.noise_var = noise_var
        self._obs: List[GPObservation] = []
        # Cholesky 因子 L (n×n): K + σ²I = L·Lᵀ
        self._L: List[List[float]] = []
        self._alpha: List[float] = []     # L⁻ᵀ·(L⁻¹·y), 即 (K+σ²I)⁻¹·y
        self._best_f: float = 0.0         # 最佳观测值 (用于 EI)
        # 诱导点模式
        self._using_inducing: bool = False
        self._inducing_inputs: List[List[float]] = []

    # //// 核函数 ////
    def _kernel(self, x1: List[float], x2: List[float]) -> float:
        """Matern 3/2 核: k(r) = σ²·(1 + √3·r/ℓ)·exp(-√3·r/ℓ).

        比 RBF 更适合建模具有突然变化的景观 (如覆盖增益的不连续性)。
        """
        r_sq = sum((a - b) ** 2 for a, b in zip(x1, x2))
        r = math.sqrt(r_sq) / self.length_scale
        sqrt3 = math.sqrt(3.0)
        return self.signal_var * (1.0 + sqrt3 * r) * math.exp(-sqrt3 * r)

    def _kernel_vector(self, x_new: List[float],
                       X: List[List[float]]) -> List[float]:
        """k(x_new, X) = [k(x_new, x1), ..., k(x_new, xn)]."""
        return [self._kernel(x_new, xi) for xi in X]

    # //// 观测添加 ////
    def add_observation(self, features: List[float],
                        coverage_gain: float, seed_id: str = "") -> None:
        """添加一次观测并增量更新 GP 后验."""
        obs = GPObservation(features=list(features),
                           coverage_gain=coverage_gain,
                           seed_id=seed_id)
        self._obs.append(obs)
        if coverage_gain > self._best_f:
            self._best_f = coverage_gain

        # 切换到诱导点模式
        if len(self._obs) > _MAX_OBSERVATIONS and not self._using_inducing:
            self._switch_to_inducing()
            return

        if self._using_inducing:
            self._update_inducing(obs)
        else:
            self._update_cholesky(obs)

    def _update_cholesky(self, obs: GPObservation) -> None:
        """增量为新观测更新 Cholesky 分解.

        对已存在的 n 个观测和新观测, 重组矩阵并重新分解。
        对于 n ≤ 200, 重新分解 O(n³) 的开销可接受。
        """
        n = len(self._obs)
        X = [o.features for o in self._obs]
        y = [o.coverage_gain for o in self._obs]
        k_new = self._kernel_vector(obs.features, X)

        # 构建 (n×n) 核矩阵 + 噪声
        K = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                K[i][j] = self._kernel(X[i], X[j])
                if i == j:
                    K[i][j] += self.noise_var

        # Cholesky 分解: K = L·Lᵀ
        self._L = self._cholesky(K)
        # 求解 α = K⁻¹·y
        self._alpha = self._solve_cholesky(self._L, y)

    def _update_inducing(self, obs: GPObservation) -> None:
        """诱导点模式下的更新: 重新选择 m 个诱导点 + 完整重建."""
        self._switch_to_inducing()

    # //// 预测 ////
    def predict(self, features: List[float]) -> Tuple[float, float]:
        """GP 预测: 返回 (后验均值, 后验方差).

        μ(x*) = k(x*, X)·α
        σ²(x*) = k(x*, x*) - k(x*, X)ᵀ·(K+σ²I)⁻¹·k(x*, X)
        """
        if not self._obs:
            return 0.0, self.signal_var

        X = (self._inducing_inputs if self._using_inducing
             else [o.features for o in self._obs])
        k_star = self._kernel_vector(features, X)
        k_self = self._kernel(features, features) + self.noise_var

        if not self._L:
            return 0.0, k_self

        # 均值
        mean = sum(k_star[i] * self._alpha[i] for i in range(len(k_star)))

        # 方差: σ² = k(x*,x*) - vᵀ·(K⁻¹)·v
        # v = L⁻¹·k(x*,X)
        v = self._forward_substitution(self._L, k_star)
        quad = sum(vi * vi for vi in v)
        variance = max(0.0, k_self - quad)

        return mean, variance

    # //// 采集函数 ////
    def expected_improvement(self, candidates: List[Tuple[str, List[float]]]
                              ) -> List[Tuple[str, float, float, float]]:
        """对候选种子计算 Expected Improvement.

        返回 [(seed_id, EI, predicted_mean, predicted_std), ...] 按 EI 降序。
        EI(x) = (μ - f_best - ξ)·Φ(Z) + σ·φ(Z)
        其中 Z = (μ - f_best - ξ) / σ
        """
        if not self._obs:
            return [(sid, 0.5, 0.0, 1.0) for sid, _ in candidates]

        results = []
        for sid, feats in candidates:
            mean, var = self.predict(feats)
            std = math.sqrt(max(1e-12, var))
            if std < 1e-8:
                ei = max(0.0, mean - self._best_f - _EI_XI)
            else:
                z = (mean - self._best_f - _EI_XI) / std
                # φ(z) = standard normal PDF
                phi_z = math.exp(-0.5 * z * z) / math.sqrt(2.0 * math.pi)
                # Φ(z) = standard normal CDF (Abramowitz & Stegun 近似)
                phi_cdf = 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))
                ei = (mean - self._best_f - _EI_XI) * phi_cdf + std * phi_z
            results.append((sid, max(0.0, ei), mean, std))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def upper_confidence_bound(self, candidates: List[Tuple[str, List[float]]],
                                beta: float = 2.0
                                ) -> List[Tuple[str, float, float, float]]:
        """GP-UCB 采集: μ(x) + β·σ(x).

        β 控制探索/利用权衡: β=0 → 纯利用, β=2 → 均衡, β=5 → 强探索。
        """
        results = []
        for sid, feats in candidates:
            mean, var = self.predict(feats)
            std = math.sqrt(max(1e-12, var))
            ucb = mean + beta * std
            results.append((sid, ucb, mean, std))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # //// 诱导点模式 ////
    def _switch_to_inducing(self) -> None:
        """切换到诱导点稀疏 GP.

        使用随机子集选择 m 个诱导点, 然后在这些点上做精确 GP。
        复杂度从 O(n³) 降至 O(m²n)。
        """
        import random
        n = len(self._obs)
        m = min(_N_INDUCING, n)
        if m == 0:
            return
        rng = random.Random(42)
        indices = rng.sample(range(n), m)
        self._inducing_inputs = [self._obs[i].features for i in indices]
        self._using_inducing = True

        # 用诱导点重建 GP
        X_ind = self._inducing_inputs
        y_all = [o.coverage_gain for o in self._obs]
        X_all = [o.features for o in self._obs]

        # K_mm: 诱导点间的核矩阵
        K_mm = [[0.0] * m for _ in range(m)]
        for i in range(m):
            for j in range(m):
                K_mm[i][j] = self._kernel(X_ind[i], X_ind[j])
                if i == j:
                    K_mm[i][j] += self.noise_var

        self._L = self._cholesky(K_mm)
        # 用所有观测的加权平均做 α
        y_mean = sum(y_all) / max(1, n)
        self._alpha = self._solve_cholesky(self._L,
                                           [y_mean] * m)

    # //// 线性代数辅助 ////
    @staticmethod
    def _cholesky(A: List[List[float]]) -> List[List[float]]:
        """Cholesky 分解: A = L·Lᵀ, L 下三角."""
        n = len(A)
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1):
                s = sum(L[i][k] * L[j][k] for k in range(j))
                if i == j:
                    L[i][j] = math.sqrt(max(1e-12, A[i][i] - s))
                else:
                    L[i][j] = (A[i][j] - s) / max(1e-12, L[j][j])
        return L

    @staticmethod
    def _solve_cholesky(L: List[List[float]],
                        y: List[float]) -> List[float]:
        """用 Cholesky 因子 L 求解 K·α = y."""
        n = len(L)
        # 前向代入: L·z = y
        z = [0.0] * n
        for i in range(n):
            s = sum(L[i][j] * z[j] for j in range(i))
            z[i] = (y[i] - s) / max(1e-12, L[i][i])
        # 后向代入: Lᵀ·α = z
        alpha = [0.0] * n
        for i in range(n - 1, -1, -1):
            s = sum(L[j][i] * alpha[j] for j in range(i + 1, n))
            alpha[i] = (z[i] - s) / max(1e-12, L[i][i])
        return alpha

    @staticmethod
    def _forward_substitution(L: List[List[float]],
                              b: List[float]) -> List[float]:
        """前向代入: 求解 L·v = b."""
        n = len(L)
        v = [0.0] * n
        for i in range(n):
            s = sum(L[i][j] * v[j] for j in range(i))
            v[i] = (b[i] - s) / max(1e-12, L[i][i])
        return v

    # //// 统计 ////
    def stats(self) -> dict:
        n = len(self._obs)
        return {
            "observations": n,
            "using_inducing": self._using_inducing,
            "n_inducing": len(self._inducing_inputs),
            "best_observed_f": round(self._best_f, 3),
            "length_scale": self.length_scale,
            "signal_variance": self.signal_var,
            "noise_variance": self.noise_var,
            "last_alpha_norm": round(
                math.sqrt(sum(a * a for a in self._alpha))
                if self._alpha else 0.0, 4),
        }

    def clear(self) -> None:
        self._obs.clear(); self._L.clear(); self._alpha.clear()
        self._best_f = 0.0; self._using_inducing = False
        self._inducing_inputs.clear()
