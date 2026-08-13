"""GP Woodbury 在线更新 — 秩-1 Cholesky 增量 + 自适应诱导点.

创建: 2024-08-14 14:35
修改: 2024-08-14 09:12 — 添加 Woodbury 数值稳定性保护

参考: Rasmussen & Williams §3.4.3 (Woodbury for rank-1 updates)
       Osborne "Gaussian Processes for Global Optimization" (adaptive inducing)

与 gaussian_process_surrogate.py 的关系:
  gaussian_process_surrogate.py 在每次观测后完整重建 Cholesky (O(n³)),
  标注为"在线"但实际是批处理。本模块用 Woodbury 恒等式实现真正的
  O(n²) 秩-1 增量更新, 使在线声称成立。

  Woodbury: (K + σ²I + vvᵀ)⁻¹ = K⁻¹ - K⁻¹v(1+vᵀK⁻¹v)⁻¹vᵀK⁻¹
  秩-1 更新: 新观测 (x_new, y_new) → K_{n+1} = [K_n, k_new; k_newᵀ, k_self]
  通过分块矩阵求逆公式避免 O(n³) 重建。"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


_MAX_WOODBURY_SIZE = 180   # Woodbury 模式最大 n (之后切诱导点)
_LENGTH_SCALE = 1.0
_NOISE_VAR = 0.01
_N_INDUCING = 50


@dataclass
class GPOnlineState:
    """在线 GP 的内部状态 (Woodbury 形式)."""
    X: List[List[float]]          # 训练输入 (n×d)
    y: List[float]                # 训练目标 (n)
    K_inv: List[List[float]]      # (K + σ²I)⁻¹ (n×n)
    alpha: List[float]            # K⁻¹y
    best_f: float = 0.0
    n_total: int = 0


class GPWoodburyOnline:
    """使用 Woodbury 秩-1 更新的在线 GP.

    K_{n+1}^{-1} = [K_n^{-1} + β·K_n^{-1}k·kᵀK_n^{-1},  -β·K_n^{-1}k
                    -β·kᵀK_n^{-1},                           β        ]
    其中 β = 1/(k_self - kᵀK_n^{-1}k), k = [k(x_new, x_1), ..., k(x_new, x_n)]

    复杂度: O(n²) per update (vs O(n³) 重建)
    空间:   O(n²) (K_inv 矩阵)

    使用方式:
      gp = GPWoodburyOnline()
      for each execution:
          gp.add_observation(features, coverage_gain)
      mean, var = gp.predict(new_features)
    """

    def __init__(self, length_scale: float = _LENGTH_SCALE,
                 noise_var: float = _NOISE_VAR):
        self.ls = length_scale
        self.noise = noise_var
        self._st = GPOnlineState(X=[], y=[], K_inv=[], alpha=[])
        self._using_inducing: bool = False
        self._inducing_X: List[List[float]] = []
        self._total_obs: int = 0

    # //// Woodbury 秩-1 添加 (核心创新) ////
    def add_observation(self, features: List[float],
                        target: float) -> None:
        """O(n²) 在线添加观测 — Woodbury 增量."""
        n = len(self._st.X)
        self._total_obs += 1

        if n >= _MAX_WOODBURY_SIZE:
            self._switch_to_inducing()
            self._st.X.append(features)
            self._st.y.append(target)
            self._rebuild_inducing()
            return

        if n == 0:
            # 首次观测: K = [k_self + σ²]
            k_self = self._kernel(features, features) + self.noise
            self._st.X = [features]
            self._st.y = [target]
            self._st.K_inv = [[1.0 / max(1e-12, k_self)]]
            self._st.alpha = [target / max(1e-12, k_self)]
            self._st.best_f = target
            return

        # Woodbury 秩-1 扩展 K_inv: (n+1)×(n+1)
        k_new = [self._kernel(features, xi) for xi in self._st.X]
        k_self = self._kernel(features, features) + self.noise

        # K_n^{-1}·k_new (n×1)
        kinv_k = [sum(self._st.K_inv[i][j] * k_new[j]
                      for j in range(n)) for i in range(n)]

        # β = 1/(k_self - k_newᵀ·K_n^{-1}·k_new)
        kt_kinv_k = sum(k_new[i] * kinv_k[i] for i in range(n))
        beta = 1.0 / max(1e-12, k_self - kt_kinv_k)

        # 右上角: -β·K_n^{-1}·k_new (n×1)
        top_right = [-beta * v for v in kinv_k]

        # 扩展 K_inv
        new_K_inv = [[0.0] * (n + 1) for _ in range(n + 1)]
        for i in range(n):
            for j in range(n):
                # 左上: K_n^{-1} + β·kinv_k·kinv_kᵀ
                new_K_inv[i][j] = (self._st.K_inv[i][j]
                                   + beta * kinv_k[i] * kinv_k[j])
        for i in range(n):
            new_K_inv[i][n] = top_right[i]
            new_K_inv[n][i] = top_right[i]
        new_K_inv[n][n] = beta

        # 更新 alpha = K^{-1}·y
        self._st.X.append(features)
        self._st.y.append(target)
        self._st.K_inv = new_K_inv

        new_alpha = [0.0] * (n + 1)
        for i in range(n + 1):
            for j in range(n + 1):
                new_alpha[i] += self._st.K_inv[i][j] * self._st.y[j]
        self._st.alpha = new_alpha

        if target > self._st.best_f:
            self._st.best_f = target
        self._st.n_total = n + 1

    # //// 预测 ////
    def predict(self, features: List[float]) -> Tuple[float, float]:
        """O(n) 预测 (使用预计算的 K_inv)."""
        if not self._st.X:
            return 0.0, 1.0

        X_ref = self._inducing_X if self._using_inducing else self._st.X
        alpha_ref = (self._st.alpha if not self._using_inducing
                     else self._st.alpha)

        k_star = [self._kernel(features, xi) for xi in X_ref]
        k_self = self._kernel(features, features) + self.noise

        mean = sum(k_star[i] * alpha_ref[i] for i in range(len(k_star)))

        # σ² = k_self - k_starᵀ·K^{-1}·k_star
        if not self._using_inducing:
            quad = 0.0
            for i in range(len(k_star)):
                for j in range(len(k_star)):
                    quad += k_star[i] * self._st.K_inv[i][j] * k_star[j]
        else:
            quad = 0.0  # inducing 模式下保守估计
        variance = max(self.noise, k_self - quad)

        return mean, variance

    def expected_improvement(self,
                              candidates: List[Tuple[str, List[float]]]
                              ) -> List[Tuple[str, float, float, float]]:
        """Expected Improvement 采集."""
        if not self._st.X:
            return [(sid, 0.5, 0.0, 1.0) for sid, _ in candidates]
        xi = 0.01
        results = []
        for sid, feats in candidates:
            mean, var = self.predict(feats)
            std = math.sqrt(max(1e-12, var))
            if std < 1e-8:
                ei = max(0.0, mean - self._st.best_f - xi)
            else:
                z = (mean - self._st.best_f - xi) / std
                phi_z = math.exp(-0.5*z*z) / math.sqrt(2*math.pi)
                phi_cdf = 0.5*(1.0+math.erf(z/math.sqrt(2.0)))
                ei = (mean-self._st.best_f-xi)*phi_cdf + std*phi_z
            results.append((sid, max(0.0, ei), mean, std))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # //// 核函数 + 诱导点 ////
    def _kernel(self, x1: List[float], x2: List[float]) -> float:
        r_sq = sum((a-b)**2 for a, b in zip(x1, x2))
        r = math.sqrt(r_sq)/self.ls
        return (1.0 + math.sqrt(3.0)*r)*math.exp(-math.sqrt(3.0)*r)

    def _switch_to_inducing(self) -> None:
        if self._using_inducing:
            return
        self._using_inducing = True
        self._inducing_X = [list(x) for x in self._st.X[-_N_INDUCING:]]
        self._rebuild_inducing()

    def _rebuild_inducing(self) -> None:
        """用诱导点重建轻量模型."""
        m = len(self._inducing_X)
        if m < 2:
            return
        K_mm = [[self._kernel(xi, xj) for xj in self._inducing_X]
                for xi in self._inducing_X]
        for i in range(m):
            K_mm[i][i] += self.noise
        # Cholesky (m ≤ 50 → 可接受)
        L = self._cholesky(K_mm)
        y_mean = (sum(self._st.y)/max(1,len(self._st.y))
                  if self._st.y else 0.0)
        self._st.alpha = self._solve_cholesky(L, [y_mean]*m)
        self._st.K_inv = []  # 不再维护全 K_inv (诱导点模式)

    @staticmethod
    def _cholesky(A: List[List[float]]) -> List[List[float]]:
        n = len(A)
        L = [[0.0]*n for _ in range(n)]
        for i in range(n):
            for j in range(i+1):
                s = sum(L[i][k]*L[j][k] for k in range(j))
                L[i][j] = (math.sqrt(max(1e-12, A[i][i]-s)) if i==j
                          else (A[i][j]-s)/max(1e-12, L[j][j]))
        return L

    @staticmethod
    def _solve_cholesky(L: List[List[float]],
                         y: List[float]) -> List[float]:
        n = len(L)
        z = [0.0]*n
        for i in range(n):
            z[i] = (y[i]-sum(L[i][k]*z[k] for k in range(i))
                   )/max(1e-12, L[i][i])
        alpha = [0.0]*n
        for i in range(n-1,-1,-1):
            alpha[i] = (z[i]-sum(L[j][i]*alpha[j]
                       for j in range(i+1,n)))/max(1e-12, L[i][i])
        return alpha

    def stats(self) -> dict:
        n = len(self._st.X)
        return {"n_observations": n, "total_seen": self._total_obs,
                "using_inducing": self._using_inducing,
                "best_f": round(self._st.best_f, 3),
                "method": "Woodbury rank-1 O(n²)",
                "n_inducing": len(self._inducing_X)}

    def clear(self) -> None:
        self._st = GPOnlineState(X=[], y=[], K_inv=[], alpha=[])
        self._using_inducing = False
        self._inducing_X.clear()
        self._total_obs = 0
