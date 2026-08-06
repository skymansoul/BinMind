"""EM 覆盖隐类发现 — 高斯混合 + 软分配 + BIC 选 K.

修改记录:
2025-08-18 14:22 - EM GMM + BIC 模型选择 + soft clustering
参考: Dempster, Laird & Rubin (1977) JRSS-B; Fraley & Raftery (2002) JASA.
在 fuzzing 中零先验。EM 自动发现种子覆盖的潜在聚类结构。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


_MAX_K = 5; _MAX_EM_ITER = 50; _TOL = 1e-4


@dataclass
class EMResult:
    n_clusters: int; n_observations: int; log_likelihood: float
    bic: float; responsibilities: List[List[float]]  # n×K
    means: List[List[float]]; cluster_sizes: List[int]


class EMLatentClassDiscovery:
    """EM 覆盖隐类发现 — 高斯混合模型聚类.

    EM 两步: E步: γ_{ik} = P(z_i=k|x_i,Θ) (后验)
             M步: 用加权数据更新 μ_k, Σ_k, π_k
    BIC: -2·logL + K·log(n) → 选最优 K.

    使用: em = EMLatentClassDiscovery(); em.add_seed(coverage_vector)
          r = em.fit(max_k=3); print(r.cluster_sizes)
    """

    def __init__(self):
        self._data: List[List[float]] = []
        self._dim: int = 0

    def add_seed(self, coverage_vector: List[float]) -> None:
        self._data.append(list(coverage_vector))
        self._dim = len(coverage_vector)
        if len(self._data) > 200:
            self._data = self._data[-150:]

    def fit(self, max_k: int = _MAX_K) -> Optional[EMResult]:
        n = len(self._data); d = self._dim
        if n < 10 or d < 2:
            return None

        best_result = None; best_bic = float('inf')
        for K in range(2, min(max_k + 1, n // 3 + 1)):
            result = self._fit_gmm(K)
            if result and result.bic < best_bic:
                best_bic = result.bic; best_result = result
        return best_result

    def _fit_gmm(self, K: int) -> Optional[EMResult]:
        import random
        n, d = len(self._data), self._dim
        rng = random.Random(42)

        # 初始化: k-means++ 选中心
        means = [self._data[rng.randint(0, n - 1)][:]]
        for _ in range(1, K):
            dists = []
            for x in self._data:
                min_d = min(sum((x[j] - m[j]) ** 2 for j in range(d))
                           for m in means)
                dists.append(min_d + 1e-8)
            total = sum(dists)
            r = rng.random() * total; cum = 0.0
            for i, di in enumerate(dists):
                cum += di
                if cum >= r:
                    means.append(self._data[i][:]); break

        # 协方差 = 单位矩阵, 混合权重 = 1/K
        pi_k = [1.0 / K] * K
        sigma_k = [[1.0 if i == j else 0.0 for j in range(d)] for i in range(K)]

        # EM 迭代
        log_lik_prev = -float('inf')
        gamma = [[0.0] * K for _ in range(n)]

        for _ in range(_MAX_EM_ITER):
            # E 步
            log_lik = 0.0
            for i, x in enumerate(self._data):
                row_sum = 0.0
                for k in range(K):
                    det_s = 1.0
                    for j in range(d):
                        det_s *= max(1e-8, sigma_k[k][j])
                    mahal = sum((x[j] - means[k][j]) ** 2 / max(1e-8, sigma_k[k][j])
                               for j in range(d))
                    log_p = (-0.5 * d * math.log(2 * math.pi)
                             - 0.5 * math.log(max(1e-8, det_s))
                             - 0.5 * mahal + math.log(max(1e-8, pi_k[k])))
                    gamma[i][k] = log_p
                    row_sum += math.exp(log_p) if log_p < 50 else float('inf')
                # log-sum-exp for stability
                max_log = max(gamma[i])
                total = sum(math.exp(g - max_log) for g in gamma[i])
                gamma[i] = [math.exp(g - max_log) / max(1e-12, total)
                           for g in gamma[i]]
                log_lik += max_log + math.log(max(1e-12, total))

            if abs(log_lik - log_lik_prev) < _TOL:
                break
            log_lik_prev = log_lik

            # M 步
            N_k = [max(1e-8, sum(gamma[i][k] for i in range(n))) for k in range(K)]
            pi_k = [nk / n for nk in N_k]
            for k in range(K):
                means[k] = [sum(gamma[i][k] * self._data[i][j] for i in range(n)) / N_k[k]
                           for j in range(d)]
                sigma_k[k] = [max(0.01, sum(gamma[i][k] * (self._data[i][j] - means[k][j]) ** 2
                               for i in range(n)) / N_k[k]) for j in range(d)]

        # BIC
        n_params = K * (d + d + 1)  # μ_k (Kd) + σ_k (Kd) + π_k (K)
        bic = -2.0 * log_lik + n_params * math.log(n)
        clusters = [max(range(K), key=lambda k: gamma[i][k]) for i in range(n)]
        sizes = [sum(1 for c in clusters if c == k) for k in range(K)]

        return EMResult(n_clusters=K, n_observations=n,
                       log_likelihood=log_lik, bic=bic,
                       responsibilities=gamma, means=means,
                       cluster_sizes=sizes)

    def stats(self) -> dict:
        r = self.fit()
        if r is None:
            return {"n": len(self._data), "status": "insufficient_data"}
        return {"n_obs": r.n_observations, "K": r.n_clusters,
                "BIC": round(r.bic, 1), "logLik": round(r.log_likelihood, 1),
                "sizes": r.cluster_sizes}

    def clear(self) -> None:
        self._data.clear()
