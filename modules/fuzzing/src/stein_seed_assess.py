"""Stein 差异种子评估 (KSD Seed Assessment) — IMQ 核 + Nyström + 均匀目标近似.

  Liu, Lee & Jordan "A Kernelized Stein Discrepancy for Goodness-of-fit
    Tests" (ICML) — KSD 的原始提出: 使用 Stein 恒等式构造核化差异度量
  Chwialkowski, Strathmann & Gretton "A Kernel Test of Goodness of Fit"
    (ICML) — 独立提出的 KSD 框架
  Gorham & Mackey "Measuring Sample Quality with Kernels" (ICML)
    — 证明 IMQ 核的 KSD 能检测非收敛

在 fuzzing 文献中的位置:
  KSD 在 fuzzing 中完全无先例。与 MMD-SDT 的区分:
    MMD 需要来自目标分布的样本 → 在 fuzzing 中目标分布未知。
    KSD 仅需 score function ∇log p(x) — 对目标分布的对数梯度,
    不依赖归一化常数。对于 fuzzing: 目标分布 = 覆盖空间上的均匀分布,
    score = 0 (均匀分布的对数梯度为零), KSD 退化为核梯度的期望。
    这给出了一种"种子是否覆盖了整个空间"的分布度量。

  1. IMQ 核 Stein 算子: k₀(x,y) = ∇_x·∇_y k(x,y) + ∇_x k(x,y)·∇_y log p(y)
     + ∇_y k(x,y)·∇_x log p(x) + k(x,y)·∇_x log p(x)·∇_y log p(y)
  2. 均匀目标简化: p(x) ∝ 1 → ∇log p = 0 → 仅需核的 Hessian 迹
  3. Nyström 加速: O(m²n) 近似 KSD², m≪n
  4. 覆盖收敛检测: KSD² → 0 ⟺ 种子分布覆盖了特征空间
"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# KSD 参数
_N_NYSTROM = 30              # Nyström 诱导点数量
_MIN_SEEDS_FOR_KSD = 15      # 启动 KSD 的最小种子数

@dataclass
class KSDResult:
    """一次 KSD 评估的结果."""
    ksd_squared: float         # KSD² 估计
    ksd: float                 # sqrt(KSD²)
    n_seeds_evaluated: int
    n_nystrom_points: int
    bandwidth: float
    is_converged: bool         # KSD < threshold → 覆盖分布已均匀
    trend: str                 # "decreasing"|"stable"|"increasing"

class SteinSeedAssessor:
    """KSD 种子分布评估器.

    使用 IMQ (Inverse Multi-Quadric) 核:
      k(x,y) = (c² + ||x-y||²)^(-β)
    IMQ 核的 Stein 算子对均匀目标的 score=0 情况:
      k₀(x,y) = trace(Hessian_xy k(x,y))
    其中 Hessian_xy 是核函数对 x 和 y 的混合二阶导数。

    使用方式:
      ssa = SteinSeedAssessor()
      for seed in corpus:
          ssa.add_seed(seed.id, seed.coverage)
      result = ssa.evaluate()
      if result.is_converged:
          print("Seed distribution covers the feature space uniformly")
    """

    def __init__(self, beta: float = 0.5, c: float = 1.0):
        self.beta = beta        # IMQ 幂参数
        self.c = c              # IMQ 偏移
        self._seeds: Dict[str, FrozenSet[int]] = {}
        self._feature_index: Dict[int, int] = {}
        self._n_features: int = 0
        self._ksd_history: List[KSDResult] = []
        self._last_result: Optional[KSDResult] = None

    # //// 种子注册 ////
    def add_seed(self, seed_id: str, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        if seed_id in self._seeds and self._seeds[seed_id] == fp:
            return
        self._seeds[seed_id] = fp
        for eid in coverage:
            if eid not in self._feature_index:
                self._feature_index[eid] = self._n_features
                self._n_features += 1
        # 容量控制
        if len(self._seeds) > 300:
            self._prune_seeds()

    # //// KSD 评估 ////
    def evaluate(self) -> Optional[KSDResult]:
        """计算当前种子池的 KSD².

        均匀目标的简化: ∇log p(x) = 0, 因此:
          k₀(x,y) = trace(∇_x ∇_y k(x,y))
        对于 IMQ: k₀ = 2β(2β+2)·||x-y||²/(c²+||x-y||²)^(β+2)
                       - 2β·d/(c²+||x-y||²)^(β+1)
        其中 d 是特征维数。
        """
        n = len(self._seeds)
        if n < _MIN_SEEDS_FOR_KSD:
            return None

        seed_ids = list(self._seeds.keys())
        # 特征向量化
        n_feats = min(self._n_features, 256)
        vectors = self._to_vectors(seed_ids, n_feats)

        # Nyström 近似: 选 m 个诱导点
        m = min(_N_NYSTROM, n)
        rng = random.Random(42)
        inducing_idx = rng.sample(range(n), m)

        # KSD² ≈ (1/n²) Σ_{i,j} k₀(x_i, x_j)
        # 使用 Nyström: k₀ ≈ K_{n,m} · K_{m,m}^{-1} · K_{m,n}
        ksd_sq = self._compute_ksd_nystrom(vectors, inducing_idx, n_feats)

        ksd = math.sqrt(max(0.0, ksd_sq))

        # 收敛判定: KSD < 0.01 → 基本均匀
        converged = ksd < 0.01

        # 趋势
        trend = "stable"
        if len(self._ksd_history) >= 2:
            prev = self._ksd_history[-1].ksd
            prev2 = self._ksd_history[-2].ksd
            if ksd < prev < prev2:
                trend = "decreasing"
            elif ksd > prev > prev2:
                trend = "increasing"

        result = KSDResult(
            ksd_squared=ksd_sq, ksd=ksd,
            n_seeds_evaluated=n, n_nystrom_points=m,
            bandwidth=self.c,
            is_converged=converged, trend=trend,
        )
        self._ksd_history.append(result)
        if len(self._ksd_history) > 30:
            self._ksd_history = self._ksd_history[-20:]
        self._last_result = result
        return result

    def _to_vectors(self, seed_ids: List[str],
                    n_feats: int) -> List[List[float]]:
        """将种子覆盖集转为归一化特征向量."""
        feat_keys = list(self._feature_index.keys())[:n_feats]
        col_map = {eid: i for i, eid in enumerate(feat_keys)}
        vectors = []
        for sid in seed_ids:
            fp = self._seeds[sid]
            vec = [0.0] * n_feats
            for eid in fp:
                col = col_map.get(eid)
                if col is not None:
                    vec[col] = 1.0
            # L2 归一化
            norm = math.sqrt(sum(v * v for v in vec))
            if norm > 1e-8:
                vec = [v / norm for v in vec]
            vectors.append(vec)
        return vectors

    def _compute_ksd_nystrom(self, vectors: List[List[float]],
                              inducing_idx: List[int],
                              n_feats: int) -> float:
        """Nyström KSD² 计算."""
        n = len(vectors)
        m = len(inducing_idx)

        # 构建 K_{n,m}: 所有点与诱导点的 Stein 核
        K_nm = [[0.0] * m for _ in range(n)]
        for i in range(n):
            for j_idx, j in enumerate(inducing_idx):
                K_nm[i][j_idx] = self._stein_kernel(
                    vectors[i], vectors[j], n_feats)

        # 构建 K_{m,m}: 诱导点之间的 Stein 核
        K_mm = [[0.0] * m for _ in range(m)]
        for a in range(m):
            for b in range(m):
                K_mm[a][b] = self._stein_kernel(
                    vectors[inducing_idx[a]],
                    vectors[inducing_idx[b]], n_feats)

        # KSD² ≈ trace(K_{n,m} · K_{m,m}^{-1} · K_{m,n}) / n²
        # 简化: mean of K_nm @ pinv(K_mm) @ K_nm^T
        K_mm_inv = self._pinv_2x2_approx(K_mm)

        # K_{n,m} · K_{m,m}^{-1}: n×m
        # then trace with K_{m,n} = sum_{i,j} (K_nm @ K_mm_inv)[i,j] * K_nm[i,j]
        trace_est = 0.0
        for i in range(n):
            for j_idx in range(m):
                # (K_nm @ K_mm_inv)[i, j_idx]
                row_dot = sum(K_nm[i][k] * K_mm_inv[k][j_idx] for k in range(m))
                trace_est += row_dot * K_nm[i][j_idx]

        return trace_est / max(1, n * n)

    def _stein_kernel(self, x: List[float], y: List[float],
                       d: int) -> float:
        """IMQ 核的 Stein 核 (均匀目标, score=0).

        k₀(x,y) = 2β(2β+2)·r²/(c²+r²)^(β+2) - 2β·d/(c²+r²)^(β+1)
        其中 r² = ||x-y||², d = 特征维数.
        """
        r_sq = sum((xi - yi) ** 2 for xi, yi in zip(x, y))
        c_sq = self.c * self.c
        denom1 = (c_sq + r_sq) ** (self.beta + 1)
        denom2 = (c_sq + r_sq) ** (self.beta + 2)
        b = self.beta
        term1 = 2.0 * b * (2.0 * b + 2.0) * r_sq / max(1e-15, denom2)
        term2 = 2.0 * b * d / max(1e-15, denom1)
        return term1 - term2

    @staticmethod
    def _pinv_2x2_approx(A: List[List[float]]) -> List[List[float]]:
        """Moore-Penrose 伪逆 (对称矩阵, 使用谱截断)."""
        m = len(A)
        if m == 0:
            return []
        # 特征值截断: 仅保留 > 1e-6 的分量
        # 简化: 使用 Tikhonov 正则化 (A + λI)^{-1}
        lam = 1e-4
        A_reg = [[A[i][j] + (lam if i == j else 0.0) for j in range(m)]
                 for i in range(m)]
        # Cholesky 求逆 (小矩阵, m ≤ 30)
        L = [[0.0] * m for _ in range(m)]
        for i in range(m):
            for j in range(i + 1):
                s = sum(L[i][k] * L[j][k] for k in range(j))
                if i == j:
                    L[i][j] = math.sqrt(max(1e-12, A_reg[i][i] - s))
                else:
                    L[i][j] = (A_reg[i][j] - s) / max(1e-12, L[j][j])
        # 前向+后向代入求逆
        inv = [[0.0] * m for _ in range(m)]
        for col in range(m):
            # 前向: L·z = e_col
            z = [0.0] * m
            for i in range(m):
                s = sum(L[i][k] * z[k] for k in range(i))
                z[i] = ((1.0 if i == col else 0.0) - s) / max(1e-12, L[i][i])
            # 后向: Lᵀ·inv_col = z
            for i in range(m - 1, -1, -1):
                s = sum(L[k][i] * inv[k][col] for k in range(i + 1, m))
                inv[i][col] = (z[i] - s) / max(1e-12, L[i][i])
        return inv

    # //// 查询 ////
    def is_converged(self) -> bool:
        if self._last_result is None:
            return False
        return self._last_result.is_converged

    def convergence_trend(self) -> str:
        if self._last_result is None:
            return "unknown"
        return self._last_result.trend

    # //// 辅助 ////
    def _prune_seeds(self) -> None:
        """保留覆盖集最大的种子."""
        items = sorted(self._seeds.items(),
                      key=lambda x: len(x[1]), reverse=True)
        self._seeds = {sid: fp for sid, fp in items[:200]}

    # //// 统计 ////
    def stats(self) -> dict:
        result = self._last_result
        self.evaluate()
        result = self._last_result
        if result is None:
            return {"status": "insufficient_data",
                    "n_seeds": len(self._seeds)}
        return {
            "n_seeds": result.n_seeds_evaluated,
            "ksd_squared": round(result.ksd_squared, 6),
            "ksd": round(result.ksd, 6),
            "is_converged": result.is_converged,
            "trend": result.trend,
            "n_nystrom_points": result.n_nystrom_points,
            "bandwidth": self.c,
            "imq_beta": self.beta,
        }

    def clear(self) -> None:
        self._seeds.clear(); self._feature_index.clear()
        self._n_features = 0
        self._ksd_history.clear(); self._last_result = None
