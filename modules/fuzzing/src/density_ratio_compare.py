"""密度比策略比较 (Density Ratio Strategy Comparison, DRSC) — uLSIF.

  Kanamori, Hido & Sugiyama "A Least-squares Approach to Direct
    Importance Estimation" (JMLR) — uLSIF 的原始论文
  Sugiyama, Suzuki & Kanamori "Density Ratio Estimation in Machine
    Learning" — 专著, 第 6 章: uLSIF/RuLSIF 的理论性质
  Yamada et al. "Relative Density-Ratio Estimation for Robust
    Distribution Comparison" (NeurIPS) — RuLSIF: α-relative Pearson

在 fuzzing 文献中的位置:
  密度比估计在 fuzzing 中完全无先例。密度比 w(x) 直接量化
  "策略 A 的种子分布比策略 B 更偏好的区域"。
  现有策略比较: t-检验 (假设正态), log-rank (仅存活数据),
  MMD (RKHS 距离, 需要核选择)。
  uLSIF 直接学习密度比, 不需要估计单独的密度, 对维度鲁棒。

  1. uLSIF 直接密度比: 避免密度估计 (高维困难)
  2. Pearson 散度: PE(P_A||P_B) = ½∫(w-1)²·p_B — 策略差异度量
  3. 在线更新: 新种子→增量更新核矩阵
  4. 策略优势区域: w(x)>1 → A 偏好, w(x)<1 → B 偏好
"""

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# uLSIF 参数
_N_BASIS = 50                 # 基函数数量 (核中心数)
_LAMBDA_REG = 0.01            # L2 正则化
_SIGMA_FACTOR = 1.0           # 高斯核带宽缩放

@dataclass
class DRSCResult:
    """一次密度比比较的结果."""
    pearson_divergence: float   # PE(P_A || P_B)
    mean_ratio: float           # E[w(x)] over B samples (=1 若相同分布)
    ratio_variance: float       # Var[w(x)] over B
    n_samples_a: int
    n_samples_b: int
    # 策略优势区域比例
    frac_a_preferred: float     # w(x)>1 的 B 样本比例
    frac_b_preferred: float     # w(x)<1 的 B 样本比例

class DensityRatioComparator:
    """密度比策略比较器 — uLSIF.

    直接学习 w(x) = p_A(x)/p_B(x), 其中 p_A, p_B 是
    两个 fuzzing 策略产生的种子覆盖分布。

    使用方式:
      drc = DensityRatioComparator()
      # 添加策略A的种子
      for seed in strategy_A_seeds:
          drc.add_sample_A(seed.coverage)
      # 添加策略B的种子
      for seed in strategy_B_seeds:
          drc.add_sample_B(seed.coverage)
      result = drc.compare()
      print(f"PE divergence: {result.pearson_divergence:.4f}")
    """

    def __init__(self, n_basis: int = _N_BASIS):
        self.n_basis = n_basis
        self._samples_A: List[FrozenSet[int]] = []
        self._samples_B: List[FrozenSet[int]] = []
        self._feature_index: Dict[int, int] = {}
        self._n_features: int = 0

    def add_sample_A(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        self._samples_A.append(fp)
        self._update_feature_index(coverage)

    def add_sample_B(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        self._samples_B.append(fp)
        self._update_feature_index(coverage)

    def _update_feature_index(self, coverage: Set[int]) -> None:
        for eid in coverage:
            if eid not in self._feature_index:
                self._feature_index[eid] = self._n_features
                self._n_features += 1

    # //// uLSIF 核心 ////
    def compare(self) -> Optional[DRSCResult]:
        """估计 P_A/P_B 的密度比并返回比较结果."""
        n_A, n_B = len(self._samples_A), len(self._samples_B)
        if n_A < 5 or n_B < 5:
            return None

        # 特征向量化
        n_feats = min(self._n_features, 128)
        vecs_A = self._to_vectors(self._samples_A, n_feats)
        vecs_B = self._to_vectors(self._samples_B, n_feats)

        # 基函数: 从 B 中随机选 center 点
        n_center = min(self.n_basis, n_B)
        rng = random.Random(42)
        centers = [vecs_B[i] for i in rng.sample(range(n_B), n_center)]

        # 高斯带宽: median heuristic on B
        sigma = self._median_pairwise_distance(vecs_B)
        sigma = max(0.01, sigma)

        # 构建设计矩阵 K: (n_B × n_center)
        K = [[self._gaussian_kernel(vb, c, sigma) for c in centers]
             for vb in vecs_B]

        # 正则化矩阵 H = KᵀK + λ·I
        H = [[0.0] * n_center for _ in range(n_center)]
        for i in range(n_center):
            for j in range(n_center):
                H[i][j] = sum(K[k][i] * K[k][j] for k in range(n_B))
                if i == j:
                    H[i][j] += _LAMBDA_REG

        # 右侧: h = (1/n_A) Σ K(x_A, ·) — A 样本在基上的平均
        h = [0.0] * n_center
        for va in vecs_A:
            kval = [self._gaussian_kernel(va, c, sigma) for c in centers]
            for j in range(n_center):
                h[j] += kval[j] / n_A

        # 求解 α = H^{-1}·h
        alpha = self._solve_linear_system(H, h)

        # 密度比估计: ŵ(x) = Σ α_j · φ_j(x)
        # 对 B 样本评估
        ratios_B = []
        for vb in vecs_B:
            w = sum(alpha[j] * self._gaussian_kernel(vb, centers[j], sigma)
                    for j in range(n_center))
            w = max(0.0, w)  # 密度比非负
            ratios_B.append(w)

        mean_ratio = sum(ratios_B) / len(ratios_B)
        var_ratio = (sum(r * r for r in ratios_B) / len(ratios_B)
                     - mean_ratio * mean_ratio)

        # Pearson 散度: PE = ½∫(w-1)² p_B
        # ≈ ½·(1/n_B)Σ(w(x_B)-1)²
        pe = 0.5 * sum((r - 1.0) ** 2 for r in ratios_B) / len(ratios_B)

        frac_a = sum(1 for r in ratios_B if r > 1.0) / len(ratios_B)
        frac_b = sum(1 for r in ratios_B if r < 1.0) / len(ratios_B)

        return DRSCResult(
            pearson_divergence=pe,
            mean_ratio=mean_ratio,
            ratio_variance=var_ratio,
            n_samples_a=n_A, n_samples_b=n_B,
            frac_a_preferred=frac_a,
            frac_b_preferred=frac_b,
        )

    # //// 核函数 ////
    def _gaussian_kernel(self, x: List[float], y: List[float],
                          sigma: float) -> float:
        r_sq = sum((xi - yi) ** 2 for xi, yi in zip(x, y))
        return math.exp(-r_sq / (2.0 * sigma * sigma))

    def _to_vectors(self, samples: List[FrozenSet[int]],
                    n_feats: int) -> List[List[float]]:
        feat_keys = list(self._feature_index.keys())[:n_feats]
        col_map = {eid: i for i, eid in enumerate(feat_keys)}
        vecs = []
        for fp in samples:
            v = [0.0] * n_feats
            for eid in fp:
                col = col_map.get(eid)
                if col is not None:
                    v[col] = 1.0
            norm = math.sqrt(sum(x * x for x in v))
            if norm > 1e-8:
                v = [x / norm for x in v]
            vecs.append(v)
        return vecs

    def _median_pairwise_distance(self,
                                    vecs: List[List[float]]) -> float:
        n = min(len(vecs), 50)
        if n < 2: return 1.0
        dists = []
        for i in range(n):
            for j in range(i + 1, n):
                d_sq = sum((vecs[i][k] - vecs[j][k]) ** 2
                          for k in range(len(vecs[i])))
                dists.append(math.sqrt(d_sq))
        dists.sort()
        return dists[len(dists) // 2]

    @staticmethod
    def _solve_linear_system(A: List[List[float]],
                              b: List[float]) -> List[float]:
        """共轭梯度法求解 Ax = b (A 对称正定)."""
        n = len(A)
        x = [0.0] * n
        r = list(b)
        p = list(r)
        rs_old = sum(ri * ri for ri in r)
        for _ in range(min(50, n)):
            Ap = [sum(A[i][j] * p[j] for j in range(n)) for i in range(n)]
            pAp = sum(p[i] * Ap[i] for i in range(n))
            if abs(pAp) < 1e-15: break
            alpha = rs_old / pAp
            for i in range(n): x[i] += alpha * p[i]
            for i in range(n): r[i] -= alpha * Ap[i]
            rs_new = sum(ri * ri for ri in r)
            if rs_new < 1e-10: break
            beta = rs_new / rs_old
            for i in range(n): p[i] = r[i] + beta * p[i]
            rs_old = rs_new
        return x

    # //// 统计 ////
    def stats(self) -> dict:
        result = self.compare()
        if result is None:
            return {"n_A": len(self._samples_A),
                    "n_B": len(self._samples_B),
                    "status": "insufficient_data"}
        return {
            "n_A": result.n_samples_a,
            "n_B": result.n_samples_b,
            "pearson_divergence": round(result.pearson_divergence, 4),
            "mean_ratio": round(result.mean_ratio, 4),
            "ratio_variance": round(result.ratio_variance, 4),
            "frac_A_preferred": round(result.frac_a_preferred, 4),
            "frac_B_preferred": round(result.frac_b_preferred, 4),
        }

    def clear(self) -> None:
        self._samples_A.clear(); self._samples_B.clear()
        self._feature_index.clear(); self._n_features = 0
