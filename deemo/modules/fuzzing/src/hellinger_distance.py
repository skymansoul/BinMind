"""Hellinger 距离分布比较 — 离散化 + 核密度 + Bhattacharyya 系数.

修改记录:
2025-08-17 11:05 - 离散经验 Hellinger + Bhattacharyya + 核平滑
参考: Hellinger; Bhattacharyya.
在 fuzzing 中零先例。H² ∈ [0,1], 对称, 满足三角不等式,
比 KL (不对称/无界) 更适合 fuzzing 分布的健壮比较。"""

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass
class HellingerResult:
    hellinger_sq: float    # H² ∈ [0,1]
    hellinger: float       # H = sqrt(H²)
    bhattacharyya: float   # BC = 1 - H² = ∫√(p·q)
    n_samples_a: int
    n_samples_b: int


class HellingerDistanceComparator:
    """Hellinger 距离分布比较器.

    离散化: 将覆盖指纹分配到公共桶 (hash mod B),
    然后计算两个直方图间的 Hellinger 距离。
    H² = 1 - Σ_b √(p_b · q_b)
    Bhattacharyya 系数 BC = Σ √(p_b·q_b) ∈ [0,1]
    核平滑: 用 Jaccard 核在指纹空间上直接估计 H².

    使用方式:
      hdc = HellingerDistanceComparator(n_bins=32)
      hdc.add_sample_A(coverage_set)
      hdc.add_sample_B(coverage_set)
      result = hdc.compare()
      print(f"H={result.hellinger:.4f}")
    """

    def __init__(self, n_bins: int = 32):
        self.n_bins = n_bins
        self._hist_a = Counter()
        self._hist_b = Counter()
        self._n_a: int = 0
        self._n_b: int = 0
        # 核平滑所需的全部样本
        self._samples_a: List[FrozenSet[int]] = []
        self._samples_b: List[FrozenSet[int]] = []

    def add_sample_A(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        b = self._bin_index(fp)
        self._hist_a[b] += 1
        self._n_a += 1
        self._samples_a.append(fp)
        if len(self._samples_a) > 150:
            self._samples_a = self._samples_a[-100:]

    def add_sample_B(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        b = self._bin_index(fp)
        self._hist_b[b] += 1
        self._n_b += 1
        self._samples_b.append(fp)
        if len(self._samples_b) > 150:
            self._samples_b = self._samples_b[-100:]

    def _bin_index(self, fp: FrozenSet[int]) -> int:
        """将覆盖指纹映射到桶索引."""
        if not fp:
            return 0
        return hash(frozenset(fp)) % self.n_bins

    def compare(self) -> Optional[HellingerResult]:
        if self._n_a < 3 or self._n_b < 3:
            return None

        # 方法1: 离散直方图 Hellinger
        bc = 0.0
        all_bins = set(self._hist_a.keys()) | set(self._hist_b.keys())
        for b in all_bins:
            p_b = self._hist_a.get(b, 0) / max(1, self._n_a)
            q_b = self._hist_b.get(b, 0) / max(1, self._n_b)
            bc += math.sqrt(p_b * q_b)
        bc = min(1.0, bc)
        h2 = 1.0 - bc

        # 方法2: 核平滑 (若样本不大)
        if len(self._samples_a) <= 50 and len(self._samples_b) <= 50:
            h2_kernel = self._kernel_hellinger()
            h2 = 0.7 * h2 + 0.3 * h2_kernel  # 加权混合

        return HellingerResult(
            hellinger_sq=h2, hellinger=math.sqrt(max(0.0, h2)),
            bhattacharyya=bc,
            n_samples_a=self._n_a, n_samples_b=self._n_b)

    def _kernel_hellinger(self) -> float:
        """核平滑 Hellinger: 用 Jaccard 核在指纹空间直接估计.

        H²_kernel = 1 - (1/(n·m)) Σ_{i,j} √(k(x_i,y_j)) / (平均归一化)
        """
        n, m = len(self._samples_a), len(self._samples_b)
        if n < 2 or m < 2:
            return 0.0

        # 归一化: √(Σ k(x_i,x_j)) 和 √(Σ k(y_i,y_j))
        norm_a = 0.0
        for i in range(min(n, 30)):
            for j in range(i + 1, min(n, 30)):
                norm_a += self._jaccard_similarity(
                    self._samples_a[i], self._samples_a[j])
        norm_a = math.sqrt(max(1e-8, 2.0 * norm_a / max(1, n * (n - 1))))

        norm_b = 0.0
        for i in range(min(m, 30)):
            for j in range(i + 1, min(m, 30)):
                norm_b += self._jaccard_similarity(
                    self._samples_b[i], self._samples_b[j])
        norm_b = math.sqrt(max(1e-8, 2.0 * norm_b / max(1, m * (m - 1))))

        # 交叉项
        cross = 0.0
        for i in range(min(n, 30)):
            for j in range(min(m, 30)):
                cross += math.sqrt(max(0.0, self._jaccard_similarity(
                    self._samples_a[i], self._samples_b[j])))
        cross_term = cross / max(1, min(n, 30) * min(m, 30))

        bc_kernel = cross_term / max(1e-8, (norm_a * norm_b))
        return max(0.0, min(1.0, 1.0 - bc_kernel))

    @staticmethod
    def _jaccard_similarity(fp_a: FrozenSet[int],
                             fp_b: FrozenSet[int]) -> float:
        if not fp_a and not fp_b: return 1.0
        if not fp_a or not fp_b: return 0.0
        inter = len(fp_a & fp_b)
        union = len(fp_a | fp_b)
        return inter / union if union > 0 else 0.0

    def stats(self) -> dict:
        r = self.compare()
        if r is None:
            return {"n_A": self._n_a, "n_B": self._n_b,
                    "status": "insufficient_data"}
        return {"n_A": r.n_samples_a, "n_B": r.n_samples_b,
                "H": round(r.hellinger, 4),
                "BC": round(r.bhattacharyya, 4)}

    def clear(self) -> None:
        self._hist_a.clear(); self._hist_b.clear()
        self._n_a = 0; self._n_b = 0
        self._samples_a.clear(); self._samples_b.clear()
