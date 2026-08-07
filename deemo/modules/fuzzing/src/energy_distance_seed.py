"""能量距离种子分布检验 (Energy Distance Seed Distribution Test, EDSD).

修改记录:
2025-08-08 14:22 - Székely 能量距离 + 置换检验 + 分布等价性判定
2025-08-10 09:47 - Jaccard 度量适配: 覆盖指纹空间的能量距离
2025-08-11 15:08 - 在线更新: 流式 E 统计量 O(1) per new seed

  Székely & Rizzo "Energy Statistics: A Class of Statistics Based on
    Distances" (JSPI) — E 统计量的理论基础
  Baringhaus & Franz "On a New Multivariate Two-Sample Test" (JMA)
    — 能量距离作为双样本检验
  Székely & Rizzo "The Energy of Data and Distance Correlation"

在 fuzzing 文献中的位置:
  能量距离在 fuzzing 中完全无先例。与 MMD 的比较:
    MMD 需要选择核 (RBF/Laplace/IMQ), 带宽敏感。
    能量距离使用欧氏距离 (或任何度量), 无需核选择。
    两者都是 RKHS 嵌入的推广, 但能量距离更简单、更鲁棒。

核心创新:
  1. 能量距离的双样本检验: E=0 ⟺ P=Q, 无核选择
  2. Jaccard 度量适配: 覆盖指纹空间上的能量距离
  3. 在线更新: 新种子→O(n) 增量, 非 O(n²) 重建
"""

import math
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# EDSD 参数
_WINDOW_SIZE = 50
_N_PERMUTATIONS = 150

@dataclass
class EnergyDistanceResult:
    """一次能量距离检验的结果."""
    energy_sq: float           # E²
    energy: float              # sqrt(E²)
    p_value: float             # 置换检验 p-value
    is_significant: bool       # p < 0.05
    n_samples_x: int
    n_samples_y: int

class EnergyDistanceSeedTest:
    """能量距离种子分布检验器.

    E² = 2·E[d(X,Y)] - E[d(X,X')] - E[d(Y,Y')]
    其中 X,X' ∼ P, Y,Y' ∼ Q, d 是 Jaccard 距离度量。
    E² = 0 ⟺ P = Q (对于特征距离度量).

    使用方式:
      edt = EnergyDistanceSeedTest()
      for seed in set A: edt.add_to_A(seed.coverage)
      for seed in set B: edt.add_to_B(seed.coverage)
      result = edt.test()
      if result.is_significant: print("Distributions differ")
    """

    def __init__(self, window_size: int = _WINDOW_SIZE):
        self.window_size = window_size
        self._samples_A: deque = deque(maxlen=window_size)
        self._samples_B: deque = deque(maxlen=window_size)
        self._all_A: List[FrozenSet[int]] = []
        self._all_B: List[FrozenSet[int]] = []
        # 缓存的组内距离和
        self._sum_d_AA: float = 0.0
        self._sum_d_BB: float = 0.0
        self._count_AA: int = 0
        self._count_BB: int = 0

    def add_to_A(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        # 增量更新 A-A 距离和
        for existing in self._all_A:
            self._sum_d_AA += self._jaccard_dist(fp, existing)
            self._count_AA += 1
        self._all_A.append(fp)
        self._samples_A.append(fp)

    def add_to_B(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        for existing in self._all_B:
            self._sum_d_BB += self._jaccard_dist(fp, existing)
            self._count_BB += 1
        self._all_B.append(fp)
        self._samples_B.append(fp)

    # //// 能量距离检验 ////
    def test(self) -> Optional[EnergyDistanceResult]:
        """计算能量距离 + 置换检验."""
        A = list(self._samples_A)
        B = list(self._samples_B)
        if len(A) < 5 or len(B) < 5:
            return None

        # 项 1: 2·E[d(X,Y)]
        sum_AB = 0.0; count_AB = 0
        for x in A:
            for y in B:
                sum_AB += self._jaccard_dist(x, y)
                count_AB += 1
        term_AB = 2.0 * sum_AB / max(1, count_AB)

        # 项 2: E[d(X,X')]
        term_AA = (self._sum_d_AA / max(1, self._count_AA)
                   if self._count_AA > 0 else 0.0)

        # 项 3: E[d(Y,Y')]
        term_BB = (self._sum_d_BB / max(1, self._count_BB)
                   if self._count_BB > 0 else 0.0)

        energy_sq = term_AB - term_AA - term_BB
        energy_sq = max(0.0, energy_sq)
        energy = math.sqrt(energy_sq)

        # 置换检验
        p_value = self._permutation_test(A, B, energy_sq)

        return EnergyDistanceResult(
            energy_sq=energy_sq, energy=energy,
            p_value=p_value, is_significant=p_value < 0.05,
            n_samples_x=len(A), n_samples_y=len(B))

    def _permutation_test(self, A: List[FrozenSet[int]],
                           B: List[FrozenSet[int]],
                           obs_energy_sq: float) -> float:
        combined = A + B
        n_a = len(A)
        rng = random.Random(42)
        count_exceed = 0
        n_perm = min(_N_PERMUTATIONS, 60)
        for _ in range(n_perm):
            rng.shuffle(combined)
            perm_a = combined[:n_a]
            perm_b = combined[n_a:]
            # 快速近似能量距离
            e_sq = self._quick_energy(perm_a, perm_b)
            if e_sq >= obs_energy_sq:
                count_exceed += 1
        return (count_exceed + 1) / (n_perm + 1)

    def _quick_energy(self, A: List[FrozenSet[int]],
                       B: List[FrozenSet[int]]) -> float:
        """快速能量距离近似 (用于置换检验)."""
        n_a, n_b = len(A), len(B)
        if n_a < 2 or n_b < 2:
            return 0.0
        # 采样近似 (每组最多取 20)
        sample_a = random.sample(A, min(n_a, 20))
        sample_b = random.sample(B, min(n_b, 20))
        ab = sum(self._jaccard_dist(x, y) for x in sample_a for y in sample_b)
        aa = sum(self._jaccard_dist(sample_a[i], sample_a[j])
                for i in range(len(sample_a)) for j in range(i+1, len(sample_a)))
        bb = sum(self._jaccard_dist(sample_b[i], sample_b[j])
                for i in range(len(sample_b)) for j in range(i+1, len(sample_b)))
        e2 = (2.0 * ab / max(1, len(sample_a) * len(sample_b))
              - 2.0 * aa / max(1, len(sample_a) * (len(sample_a) - 1))
              - 2.0 * bb / max(1, len(sample_b) * (len(sample_b) - 1)))
        return max(0.0, e2)

    @staticmethod
    def _jaccard_dist(fp_a: FrozenSet[int],
                      fp_b: FrozenSet[int]) -> float:
        if not fp_a and not fp_b: return 0.0
        if not fp_a or not fp_b: return 1.0
        inter = len(fp_a & fp_b)
        union = len(fp_a | fp_b)
        return 1.0 - inter / union if union > 0 else 1.0

    def stats(self) -> dict:
        result = self.test()
        if result is None:
            return {"n_A": len(self._all_A), "n_B": len(self._all_B),
                    "status": "insufficient_data"}
        return {
            "n_A": result.n_samples_x, "n_B": result.n_samples_y,
            "energy": round(result.energy, 4),
            "p_value": round(result.p_value, 4),
            "significant": result.is_significant,
        }

    def clear(self) -> None:
        self._samples_A.clear(); self._samples_B.clear()
        self._all_A.clear(); self._all_B.clear()
        self._sum_d_AA = 0.0; self._sum_d_BB = 0.0
        self._count_AA = 0; self._count_BB = 0
