"""最大均值差异种子分布检验 — RBF核 MMD + 置换检验 + 分布偏移检测. 参考: Gretton et al. (2012). MMD 在 fuzzing 中无先例。RKHS 中的分布距离度量, 在线滑动窗口比较, 检测探索突破 vs 平台期."""

import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# MMD 参数
_WINDOW_SIZE = 50             # 滑动窗口大小
_N_PERMUTATIONS = 200         # 置换检验重采样次数
_MMD_ALPHA = 0.01             # 显著性水平
_BANDWIDTH_FACTOR = 1.0       # Median heuristic 的缩放因子


@dataclass
class MMDResult:
    """一次 MMD 检验的结果."""
    mmd_squared: float         # 无偏 MMD² 估计
    mmd: float                 # sqrt(max(0, MMD²))
    p_value: float             # 置换检验 p-value
    is_significant: bool       # p < α
    bandwidth_used: float      # 使用的 RBF 带宽
    n_samples_x: int
    n_samples_y: int
    # 效应量
    cohens_d: float            # MMD / pooled_std (近似效应量)


class MMDSeedDistributionTest:
    """MMD 种子分布检验器.

    使用 RBF 核 (高斯核) 将种子覆盖指纹映射到 RKHS,
    比较两个种子集合的 MMD² = ||μ_X - μ_Y||²_H。

    在线模式: 维护滑动窗口, 周期性比较当前窗口与前一窗口的分布。
    MMD 上升 → 分布偏移 → 探索有进展。
    MMD 下降 → 分布稳定 → 可能平台期。

    使用方式:
      mmd_test = MMDSeedDistributionTest()
      for each new seed:
          mmd_test.add_to_window(seed.coverage)
          result = mmd_test.compare_windows()
          if result.is_significant:
              print(f"Distribution shift detected: MMD={result.mmd:.4f}")
    """

    def __init__(self, window_size: int = _WINDOW_SIZE,
                 alpha: float = _MMD_ALPHA):
        self.window_size = window_size
        self.alpha = alpha
        self._current_window: deque = deque(maxlen=window_size)
        self._previous_window: List[FrozenSet[int]] = []
        self._bandwidth: float = 1.0
        self._mmd_history: List[MMDResult] = []
        self._total_seeds: int = 0
        self._last_compare_time: float = 0.0

    # //// 窗口管理 ////
    def add_to_window(self, coverage: Set[int]) -> None:
        """添加新种子到当前滑动窗口."""
        fp = frozenset(coverage)
        self._current_window.append(fp)
        self._total_seeds += 1

        # 当前窗口满时, 滚动
        if len(self._current_window) >= self.window_size:
            if (time.time() - self._last_compare_time > 5.0
                    and len(self._previous_window) >= 10):
                self.compare_windows()
            self._previous_window = list(self._current_window)

    def compare_windows(self) -> Optional[MMDResult]:
        """比较上一窗口和当前窗口的种子分布."""
        prev = self._previous_window
        curr = list(self._current_window)
        if len(prev) < 10 or len(curr) < 10:
            return None
        result = self._mmd_two_sample(prev, curr)
        self._mmd_history.append(result)
        if len(self._mmd_history) > 50:
            self._mmd_history = self._mmd_history[-30:]
        self._last_compare_time = time.time()
        return result

    # //// MMD 计算 ////
    def _mmd_two_sample(self, X: List[FrozenSet[int]],
                         Y: List[FrozenSet[int]]) -> MMDResult:
        """计算两组种子覆盖分布的 MMD².

        MMD² = 1/(n(n-1)) Σ_{i≠j} k(x_i, x_j)
             + 1/(m(m-1)) Σ_{i≠j} k(y_i, y_j)
             - 2/(nm) Σᵢⱼ k(x_i, y_j)
        """
        n, m = len(X), len(Y)
        # 自适应带宽: median heuristic on combined sample
        combined = X + Y
        self._bandwidth = self._median_heuristic(combined)

        # 项 1: k(x, x') 平均值 (off-diagonal)
        kxx = 0.0
        for i in range(n):
            for j in range(i + 1, n):
                kxx += self._rbf_kernel(X[i], X[j])
        kxx_term = 2.0 * kxx / max(1, n * (n - 1))

        # 项 2: k(y, y')
        kyy = 0.0
        for i in range(m):
            for j in range(i + 1, m):
                kyy += self._rbf_kernel(Y[i], Y[j])
        kyy_term = 2.0 * kyy / max(1, m * (m - 1))

        # 项 3: k(x, y)
        kxy = 0.0
        for i in range(n):
            for j in range(m):
                kxy += self._rbf_kernel(X[i], Y[j])
        kxy_term = 2.0 * kxy / max(1, n * m)

        mmd_sq = kxx_term + kyy_term - kxy_term
        mmd = math.sqrt(max(0.0, mmd_sq))

        # 置换检验 p-value
        p_value = self._permutation_test(X, Y, mmd_sq)

        # 效应量: Cohen's d ≈ MMD / pooled_std
        pooled_std = math.sqrt(0.5 * (
            self._kernel_variance(X) + self._kernel_variance(Y)))
        cohens_d = mmd / max(1e-8, pooled_std)

        result = MMDResult(
            mmd_squared=mmd_sq,
            mmd=mmd,
            p_value=p_value,
            is_significant=p_value < self.alpha,
            bandwidth_used=self._bandwidth,
            n_samples_x=n,
            n_samples_y=m,
            cohens_d=cohens_d,
        )
        return result

    # //// 核函数 ////
    def _rbf_kernel(self, fp_a: FrozenSet[int],
                    fp_b: FrozenSet[int]) -> float:
        """RBF 核: k(x,y) = exp(-JaccardDistance/σ²).

        Jaccard 距离作为覆盖指纹空间的自然度量。
        """
        if not fp_a and not fp_b:
            return 1.0
        if not fp_a or not fp_b:
            return 0.0
        inter = len(fp_a & fp_b)
        union = len(fp_a | fp_b)
        jac_dist = 1.0 - inter / union if union > 0 else 1.0
        return math.exp(-jac_dist / max(1e-8, self._bandwidth))

    def _median_heuristic(self,
                           samples: List[FrozenSet[int]]) -> float:
        """Median heuristic: σ = median pairwise distance.

        对 RBF 核的带宽选择具有理论支持, 在实践中表现良好。
        """
        n = min(len(samples), 60)
        if n < 2:
            return 1.0
        distances = []
        for i in range(n):
            for j in range(i + 1, n):
                fp_a, fp_b = samples[i], samples[j]
                if not fp_a and not fp_b:
                    d = 0.0
                elif not fp_a or not fp_b:
                    d = 1.0
                else:
                    inter = len(fp_a & fp_b)
                    union = len(fp_a | fp_b)
                    d = 1.0 - inter / union if union > 0 else 1.0
                distances.append(d)
        distances.sort()
        median = distances[len(distances) // 2]
        return max(0.01, median * _BANDWIDTH_FACTOR)

    # //// 置换检验 ////
    def _permutation_test(self, X: List[FrozenSet[int]],
                           Y: List[FrozenSet[int]],
                           observed_mmd_sq: float) -> float:
        """置换检验: 估计在原假设 (两个分布相同) 下 MMD² ≥ observed 的概率."""
        combined = X + Y
        n_x = len(X)
        rng = random.Random(42)
        count_exceed = 0
        n_perm = min(_N_PERMUTATIONS, max(20, len(combined) // 2))

        for _ in range(n_perm):
            rng.shuffle(combined)
            perm_x = combined[:n_x]
            perm_y = combined[n_x:]
            perm_mmd2 = self._mmd_squared_quick(perm_x, perm_y)
            if perm_mmd2 >= observed_mmd_sq:
                count_exceed += 1

        return (count_exceed + 1) / (n_perm + 1)

    def _mmd_squared_quick(self, X: List[FrozenSet[int]],
                            Y: List[FrozenSet[int]]) -> float:
        """快速 MMD² 估计 (仅用于置换检验, 不做完整计算)."""
        n, m = len(X), len(Y)
        if n < 2 or m < 2:
            return 0.0
        # 仅计算少量项来近似
        sample_size = min(n, m, 15)
        rng = random.Random(99)
        xi = rng.sample(range(n), sample_size)
        yi = rng.sample(range(m), sample_size)

        kxx = sum(self._rbf_kernel(X[i], X[j])
                  for i in xi for j in xi if i != j) / max(1, sample_size * (sample_size - 1))
        kyy = sum(self._rbf_kernel(Y[i], Y[j])
                  for i in yi for j in yi if i != j) / max(1, sample_size * (sample_size - 1))
        kxy = sum(self._rbf_kernel(X[i], Y[j])
                  for i in xi for j in yi) / max(1, sample_size * sample_size)
        return max(0.0, kxx + kyy - 2.0 * kxy)

    # //// 核方差 ////
    def _kernel_variance(self,
                          samples: List[FrozenSet[int]]) -> float:
        """核矩阵 (对角) 方差近似."""
        if len(samples) < 2:
            return 0.0
        vals = [self._rbf_kernel(samples[i], samples[i])
                for i in range(min(len(samples), 30))]
        mean = sum(vals) / len(vals)
        return sum((v - mean) ** 2 for v in vals) / max(1, len(vals) - 1)

    # //// 分布偏移检测 ////
    def shift_detected(self) -> bool:
        """最近一次比较是否检测到显著分布偏移."""
        if not self._mmd_history:
            return False
        return self._mmd_history[-1].is_significant

    def plateau_likelihood(self) -> float:
        """平台期似然: 最近 3 次 MMD 都低 → 高平台概率."""
        if len(self._mmd_history) < 3:
            return 0.0
        recent = self._mmd_history[-3:]
        low_count = sum(1 for r in recent if not r.is_significant)
        return low_count / 3.0

    # //// 统计 ////
    def stats(self) -> dict:
        last = self._mmd_history[-1] if self._mmd_history else None
        return {
            "total_seeds_processed": self._total_seeds,
            "current_window_size": len(self._current_window),
            "previous_window_size": len(self._previous_window),
            "last_mmd": round(last.mmd, 4) if last else None,
            "last_p_value": round(last.p_value, 4) if last else None,
            "shift_detected": last.is_significant if last else False,
            "bandwidth": round(self._bandwidth, 4),
            "plateau_likelihood": round(self.plateau_likelihood(), 3),
            "mmd_history_size": len(self._mmd_history),
        }

    def clear(self) -> None:
        self._current_window.clear(); self._previous_window.clear()
        self._bandwidth = 1.0; self._mmd_history.clear()
        self._total_seeds = 0
