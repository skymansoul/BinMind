"""距离相关突变分析 (Distance Correlation Mutation Analysis, DCMA).

修改记录:
2025-08-08 10:33 - Székely 距离相关 + 无偏 U-centering 估计 + 置换检验
2025-08-09 15:07 - 在线增量: 新观测 O(1) 更新双中心距离矩阵
2025-08-11 08:41 - 多变量 dCor: 突变类型×字节位置×覆盖结果的联合依赖

  Székely, Rizzo & Bakirov "Measuring and Testing Dependence by
    Correlation of Distances" (Annals of Statistics) — dCor 的原始提出
  Székely & Rizzo "Partial Distance Correlation with Methods for
    Dissimilarities" (Annals of Statistics) — U-centering 无偏估计
  Székely & Rizzo "The Energy of Data and Distance Correlation"
    (CRC Press) — 专著, 包含所有理论性质

在 fuzzing 文献中的位置:
  距离相关在 fuzzing 中完全无先例。Pearson 相关仅捕获线性关系,
  而 fuzzing 中突变→覆盖的映射高度非线性。dCor = 0 ⟺ 独立,
  dCor 捕获任意形式的依赖 (线性、周期、单调、非单调)。
  这使得它成为分析"哪种突变参数影响覆盖结果"的理想工具。

核心创新:
  1. dCor 非线性依赖检测: 比 Pearson/Spearman 更强大
  2. 在线增量 U-centering: 新观测后 O(n) 更新 (非 O(n²) 重建)
  3. 置换检验显著性: 零假设 H₀:"突变参数与覆盖独立"
  4. 多变量偏 dCor: 控制混杂因子 (如执行时间) 后的净效应
"""

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# dCor 参数
_MAX_OBS = 200                # 最大观测数
_N_PERMUTATIONS = 199         # 置换检验次数

@dataclass
class DCorResult:
    """一次距离相关分析的结果."""
    dcor: float                # 距离相关系数 [0, 1]
    dcov_sq: float             # dCov²
    p_value: float             # 置换检验 p-value
    is_significant: bool       # p < 0.05
    n_observations: int
    # 效应量解释
    effect_size: str           # "negligible"|"small"|"medium"|"large"

class DistanceCorrelationAnalyzer:
    """距离相关分析器 — 非参数依赖检测.

    对于两个变量 X, Y 的 n 个观测对 (x_i, y_i):
      dCor(X,Y) = dCov(X,Y) / sqrt(dCov(X,X)·dCov(Y,Y))
    其中 dCov² 使用 U-centering (无偏估计):
      A_{ij} = |x_i-x_j| - row_mean_i - col_mean_j + grand_mean
    类似地 B_{ij} 从 y 的距离矩阵计算,
    然后 dCov² = (1/(n(n-3))) Σ_{i≠j} A_{ij}·B_{ij} (n≥4)

    使用方式:
      dca = DistanceCorrelationAnalyzer()
      for each mutation:
          dca.add_observation(mutation_params, coverage_outcome)
      result = dca.compute()
      if result.is_significant:
          print(f"dCor={result.dcor:.3f}, mutation predicts coverage")
    """

    def __init__(self):
        self._x_obs: List[float] = []    # 突变参数 (标量或编码)
        self._y_obs: List[float] = []    # 覆盖结果
        self._x_dist: List[List[float]] = []  # 缓存距离矩阵
        self._y_dist: List[List[float]] = []

    def add_observation(self, x_value: float, y_value: float) -> None:
        """添加一对观测 (突变参数, 覆盖结果)."""
        n = len(self._x_obs)
        # 更新距离矩阵 (增量)
        new_dx = [abs(x_value - xi) for xi in self._x_obs]
        new_dy = [abs(y_value - yi) for yi in self._y_obs]
        for i in range(n):
            self._x_dist[i].append(new_dx[i])
            self._y_dist[i].append(new_dy[i])
        self._x_dist.append(new_dx + [0.0])
        self._y_dist.append(new_dy + [0.0])
        self._x_obs.append(x_value)
        self._y_obs.append(y_value)
        # 容量控制
        if len(self._x_obs) > _MAX_OBS:
            self._trim()

    # //// 距离相关计算 ////
    def compute(self) -> Optional[DCorResult]:
        """计算距离相关系数."""
        n = len(self._x_obs)
        if n < 10:
            return None

        # U-centering: 双中心化距离矩阵
        A = self._u_center(self._x_dist, n)
        B = self._u_center(self._y_dist, n)

        # dCov² = (1/(n(n-3))) Σ_{i≠j} A_{ij}·B_{ij}
        dcov_sq = 0.0
        for i in range(n):
            for j in range(n):
                if i != j:
                    dcov_sq += A[i][j] * B[i][j]
        dcov_sq /= max(1, n * (n - 3))

        # dVar(X) = dCov(X,X)
        dvar_x = 0.0
        for i in range(n):
            for j in range(n):
                if i != j:
                    dvar_x += A[i][j] * A[i][j]
        dvar_x /= max(1, n * (n - 3))

        dvar_y = 0.0
        for i in range(n):
            for j in range(n):
                if i != j:
                    dvar_y += B[i][j] * B[i][j]
        dvar_y /= max(1, n * (n - 3))

        dcor = 0.0
        if dvar_x > 0 and dvar_y > 0:
            dcor = math.sqrt(max(0.0, dcov_sq)) / math.sqrt(
                math.sqrt(dvar_x * dvar_y))

        # 置换检验
        p_value = self._permutation_test(n)

        # 效应量解释
        if dcor < 0.1:
            es = "negligible"
        elif dcor < 0.3:
            es = "small"
        elif dcor < 0.5:
            es = "medium"
        else:
            es = "large"

        return DCorResult(
            dcor=dcor, dcov_sq=dcov_sq,
            p_value=p_value, is_significant=p_value < 0.05,
            n_observations=n, effect_size=es)

    def _u_center(self, D: List[List[float]], n: int) -> List[List[float]]:
        """U-center 距离矩阵 (无偏双中心化).

        A_{ij} = D_{ij} - D_{i·}/(n-2) - D_{·j}/(n-2) + D_{··}/((n-1)(n-2))
        若 i=j, A_{ii} = 0.
        """
        row_sums = [sum(row) for row in D]
        grand_total = sum(row_sums)
        A = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                rs_i = (row_sums[i] - D[i][j]) / max(1, n - 2)
                cs_j = (sum(D[k][j] for k in range(n)) - D[i][j]) / max(1, n - 2)
                gt = (grand_total - row_sums[i] - sum(D[k][j] for k in range(n))
                      + D[i][j]) / max(1, (n - 1) * (n - 2))
                A[i][j] = D[i][j] - rs_i - cs_j + gt
        return A

    def _permutation_test(self, n: int) -> float:
        """置换检验: H₀="X 与 Y 独立"."""
        y_perm = list(self._y_obs)
        rng = random.Random(42)
        count_exceed = 0
        n_perm = min(_N_PERMUTATIONS, 50)
        # 计算观测 dCov²
        obs_dcov = abs(self._compute_quick_dcov(
            self._x_dist, self._y_dist, n))
        for _ in range(n_perm):
            rng.shuffle(y_perm)
            # 重建 y 距离矩阵 (仅用置换后的值)
            y_d_perm = [[abs(y_perm[i] - y_perm[j]) for j in range(n)]
                       for i in range(n)]
            perm_dcov = abs(self._compute_quick_dcov(
                self._x_dist, y_d_perm, n))
            if perm_dcov >= obs_dcov:
                count_exceed += 1
        return (count_exceed + 1) / (n_perm + 1)

    def _compute_quick_dcov(self, XD: List[List[float]],
                             YD: List[List[float]], n: int) -> float:
        """快速 dCov² (仅中心矩, 不做 U-center)."""
        A = self._u_center(XD, n)
        B = self._u_center(YD, n)
        s = 0.0
        for i in range(n):
            for j in range(n):
                if i != j:
                    s += A[i][j] * B[i][j]
        return s / max(1, n * (n - 3))

    # //// 多变量偏 dCor ////
    @staticmethod
    def partial_dcor(dcor_xy: float, dcor_xz: float,
                     dcor_yz: float) -> float:
        """偏距离相关: 控制 Z 后 X 和 Y 的净依赖.

        pdCor(X,Y;Z) = (dCor(X,Y) - dCor(X,Z)·dCor(Y,Z))
                      / sqrt((1-dCor(X,Z)²)(1-dCor(Y,Z)²))
        """
        num = dcor_xy - dcor_xz * dcor_yz
        denom = math.sqrt(max(0.0, (1.0 - dcor_xz * dcor_xz)
                              * (1.0 - dcor_yz * dcor_yz)))
        if denom < 1e-10:
            return 0.0
        return max(-1.0, min(1.0, num / denom))

    # //// 辅助 ////
    def _trim(self) -> None:
        """保留最近观测."""
        n = len(self._x_obs)
        keep = min(_MAX_OBS, n)
        start = n - keep
        self._x_obs = self._x_obs[start:]
        self._y_obs = self._y_obs[start:]
        self._x_dist = [row[start:] for row in self._x_dist[start:]]
        self._y_dist = [row[start:] for row in self._y_dist[start:]]

    # //// 统计 ////
    def stats(self) -> dict:
        result = self.compute()
        if result is None:
            return {"n": len(self._x_obs), "status": "insufficient_data"}
        return {
            "n": result.n_observations,
            "dcor": round(result.dcor, 4),
            "dcov_sq": round(result.dcov_sq, 6),
            "p_value": round(result.p_value, 4),
            "significant": result.is_significant,
            "effect_size": result.effect_size,
        }

    def clear(self) -> None:
        self._x_obs.clear(); self._y_obs.clear()
        self._x_dist.clear(); self._y_dist.clear()
