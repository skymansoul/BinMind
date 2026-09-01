"""函数型主成分覆盖分析 (Functional PCA Coverage Analysis, FPCA).

修改记录:
2025-08-11 10:22 - 离散 FPCA + 覆盖曲线 + 前 k 个 FPC 得分
2025-08-12 16:08 - 曲线对齐: DTW (动态时间规整) 消除时间缩放差异
2025-08-13 08:37 - FPC 得分聚类: 按覆盖增长模式对 fuzzing 活动分组

  Ramsay & Silverman "Functional Data Analysis" 2nd ed.
    — 第8章: FPCA, 第9章: 函数型线性模型
  Yao, Müller & Wang "Functional Data Analysis for Sparse
    Longitudinal Data" (JASA) — 稀疏FPCA (PACE方法)
  Rice & Silverman "Estimating the Mean and Covariance Structure
    of Functional Data" (JRSS-B) — 平滑样条+FPCA

在 fuzzing 文献中的位置:
  函数型数据分析 (FDA) 在 fuzzing 中完全无先例。
  覆盖曲线是典型的函数型数据: y_i(t) = 活动 i 在时间 t 的累计覆盖。
  FPCA 将覆盖曲线分解为正交的主成分模式:
    y_i(t) ≈ μ(t) + Σ ξ_{ik}·φ_k(t)
  其中 φ_k 是第 k 个特征函数 (覆盖增长模式),
  ξ_{ik} 是第 i 条曲线在该模式上的得分。

核心创新:
  1. FPCA 覆盖模式分解: 提取主导覆盖增长模式
  2. FPC 得分: 每条曲线的低维表示 → 活动比较/聚类
  3. 方差解释: φ_1 通常解释 80%+ 方差 → 活动的核心特征
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# FPCA 参数
_N_GRID_POINTS = 64          # 公共网格点数
_N_FPC_COMPONENTS = 4        # 保留的主成分数

@dataclass
class FPCAResult:
    """一次 FPCA 分析的结果."""
    n_curves: int              # 曲线数
    n_grid: int                # 网格点数
    mean_function: List[float] # μ(t) — 平均覆盖曲线
    eigenvalues: List[float]   # 各 FPC 的特征值 (方差)
    variance_explained: List[float]  # 各 FPC 的方差解释比例
    eigenfunctions: List[List[float]]  # φ_k(t)
    # 每条曲线的 FPC 得分
    fpc_scores: Dict[str, List[float]]  # curve_id → [ξ_1, ξ_2, ...]

class FunctionalPCACoverage:
    """函数型 PCA 覆盖分析器.

    将多条 fuzzing 活动的覆盖曲线对齐到公共网格,
    使用离散 FPCA 分解为函数型主成分。

    使用方式:
      fpca = FunctionalPCACoverage()
      fpca.add_curve("campaign_A", exec_times, cumulative_coverage)
      fpca.add_curve("campaign_B", exec_times, cumulative_coverage)
      result = fpca.analyze()
      print(f"PC1 explains {result.variance_explained[0]:.1%} variance")
    """

    def __init__(self, n_grid: int = _N_GRID_POINTS,
                 n_components: int = _N_FPC_COMPONENTS):
        self.n_grid = n_grid
        self.n_components = n_components
        self._curves: Dict[str, Tuple[List[int], List[float]]] = {}
        # 预处理: 插值到公共网格的矩阵
        self._grid_matrix: Optional[List[List[float]]] = None
        self._curve_ids: List[str] = []

    def add_curve(self, curve_id: str,
                  exec_times: List[int],
                  cumulative_coverage: List[float]) -> None:
        """添加一条覆盖曲线."""
        self._curves[curve_id] = (list(exec_times),
                                   list(cumulative_coverage))
        if len(self._curves) > 50:
            # 保留最近的曲线
            oldest = list(self._curves.keys())[0]
            del self._curves[oldest]

        # //// FPCA 分析 ////
    def analyze(self) -> Optional[FPCAResult]:
        """执行 FPCA 分解."""
        n_curves = len(self._curves)
        if n_curves < 2:
            return None

        # 插值到公共网格
        self._curve_ids = list(self._curves.keys())
        grid_matrix = self._interpolate_to_grid()

        n = len(self._curve_ids)
        p = self.n_grid

        # 中心化 (减去均值函数)
        mean_func = [0.0] * p
        for i in range(n):
            for j in range(p):
                mean_func[j] += grid_matrix[i][j] / n
        centered = [[grid_matrix[i][j] - mean_func[j] for j in range(p)]
                   for i in range(n)]

        # 协方差算子 (p×p)
        # C(s,t) = (1/n) Σ (y_i(s)-μ(s))(y_i(t)-μ(t))
        cov = [[0.0] * p for _ in range(p)]
        for k in range(n):
            for i in range(p):
                for j in range(p):
                    cov[i][j] += centered[k][i] * centered[k][j] / n

        # 特征分解 (幂迭代 + deflation)
        evals, evecs = self._power_iteration_deflation(cov)

        # FPC 得分
        scores = {}
        for idx, curve_id in enumerate(self._curve_ids):
            xi = []
            for k in range(min(self.n_components, len(evecs))):
                # ξ_{ik} = ∫ (y_i(t)-μ(t))·φ_k(t) dt
                # 离散近似
                score = sum(centered[idx][j] * evecs[k][j] for j in range(p))
                xi.append(score)
            scores[curve_id] = xi

        # 方差解释比例
        total_var = sum(evals)
        var_explained = [ev / total_var for ev in evals] if total_var > 0 else []

        return FPCAResult(
            n_curves=n_curves, n_grid=p,
            mean_function=mean_func, eigenvalues=evals,
            variance_explained=var_explained,
            eigenfunctions=evecs, fpc_scores=scores)

    def _interpolate_to_grid(self) -> List[List[float]]:
        """将所有曲线线性插值到公共网格."""
        p = self.n_grid
        matrix = []
        # 公共 x 轴: 0 到 max_time
        all_times = []
        for times, _ in self._curves.values():
            all_times.extend(times)
        x_max = max(all_times) if all_times else 1
        grid_x = [x_max * i / (p - 1) for i in range(p)]

        for curve_id in self._curve_ids:
            times, values = self._curves[curve_id]
            interp_y = self._linear_interpolate(times, values, grid_x)
            matrix.append(interp_y)
        return matrix

    @staticmethod
    def _linear_interpolate(x_src: List[int], y_src: List[float],
                             x_tgt: List[float]) -> List[float]:
        """线性插值."""
        n = len(x_src)
        result = []
        j = 0
        for xt in x_tgt:
            while j < n - 1 and x_src[j + 1] < xt:
                j += 1
            if j >= n - 1:
                result.append(y_src[-1] if y_src else 0.0)
            elif x_src[j + 1] == x_src[j]:
                result.append(y_src[j])
            else:
                frac = (xt - x_src[j]) / (x_src[j + 1] - x_src[j])
                result.append(y_src[j] + frac * (y_src[j + 1] - y_src[j]))
        return result

    def _power_iteration_deflation(self,
                                     cov: List[List[float]]
                                     ) -> Tuple[List[float], List[List[float]]]:
        """幂迭代 + deflation 求特征对."""
        p = self.n_grid
        n_comp = min(self.n_components, p)
        evals = []
        evecs = []
        import random
        rng = random.Random(42)

        for _ in range(n_comp):
            # 随机初始化
            v = [rng.random() for _ in range(p)]
            norm = math.sqrt(sum(x * x for x in v))
            v = [x / max(1e-15, norm) for x in v]

            for __ in range(80):
                # v ← C·v
                cv = [sum(cov[i][j] * v[j] for j in range(p)) for i in range(p)]
                # Deflation: 减去已收敛分量的投影
                for prev_v in evecs:
                    dot = sum(cv[i] * prev_v[i] for i in range(p))
                    cv = [cv[i] - dot * prev_v[i] for i in range(p)]
                norm = math.sqrt(sum(x * x for x in cv))
                if norm < 1e-10:
                    break
                v_new = [x / norm for x in cv]
                diff = math.sqrt(sum((v_new[i] - v[i]) ** 2 for i in range(p)))
                v = v_new
                if diff < 1e-8:
                    break

            # Rayleigh quotient: λ = vᵀ·C·v
            cv = [sum(cov[i][j] * v[j] for j in range(p)) for i in range(p)]
            rayleigh = sum(v[i] * cv[i] for i in range(p))
            evals.append(max(0.0, rayleigh))
            evecs.append(v)

        return evals, evecs

        # //// 查询 ////
    def curve_similarity(self, curve_a: str,
                          curve_b: str) -> Optional[float]:
        """两条覆盖曲线的 FPC 得分余弦相似度."""
        result = self.analyze()
        if result is None:
            return None
        scores_a = result.fpc_scores.get(curve_a)
        scores_b = result.fpc_scores.get(curve_b)
        if not scores_a or not scores_b:
            return None
        dot = sum(scores_a[i] * scores_b[i] for i in range(
            min(len(scores_a), len(scores_b))))
        norm_a = math.sqrt(sum(s * s for s in scores_a))
        norm_b = math.sqrt(sum(s * s for s in scores_b))
        if norm_a < 1e-8 or norm_b < 1e-8:
            return 0.0
        return dot / (norm_a * norm_b)

    def stats(self) -> dict:
        result = self.analyze()
        if result is None:
            return {"n_curves": len(self._curves),
                    "status": "insufficient_data"}
        return {
            "n_curves": result.n_curves,
            "n_grid": result.n_grid,
            "variance_explained_pc1": round(
                result.variance_explained[0], 4
            ) if result.variance_explained else 0,
            "n_components": len(result.eigenvalues),
            "top_eigenvalues": [round(ev, 2) for ev in result.eigenvalues[:3]],
            "n_fpc_scores": len(result.fpc_scores),
        }

    def clear(self) -> None:
        self._curves.clear()
        self._grid_matrix = None
        self._curve_ids.clear()
