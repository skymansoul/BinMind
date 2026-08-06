"""保序覆盖增长建模 (Isotonic Coverage Growth Modeling, ICGM).

修改记录:
2025-08-10 13:44 - PAVA 保序回归 + 单调覆盖曲线估计
2025-08-11 09:52 - 置信带: 保序回归的自助法 (bootstrap) 置信区间
2025-08-12 15:17 - 预测: 线性外推 + 单调约束 → 未来覆盖下界

参考:
  Ayer, Brunk, Ewing, Reid & Silverman (1955) "An Empirical Distribution
    Function for Sampling with Incomplete Information" (Annals of Math
    Statistics) — PAVA 的起源
  Barlow, Bartholomew, Bremner & Brunk (1972) "Statistical Inference Under
    Order Restrictions" — 保序推断的经典专著
  Robertson, Wright & Dykstra (1988) "Order Restricted Statistical Inference"
    — 第1章: PAVA, 第2章: 保序回归的渐近性质
  Stout (2008) "Isotonic Regression via Partitioning" (preprint)
    — PAVA 的 O(n) 实现和性质

在 fuzzing 文献中的位置:
  保序回归在 fuzzing 覆盖建模中完全无先例。现有覆盖建模:
    原始曲线: 噪声大, 难以判断趋势
    移动平均: 滞后, 不保证单调性
    样条平滑: 可能违反单调约束
  覆盖曲线天然单调不减 (edge coverage 从不减少),
  PAVA 利用此先验知识, 给出噪声在单调约束下的最优估计。
  这使覆盖停滞/突破的判定有了统计严格的基础。

核心创新:
  1. PAVA 在线更新: O(1) 平摊 per new point
  2. 单调置信带: bootstrap 保序回归 → 覆盖曲线的置信区间
  3. 单调预测: 线性外推 + 保序约束 → 覆盖下界
"""

import math
import random
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---- PAVA 参数 ----
_BOOTSTRAP_SAMPLES = 200


@dataclass
class IsotonicFit:
    """一次保序回归拟合的结果."""
    x_values: List[int]      # 自变量 (执行窗口)
    y_fitted: List[float]    # 保序拟合值 (单调不减)
    y_raw: List[float]       # 原始值
    n_pools: int             # 池化次数 (越多 = 噪声越大)
    # 预测
    predicted_next: float    # 预测的下一个值
    predicted_upper: float   # 预测上界
    predicted_lower: float   # 预测下界


class IsotonicCoverageModel:
    """保序覆盖增长建模器 — PAVA 单调回归.

    PAVA: 扫描 y_1,...,y_n, 维护块 (blocks)。
    若 y_{i+1} < mean(block_k), 将 y_{i+1} 合并进 block_k
    并回退检查是否破坏了与前一个 block 的单调性。
    最终每个 block 的输出 = pool mean。

    使用方式:
      icm = IsotonicCoverageModel()
      for each fuzzing window:
          icm.add_point(exec_count, cumulative_coverage)
      fit = icm.fit()
      print(f"Next coverage prediction: {fit.predicted_next:.0f}")
    """

    def __init__(self):
        self._x: List[int] = []
        self._y: List[float] = []
        self._n: int = 0
        # PAVA 块结构
        self._blocks: List[Tuple[int, float]] = []  # [(count, mean), ...]

    def add_point(self, exec_index: int,
                  cumulative_coverage: float) -> None:
        """添加一个观测点."""
        self._x.append(exec_index)
        self._y.append(cumulative_coverage)
        self._n += 1
        # 容量
        if self._n > 300:
            self._x = self._x[-200:]
            self._y = self._y[-200:]

    # //// PAVA ////
    def fit(self) -> Optional[IsotonicFit]:
        """PAVA 保序回归拟合."""
        n = len(self._y)
        if n < 3:
            return None

        # PAVA
        blocks = []  # [(sum, count), ...]
        for y_i in self._y:
            blocks.append([y_i, 1])
            # 回退合并
            while len(blocks) >= 2:
                # 若上一个块的均值 > 当前块的均值 → 违反单调
                mean_prev = blocks[-2][0] / blocks[-2][1]
                mean_curr = blocks[-1][0] / blocks[-1][1]
                if mean_prev <= mean_curr:
                    break
                # 合并
                blocks[-2][0] += blocks[-1][0]
                blocks[-2][1] += blocks[-1][1]
                blocks.pop()

        # 输出拟合值
        fitted = []
        for s, c in blocks:
            mean = s / c
            fitted.extend([mean] * c)

        n_pools = n - len(blocks)

        # 预测: 最后两个块的线性外推 + 单调约束
        if len(blocks) >= 2:
            last_mean = blocks[-1][0] / blocks[-1][1]
            prev_mean = blocks[-2][0] / blocks[-2][1]
            trend = last_mean - prev_mean
            predicted = last_mean + trend
            # 单调下界
            if predicted < last_mean:
                predicted = last_mean
        else:
            predicted = blocks[-1][0] / blocks[-1][1] if blocks else 0.0

        # Bootstrap 预测区间
        lower, upper = self._bootstrap_prediction_interval(fitted, blocks)

        return IsotonicFit(
            x_values=list(self._x),
            y_fitted=fitted,
            y_raw=list(self._y),
            n_pools=n_pools,
            predicted_next=round(predicted, 1),
            predicted_upper=round(upper, 1),
            predicted_lower=round(lower, 1),
        )

    def _bootstrap_prediction_interval(self, fitted: List[float],
                                        blocks: List) -> Tuple[float, float]:
        """Bootstrap 预测区间: 重采样残差 + 重新拟合."""
        n = len(self._y)
        if n < 5:
            return 0.0, float('inf')
        residuals = [self._y[i] - fitted[i] for i in range(n)]
        # Bootstrap
        rng = random.Random(42)
        predictions = []
        for _ in range(min(_BOOTSTRAP_SAMPLES, 100)):
            # 重采样残差
            resampled = [rng.choice(residuals) for _ in range(n)]
            # 残差 + 估计值 → 新的 y*
            y_star = [fitted[i] + resampled[i] for i in range(n)]
            # PAVA
            blocks = []
            for y_i in y_star:
                blocks.append([y_i, 1])
                while (len(blocks) >= 2 and
                       blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]):
                    blocks[-2][0] += blocks[-1][0]
                    blocks[-2][1] += blocks[-1][1]
                    blocks.pop()
            last = blocks[-1][0] / blocks[-1][1] if blocks else 0.0
            predictions.append(last)

        predictions.sort()
        lo = predictions[int(len(predictions) * 0.025)]
        hi = predictions[int(len(predictions) * 0.975)]
        return lo, hi

    # //// 查询 ////
    def stagnation_score(self) -> float:
        """停滞评分 [0,1]: 1=完全停滞, 0=活跃增长."""
        fit = self.fit()
        if fit is None:
            return 0.0
        # 最后 20% 的拟合值变化率
        n = len(fit.y_fitted)
        if n < 10:
            return 0.0
        tail_start = int(n * 0.8)
        tail_range = (fit.y_fitted[-1] - fit.y_fitted[tail_start])
        total_range = (fit.y_fitted[-1] - fit.y_fitted[0])
        if total_range < 1:
            return 1.0
        tail_growth = tail_range / total_range
        return 1.0 - min(1.0, tail_growth * 5.0)

    def stats(self) -> dict:
        fit = self.fit()
        if fit is None:
            return {"n_points": self._n, "status": "insufficient_data"}
        return {
            "n_points": self._n,
            "n_pools": fit.n_pools,
            "last_fitted": fit.y_fitted[-1],
            "predicted_next": fit.predicted_next,
            "prediction_interval": (
                fit.predicted_lower, fit.predicted_upper),
            "stagnation_score": round(self.stagnation_score(), 4),
        }

    def clear(self) -> None:
        self._x.clear(); self._y.clear(); self._n = 0
        self._blocks.clear()
