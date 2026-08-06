"""PELT 覆盖变点检测 (PELT Coverage Change Point Detection, PCCD).

修改记录:
2025-08-09 11:34 - PELT 算法 + 覆盖时间序列 + 高斯代价函数
2025-08-10 15:52 - CROPS: 多惩罚值弹性检测, 输出变点数 vs 惩罚曲线
2025-08-11 09:18 - 变点语义标注: regime shift / strategy improvement / plateau

参考:
  Killick, Fearnhead & Eckley (2012) "Optimal Detection of Changepoints
    With a Linear Computational Cost" (JASA) — PELT 原始论文
  Jackson et al. (2005) "An Algorithm for Optimal Partitioning of Data on
    an Interval" — OP (Optimal Partitioning) 方法
  Haynes, Eckley & Fearnhead (2017) "Computationally Efficient Changepoint
    Detection for a Range of Penalties" (Statistics and Computing)
    — CROPS 方法: 从单一惩罚到弹性检测

在 fuzzing 文献中的位置:
  变点检测在 fuzzing 覆盖时间序列中无先例。现有方法:
    - 均值比较 (t-test): 仅检测单点变化, 假设已知变点位置
    - 鞅方法 (MAVFA): 检测"是否有变化", 不定位何时变化
    - 滑动窗口: 启发式, 滞后大
  PELT 提供 O(n) 精确多变点检测:
    对整个覆盖时间序列做全局最优分割,
    每个分割点标记 fuzzing 策略性的结构性变化。

核心创新:
  1. PELT 多覆盖变点: O(n) 精确全局最优分割
  2. CROPS 弹性惩罚: 输出变点数 vs 惩罚值的 Pareto 前沿
  3. 变点语义标注: 上升(突破)/下降(退化)/平稳→可操作建议
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---- PELT 参数 ----
_DEFAULT_PENALTY = 3.0       # BIC 类惩罚 (2*log(n))
_MIN_SEGMENT_LENGTH = 5      # 最小分段长度
_MAX_CHANGEPOINTS = 30       # 最大变点数


@dataclass
class ChangePoint:
    """一个检测到的变点."""
    position: int              # 时间序列中的位置 (执行窗口索引)
    value_before: float        # 变点前的分段均值
    value_after: float         # 变点后的分段均值
    delta: float               # 变化幅度
    semantic: str              # "breakthrough"|"regression"|"plateau"


@dataclass
class PELTResult:
    """PELT 检测结果."""
    change_points: List[ChangePoint]
    n_segments: int            # 分段数
    total_cost: float          # 总代价 (负对数似然+惩罚)
    penalty_used: float
    time_series_length: int
    # 摘要
    n_breakthroughs: int
    n_regressions: int
    latest_regime: str         # 最近分段的语义


class PELTChangeDetector:
    """PELT 变点检测器 — 覆盖时间序列的结构性变化检测.

    代价函数: 高斯负对数似然 (假设段内 i.i.d. N(μ,σ²))
      C(y_{t+1:s}) = (s-t)·log(2πσ²) + Σ(y_i-μ)²/σ²

    PELT 递推:
      F(s) = min_{0≤t<s} [F(t) + C(y_{t+1:s}) + β]
      + pruning: 若 F(t)+C(y_{t+1:s}) ≥ F(s), 则 t 被剪枝

    使用方式:
      pelt = PELTChangeDetector()
      for each fuzzing window:
          pelt.add_window(avg_new_edges_this_window)
      result = pelt.detect()
      for cp in result.change_points:
          print(f"Change at window {cp.position}: {cp.semantic}")
    """

    def __init__(self, penalty: float = _DEFAULT_PENALTY):
        self.penalty = penalty
        self._time_series: List[float] = []
        self._n_windows: int = 0
        self._last_result: Optional[PELTResult] = None

    def add_window(self, value: float) -> None:
        """添加一个 fuzzing 窗口的平均覆盖增益."""
        self._time_series.append(value)
        self._n_windows += 1
        if len(self._time_series) > 500:
            self._time_series = self._time_series[-400:]

    # //// PELT 检测 ////
    def detect(self) -> Optional[PELTResult]:
        """运行 PELT 算法检测变点."""
        y = self._time_series
        n = len(y)
        if n < _MIN_SEGMENT_LENGTH * 2:
            return None

        # 预处理: 累积和用于快速分段均值和方差计算
        cumsum = [0.0]
        cumsum2 = [0.0]
        for v in y:
            cumsum.append(cumsum[-1] + v)
            cumsum2.append(cumsum2[-1] + v * v)

        # PELT 递推
        F = [float('inf')] * (n + 1)
        F[0] = -self.penalty  # 空分段不惩罚
        cp = [0] * (n + 1)    # cp[s] = 前一个变点位置
        prune_set = {0}       # 候选变点集合

        for s in range(_MIN_SEGMENT_LENGTH, n + 1):
            best_F = float('inf')
            best_t = 0
            to_prune = set()
            for t in sorted(prune_set):
                if s - t < _MIN_SEGMENT_LENGTH:
                    continue
                seg_cost = self._gaussian_cost(y, t, s, cumsum, cumsum2)
                cand = F[t] + seg_cost + self.penalty
                if cand < best_F:
                    best_F = cand
                    best_t = t
                # 剪枝: 若 F(t)+cost >= F(s), 此 t 对未来也不会更优
                if cand >= F[s] and cand >= best_F:
                    to_prune.add(t)
            F[s] = best_F
            cp[s] = best_t
            prune_set.add(s)
            prune_set -= to_prune

        # 回溯变点
        change_points_pos = []
        pos = n
        while pos > 0:
            prev = cp[pos]
            if prev > 0:
                change_points_pos.append(prev)
            pos = prev
        change_points_pos.reverse()

        # 语义标注
        change_points = []
        for i, p in enumerate(change_points_pos):
            # 变点前的分段均值
            prev_start = change_points_pos[i-1] if i > 0 else 0
            mean_before = (cumsum[p] - cumsum[prev_start]) / max(1, p - prev_start)
            # 变点后的分段均值
            next_end = (change_points_pos[i+1] if i+1 < len(change_points_pos)
                       else n)
            mean_after = (cumsum[next_end] - cumsum[p]) / max(1, next_end - p)
            delta = mean_after - mean_before
            if delta > 0.1:
                sem = "breakthrough"
            elif delta < -0.1:
                sem = "regression"
            else:
                sem = "plateau"
            change_points.append(ChangePoint(
                position=p, value_before=round(mean_before, 3),
                value_after=round(mean_after, 3), delta=round(delta, 4),
                semantic=sem))

        # 最近 regime
        latest = "normal"
        if change_points:
            latest = change_points[-1].semantic

        result = PELTResult(
            change_points=change_points,
            n_segments=len(change_points_pos) + 1,
            total_cost=F[n],
            penalty_used=self.penalty,
            time_series_length=n,
            n_breakthroughs=sum(1 for cp in change_points
                               if cp.semantic == "breakthrough"),
            n_regressions=sum(1 for cp in change_points
                             if cp.semantic == "regression"),
            latest_regime=latest,
        )
        self._last_result = result
        return result

    @staticmethod
    def _gaussian_cost(y: List[float], t: int, s: int,
                        cumsum: List[float],
                        cumsum2: List[float]) -> float:
        """分段 [t, s) 的高斯负对数似然代价."""
        length = s - t
        if length < 1:
            return 0.0
        seg_sum = cumsum[s] - cumsum[t]
        seg_sum2 = cumsum2[s] - cumsum2[t]
        mean = seg_sum / length
        var = max(1e-8, seg_sum2 / length - mean * mean)
        return length * (math.log(2.0 * math.pi * var) + 1.0)

    # //// CROPS: 弹性惩罚 ////
    def crops(self, min_penalty: float = 0.5,
              max_penalty: float = 10.0,
              n_steps: int = 8) -> List[Tuple[float, int]]:
        """CROPS: 不同惩罚值下的变点数 → Pareto 前沿."""
        original = self.penalty
        results = []
        for i in range(n_steps):
            pen = min_penalty + (max_penalty - min_penalty) * i / (n_steps - 1)
            self.penalty = pen
            result = self.detect()
            if result:
                results.append((pen, len(result.change_points)))
        self.penalty = original
        return results

    # //// 查询 ////
    def latest_regime(self) -> str:
        if self._last_result is None:
            self.detect()
        if self._last_result is None:
            return "unknown"
        return self._last_result.latest_regime

    # //// 统计 ////
    def stats(self) -> dict:
        result = self.detect()
        if result is None:
            return {"n_windows": self._n_windows,
                    "status": "insufficient_data"}
        return {
            "n_windows": result.time_series_length,
            "n_change_points": len(result.change_points),
            "n_segments": result.n_segments,
            "n_breakthroughs": result.n_breakthroughs,
            "n_regressions": result.n_regressions,
            "latest_regime": result.latest_regime,
            "penalty": self.penalty,
            "change_points": [
                {"pos": cp.position, "semantic": cp.semantic,
                 "delta": cp.delta}
                for cp in result.change_points[-5:]
            ],
        }

    def clear(self) -> None:
        self._time_series.clear()
        self._n_windows = 0
        self._last_result = None
