"""Granger 因果覆盖预测 — VAR + F 检验 + 预测误差比较.

参考: Granger "Investigating Causal Relations by Econometric Models"
在 fuzzing 中零先例。测试 X 的历史是否有助于预测 Y 的未来,
超越 Y 自身历史。揭示 fuzzing 动态中的因果方向。"""

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class GrangerResult:
    cause_var: str             # X (潜在原因)
    effect_var: str            # Y (结果)
    f_statistic: float         # F 统计量
    p_value: float             # 显著性
    is_causal: bool            # p<0.05 → X Granger-causes Y
    error_ratio: float         # restricted/unrestricted MSE 比
    n_observations: int


class GrangerCausalityTest:
    """Granger 因果检验 — 覆盖时间序列的预测因果性.

    VAR(1): Y_t = α + β·Y_{t-1} + γ·X_{t-1} + ε_t
    H₀: γ=0 (X 不 Granger-cause Y)
    F 检验比较 restricted (γ=0) 和 unrestricted 模型的拟合。

    使用方式:
      gct = GrangerCausalityTest(max_lag=3)
      for each fuzzing window:
          gct.add_observation("seed_diversity", value)
          gct.add_observation("coverage_gain", value)
      result = gct.test("seed_diversity", "coverage_gain")
      if result.is_causal:
          print("Diversity Granger-causes coverage gain")
    """

    def __init__(self, max_lag: int = 3):
        self.max_lag = max_lag
        self._series: Dict[str, List[float]] = defaultdict(list)
        self._n: int = 0

    def add_observation(self, variable_name: str, value: float) -> None:
        self._series[variable_name].append(value)
        # 同步长度 (各变量应对齐)
        max_len = max(len(v) for v in self._series.values())
        for name in self._series:
            while len(self._series[name]) < max_len:
                self._series[name].insert(0, 0.0)
        self._n = max_len
        # 容量
        if self._n > 200:
            for name in self._series:
                self._series[name] = self._series[name][-150:]

    # //// Granger 因果检验 ////
    def test(self, cause_var: str, effect_var: str, lag: int = 1
             ) -> Optional[GrangerResult]:
        """检验 cause_var 是否 Granger-cause effect_var."""
        x = self._series.get(cause_var, [])
        y = self._series.get(effect_var, [])
        n = min(len(x), len(y))
        if n < lag + 5:
            return None

        # 构建滞后数据
        y_lag = y[lag:]          # Y_t
        y_lag1 = y[lag-1:-1]     # Y_{t-1}
        x_lag1 = x[lag-1:-1]     # X_{t-1}
        T = len(y_lag)

        # Unrestricted: Y_t = α + β·Y_{t-1} + γ·X_{t-1}
        # Restricted:   Y_t = α + β·Y_{t-1} (γ=0)
        # OLS 估计
        # SSR_unrestricted
        y_mean = sum(y_lag) / T
        x_lag1_mean = sum(x_lag1) / T
        y_lag1_mean = sum(y_lag1) / T

        # 简化: F = ((SSR_R - SSR_U)/q) / (SSR_U/(T-k))
        # q=1 (一个约束: γ=0), k=3 (3个参数: α,β,γ)
        # 用两变量回归的解析解

        # 去均值
        yc = [yi - y_mean for yi in y_lag]
        y1c = [yi - y_lag1_mean for yi in y_lag1]
        x1c = [xi - x_lag1_mean for xi in x_lag1]

        # Unrestricted: regress yc on y1c + x1c
        s_y1y1 = sum(a*a for a in y1c)
        s_x1x1 = sum(a*a for a in x1c)
        s_y1x1 = sum(a*b for a, b in zip(y1c, x1c))
        s_yy1 = sum(a*b for a, b in zip(yc, y1c))
        s_yx1 = sum(a*b for a, b in zip(yc, x1c))

        det = s_y1y1 * s_x1x1 - s_y1x1 * s_y1x1
        if abs(det) < 1e-15:
            return None

        beta = (s_yy1 * s_x1x1 - s_yx1 * s_y1x1) / det
        gamma = (s_yx1 * s_y1y1 - s_yy1 * s_y1x1) / det

        # SSR_U
        ssr_u = sum((yc[i] - beta*y1c[i] - gamma*x1c[i])**2
                    for i in range(T))

        # Restricted: regress yc on y1c only
        beta_r = s_yy1 / max(1e-15, s_y1y1)
        ssr_r = sum((yc[i] - beta_r*y1c[i])**2 for i in range(T))

        # F 统计量 (q=1 约束, T-3 自由度)
        if ssr_u < 1e-15:
            f_stat = 0.0
        else:
            f_stat = ((ssr_r - ssr_u) / 1.0) / (ssr_u / max(1, T - 3))

        # p-value (F(1, T-3))
        df = max(1, T - 3)
        p_value = self._f_dist_pvalue(f_stat, 1, df)

        error_ratio = ssr_r / max(1e-15, ssr_u)  # >1 表示 unrestricted 更好

        return GrangerResult(
            cause_var=cause_var, effect_var=effect_var,
            f_statistic=f_stat, p_value=p_value,
            is_causal=p_value < 0.05,
            error_ratio=error_ratio, n_observations=T)

    @staticmethod
    def _f_dist_pvalue(f_stat: float, df1: int, df2: int) -> float:
        """F 分布的 p-value 近似 (Satterthwaite)."""
        if f_stat < 0:
            return 1.0
        # 使用 Beta 不完全函数近似
        x = df2 / (df2 + df1 * f_stat)
        # 正则化不完全 Beta 函数 (数值近似)
        a, b = df2 / 2.0, df1 / 2.0
        # 简化: 使用正态近似
        if df1 == 1:
            t = math.sqrt(f_stat)
            # t 分布的 p-value (双尾): p = 2*(1 - Φ(|t|))
            z = abs(t)
            # Hastings 近似 Φ(z)
            phi = 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))
            return 2.0 * (1.0 - phi)
        return math.exp(-0.5 * f_stat)  # 粗近似

    # //// 多变量 Granger ////
    def multi_causal_graph(self, variables: List[str]
                            ) -> Dict[Tuple[str, str], float]:
        """所有变量对的 Granger 因果检验 → 因果图的邻接矩阵."""
        edges = {}
        for cause in variables:
            for effect in variables:
                if cause == effect:
                    continue
                r = self.test(cause, effect)
                if r and r.is_causal:
                    edges[(cause, effect)] = r.p_value
        return edges

    def stats(self) -> dict:
        n = len(self._series)
        return {"n_variables": n, "series_length": self._n,
                "variables": list(self._series.keys()),
                "max_lag": self.max_lag}

    def clear(self) -> None:
        self._series.clear(); self._n = 0
