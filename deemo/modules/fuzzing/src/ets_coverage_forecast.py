"""ETS 覆盖预测 — 指数平滑状态空间模型 + 预测区间.
参考: Hyndman et al. "Forecasting with Exponential Smoothing" (Springer).
在 fuzzing 中零先验。状态空间指数平滑比移动平均更优,
自动估计平滑参数 α, 提供概率预测区间。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ETSResult:
    alpha: float               # 平滑参数
    level: float               # 当前水平
    sigma: float               # 残差标准差
    aic: float                 # Akaike 信息准则
    forecasts: List[float]     # 未来 h 步预测
    lower_95: List[float]      # 95% 预测下界
    upper_95: List[float]      # 95% 预测上界
    n_observations: int


class ETSModel:
    """ETS 覆盖预测器 — 指数平滑状态空间模型.

    ETS(A,N,N): 加法误差, 无趋势, 无季节.
    状态: level_t = α·y_t + (1-α)·level_{t-1}
    预测: ŷ_{T+h|T} = level_T
    方差: Var(ŷ_{T+h}) = σ²(1 + (h-1)α²)

    使用方式:
      ets = ETSModel()
      for each window: ets.add(coverage_value)
      result = ets.forecast(h=10)
      print(f"Next 10: {result.forecasts}")
    """

    def __init__(self):
        self._y: List[float] = []
        self._n: int = 0
        self._alpha: float = 0.3
        self._level: float = 0.0
        self._sigma: float = 1.0

    def add(self, value: float) -> None:
        """添加新的覆盖观测."""
        self._y.append(value)
        self._n += 1
        # 在线更新 level (使用当前 α)
        if self._n == 1:
            self._level = value
        else:
            self._level = (self._alpha * value
                          + (1 - self._alpha) * self._level)
        if self._n > 200:
            self._y = self._y[-150:]
        # 每 20 步重新估计 α
        if self._n % 20 == 0 and self._n >= 10:
            self._estimate_alpha()

    def _estimate_alpha(self) -> None:
        """MLE 估计 α: 最小化一步预测误差平方和."""
        n = len(self._y)
        if n < 5:
            return
        # Grid search α ∈ [0.01, 0.99]
        best_alpha = 0.3; best_sse = float('inf')
        for alpha_cand in [0.01, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]:
            level = self._y[0]; sse = 0.0
            for t in range(1, n):
                forecast = level
                error = self._y[t] - forecast
                sse += error * error
                level = alpha_cand * self._y[t] + (1 - alpha_cand) * level
            if sse < best_sse:
                best_sse = sse; best_alpha = alpha_cand
        self._alpha = best_alpha
        # 用最优 α 更新最终 level
        level = self._y[0]
        for t in range(1, n):
            level = best_alpha * self._y[t] + (1 - best_alpha) * level
        self._level = level
        # 残差标准差
        sse_final = 0.0
        level_check = self._y[0]
        for t in range(1, n):
            error = self._y[t] - level_check
            sse_final += error * error
            level_check = best_alpha * self._y[t] + (1 - best_alpha) * level_check
        self._sigma = math.sqrt(max(1e-8, sse_final / (n - 2)))

    def forecast(self, h: int = 10) -> Optional[ETSResult]:
        """预测未来 h 步."""
        n = self._n
        if n < 5:
            return None
        self._estimate_alpha()

        # AIC = -2 log L + 2k, k=2 (α, σ²)
        # log L ≈ -(n/2)(log(2πσ²) + 1)
        aic = n * (math.log(2 * math.pi * self._sigma * self._sigma) + 1) + 4

        forecasts = [self._level] * h
        # 预测方差: σ²(1 + (h-1)α²)
        lower = []; upper = []
        z_95 = 1.96
        for step in range(1, h + 1):
            var = (self._sigma ** 2) * (1 + (step - 1) * self._alpha ** 2)
            se = math.sqrt(var)
            lower.append(self._level - z_95 * se)
            upper.append(self._level + z_95 * se)

        return ETSResult(
            alpha=self._alpha, level=self._level,
            sigma=self._sigma, aic=aic,
            forecasts=forecasts, lower_95=lower, upper_95=upper,
            n_observations=n)

    def stats(self) -> dict:
        r = self.forecast(5)
        if r is None:
            return {"n": self._n, "status": "insufficient_data"}
        return {"n": r.n_observations, "alpha": round(r.alpha, 3),
                "level": round(r.level, 2), "sigma": round(r.sigma, 2),
                "AIC": round(r.aic, 1),
                "forecast_next": round(r.forecasts[0], 2)}

    def clear(self) -> None:
        self._y.clear(); self._n = 0
        self._alpha = 0.3; self._level = 0.0; self._sigma = 1.0
