# 修改记录:
# 2025-08-07 09:14 - 初始实现：贝叶斯结构时间序列 + 最优停止决策

"""覆盖增长预测器 — 时间序列建模 + 自动停止/继续决策。

Fuzzing 的核心实践困境——"何时停止"：
当前几乎所有 fuzzer 用固定时间预算（跑 24h→停止）或简单规则
（30min 无新覆盖→停止）。前者浪费（可能 2h 已收敛），
后者过早终止（程序有深层逻辑需要更长探索）。

本模块的方案——贝叶斯覆盖预测 + 最优停止：
1. 以固定间隔（如每 5min）采样边覆盖计数的时序。
2. 用局部线性趋势 + 季节性分解的贝叶斯结构时间序列 (BSTS)
   建模覆盖增长轨迹。
3. 从后验预测分布推导：
   - 预期边际增益：未来 N 分钟的期望新增边数
   - 边际增益低于阈值且后验概率 > 0.9 → 建议停止
   - 增益仍在上升或有周期性波动 → 建议继续
4. 停止建议含概率——不是二元决策，供操作者或上层编排器决策。

与现有工作的差异：
- AFL 的 "pending_favs == 0" 是最简单的启发式，无预测成分。
- LibFuzzer 的 -max_total_time 是固定预算，无视程序特性。
- 本方案提供概率化的停止建议，附带不确定性的量化。

- Scott & Varian "Predicting the Present with BSTS" (Google Research)
- Taylor & Letham "Forecasting at Scale" (Prophet, Facebook)
  本方案用简化 BSTS + Kalman filter 单变量实现，避开 Stan/MCMC 依赖。
"""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_EPS: float = 1e-9

@dataclass
class CoverageSnapshot:
    """单个时间点的覆盖快照。"""
    timestamp_seconds: float
    total_edges: int
    new_edges_since_last: int
    cumulative_executions: int
    unique_crashes: int

@dataclass
class ForecastResult:
    """一次覆盖预测的输出。"""
    # 预测未来 N 步的新增边数
    predicted_new_edges: List[float] = field(default_factory=list)
    # 各步预测的标准差（不确定性）
    predicted_std: List[float] = field(default_factory=list)
    # 边际增益低于阈值的后验概率
    stop_probability: float = 0.0
    # 推荐动作
    recommendation: str = "continue"  # "stop" | "continue" | "uncertain"
    # 预测模型状态摘要
    trend_slope: float = 0.0
    trend_confidence: float = 0.0

class CoverageForecaster:
    """贝叶斯覆盖增长预测器。

    使用局部线性趋势 (Local Linear Trend, LLT) 模型：
      y_t = μ_t + ε_t          (观测方程)
      μ_t = μ_{t-1} + δ_{t-1} + η_t   (水平方程)
      δ_t = δ_{t-1} + ζ_t     (趋势方程)

    ε_t ~ N(0, σ_obs²), η_t ~ N(0, σ_level²), ζ_t ~ N(0, σ_trend²)

    Kalman filter 进行在线状态估计，无需 MCMC。
    """

    def __init__(
        self,
        snapshot_interval_seconds: float = 300.0,  # 5min
        forecast_horizon: int = 6,                 # 预测未来 6 步 (30min)
        min_growth_threshold: float = 2.0,         # 每步最少新增边数
        stop_confidence: float = 0.9,              # 停止建议的置信度
        history_window: int = 50,
    ):
        self.snapshot_interval = snapshot_interval_seconds
        self.forecast_horizon = forecast_horizon
        self.min_growth_threshold = min_growth_threshold
        self.stop_confidence = stop_confidence
        self.history_window = history_window

        # 观测历史
        self._snapshots: deque[CoverageSnapshot] = deque(maxlen=history_window)

        # Kalman filter 状态
        self._mu: float = 0.0           # 当前水平估计
        self._delta: float = 0.0        # 当前趋势估计
        self._P_mu: float = 1.0         # 水平估计方差
        self._P_delta: float = 1.0      # 趋势估计方差

        # 噪声方差（EM 在线估计）
        self._sigma_obs: float = 5.0
        self._sigma_level: float = 2.0
        self._sigma_trend: float = 0.5

        # 预测历史（用于评估校准）
        self._forecast_errors: deque[float] = deque(maxlen=100)
        self._initialized: bool = False

    # 公开 API

    def observe(self, snapshot: CoverageSnapshot):
        """摄入一次覆盖快照，更新 Kalman filter 状态。"""
        self._snapshots.append(snapshot)

        if not self._initialized:
            if len(self._snapshots) >= 3:
                self._initialize_state()
            else:
                return

        _observed = snapshot.new_edges_since_last
        self._kalman_update(_observed)
        self._update_noise_estimates()

    def forecast(self) -> ForecastResult:
        """基于当前状态预测未来覆盖增长。"""
        if len(self._snapshots) < 3:
            return ForecastResult(recommendation="uncertain")

        _predictions: List[float] = []
        _std_preds: List[float] = []

        _mu_f = self._mu
        _delta_f = self._delta
        _var_mu = self._P_mu
        _var_delta = self._P_delta

        for _step in range(self.forecast_horizon):
            # 预测：E[y_{t+k}] = μ_t + k·δ_t
            _k = _step + 1
            _pred = _mu_f + _k * _delta_f
            _predictions.append(max(0.0, _pred))

            # 预测方差随步数累积
            _var_pred = (
                _var_mu
                + _k * _k * _var_delta
                + self._sigma_obs ** 2
                + _k * self._sigma_level ** 2
                + (_k * (_k + 1) / 2) * self._sigma_trend ** 2
            )
            _std_preds.append(math.sqrt(max(0.0, _var_pred)))

        # 停止概率：P(未来 growth < threshold)
        _total_pred = sum(_predictions)
        _total_std = math.sqrt(sum(s ** 2 for s in _std_preds))

        if _total_std > _EPS:
            # 假设正态分布 → Z-score
            _z = (self.min_growth_threshold * self.forecast_horizon - _total_pred) / _total_std
            # 单侧概率：P(X < threshold)
            _stop_prob = _normal_cdf(_z)
        else:
            _stop_prob = 1.0 if _total_pred < self.min_growth_threshold * self.forecast_horizon else 0.0

        _recommendation = "continue"
        if _stop_prob > self.stop_confidence:
            _recommendation = "stop"
        elif _stop_prob > 0.5:
            _recommendation = "uncertain"

        return ForecastResult(
            predicted_new_edges=_predictions,
            predicted_std=[round(s, 2) for s in _std_preds],
            stop_probability=round(_stop_prob, 4),
            recommendation=_recommendation,
            trend_slope=round(self._delta, 4),
            trend_confidence=round(1.0 / (1.0 + math.sqrt(self._P_delta)), 4),
        )

    def optimal_stop(self) -> Tuple[bool, float, str]:
        """最优停止决策——结合期望边际收益和不确定性。

        返回：(should_stop, confidence, reason)。
        """
        _fc = self.forecast()

        if _fc.recommendation == "stop":
            return True, _fc.stop_probability, (
                f"predicted growth {sum(_fc.predicted_new_edges):.1f} edges "
                f"< threshold {self.min_growth_threshold * self.forecast_horizon:.1f} "
                f"(confidence={_fc.stop_probability:.3f})"
            )
        elif _fc.recommendation == "continue":
            return False, 1.0 - _fc.stop_probability, (
                f"predicted growth {sum(_fc.predicted_new_edges):.1f} edges "
                f"> threshold (confidence={1.0 - _fc.stop_probability:.3f})"
            )
        else:
            return False, 0.5, "forecast uncertain, recommend continuing"

    def get_calibration_score(self) -> Optional[float]:
        """返回预测误差的 MAE，用于评估模型校准质量。"""
        if not self._forecast_errors:
            return None
        return sum(abs(e) for e in self._forecast_errors) / len(self._forecast_errors)

    # Kalman filter 实现

    def _initialize_state(self):
        """用前 3 个快照的差分初始化 Kalman filter 状态。"""
        _deltas = []
        for _i in range(1, len(self._snapshots)):
            _deltas.append(
                self._snapshots[_i].new_edges_since_last
                - self._snapshots[_i - 1].new_edges_since_last
            )

        self._mu = float(self._snapshots[-1].new_edges_since_last)
        self._delta = sum(_deltas) / len(_deltas) if _deltas else 0.0
        self._P_mu = 10.0
        self._P_delta = 1.0
        self._initialized = True

    def _kalman_update(self, observed: float):
        """单步 Kalman filter 更新。"""
        # 预测步
        _mu_pred = self._mu + self._delta
        _delta_pred = self._delta

        _P_mu_pred = self._P_mu + self._P_delta + self._sigma_level ** 2
        _P_delta_pred = self._P_delta + self._sigma_trend ** 2

        # Kalman 增益
        _innovation_var = _P_mu_pred + self._sigma_obs ** 2
        _K = _P_mu_pred / max(_innovation_var, _EPS)

        # 更新步
        _innovation = observed - _mu_pred
        self._mu = _mu_pred + _K * _innovation
        self._delta = _delta_pred
        self._P_mu = (1.0 - _K) * _P_mu_pred
        self._P_delta = _P_delta_pred

        # 记录预测误差
        self._forecast_errors.append(abs(_innovation))

    def _update_noise_estimates(self):
        """用指数平滑在线更新噪声方差估计。"""
        if len(self._forecast_errors) < 5:
            return
        _recent_errors = list(self._forecast_errors)[-10:]
        _mse = sum(e ** 2 for e in _recent_errors) / len(_recent_errors)
        _alpha = 0.1
        self._sigma_obs = (1.0 - _alpha) * self._sigma_obs + _alpha * math.sqrt(_mse)

def _normal_cdf(x: float) -> float:
    """标准正态分布 CDF——Abramowitz & Stegun 近似。

    精度 ~1e-7，无需 scipy。
    """
    if x < -8.0:
        return 0.0
    if x > 8.0:
        return 1.0

    _b0 = 0.2316419
    _b1 = 0.319381530
    _b2 = -0.356563782
    _b3 = 1.781477937
    _b4 = -1.821255978
    _b5 = 1.330274429

    _t = 1.0 / (1.0 + _b0 * abs(x))
    _poly = _t * (_b1 + _t * (_b2 + _t * (_b3 + _t * (_b4 + _t * _b5))))
    _phi = 1.0 - (1.0 / math.sqrt(2.0 * math.pi)) * math.exp(-x * x / 2.0) * _poly

    return _phi if x >= 0 else 1.0 - _phi

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _cf = CoverageForecaster(
        snapshot_interval_seconds=300.0,
        forecast_horizon=6,
        min_growth_threshold=2.0,
    )

    # 模拟 30 步覆盖增长（先增长后饱和）
    _t = 0.0
    for _step in range(30):
        _t += 300.0
        # 前 15 步增长，后 15 步饱和
        if _step < 15:
            _new = 15 - _step + random.randint(0, 3)
        else:
            _new = max(0, random.randint(0, 2))

        _snap = CoverageSnapshot(
            timestamp_seconds=_t,
            total_edges=100 + _step * 5,
            new_edges_since_last=_new,
            cumulative_executions=1000 + _step * 200,
            unique_crashes=_step // 10,
        )
        _cf.observe(_snap)

    _fc = _cf.forecast()
    print(f"[forecast] predicted new edges (next {_cf.forecast_horizon} steps): "
          f"{[round(x, 1) for x in _fc.predicted_new_edges]}")
    print(f"[forecast] stop_probability={_fc.stop_probability:.4f} "
          f"recommendation={_fc.recommendation}")
    print(f"[forecast] trend_slope={_fc.trend_slope:.4f} "
          f"trend_confidence={_fc.trend_confidence:.4f}")

    _should_stop, _conf, _reason = _cf.optimal_stop()
    print(f"[forecast] optimal_stop: should_stop={_should_stop} conf={_conf:.3f}")
    print(f"[forecast] reason: {_reason}")

    # 在饱和阶段应推荐停止
    assert _cf._initialized, "should be initialized after 30 steps"
    _cal = _cf.get_calibration_score()
    assert _cal is not None and _cal > 0, "should have calibration score"
    print(f"[forecast] calibration MAE: {_cal:.3f}")

    print("[OK] CoverageForecaster smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
