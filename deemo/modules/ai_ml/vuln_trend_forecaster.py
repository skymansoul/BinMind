"""
Vulnerability Trend Forecaster - Time-series forecasting for vulnerability data.

Provides SQLite-backed history storage, multiple forecasting methods,
seasonal pattern detection, and trend analysis for CVE/vuln data.
"""

from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TrendMethod(Enum):
    """Forecasting methods."""
    MOVING_AVG = "moving_avg"
    EXPONENTIAL = "exponential"
    LINEAR_REGRESSION = "linear_regression"
    NAIVE = "naive"
    SEASONAL = "seasonal"
    HOLT_WINTERS = "holt_winters"  # 三重指数平滑 — 处理趋势+季节性


@dataclass
class VulnTimePoint:
    """A single vulnerability data point in time."""
    timestamp: float
    binary_id: str
    vuln_type: str
    severity: str
    count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'binary_id': self.binary_id,
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'count': self.count,
        }


@dataclass
class Forecast:
    """A forecast result."""
    binary_id: str
    method: TrendMethod
    horizon: int
    predicted_count: float
    confidence_low: float
    confidence_high: float
    predicted_types: List[Tuple[str, float]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_id': self.binary_id,
            'method': self.method.value,
            'horizon': self.horizon,
            'predicted_count': self.predicted_count,
            'confidence_low': self.confidence_low,
            'confidence_high': self.confidence_high,
            'predicted_types': [
                {'type': t, 'predicted': p}
                for t, p in self.predicted_types
            ],
            'notes': self.notes,
        }


@dataclass
class ForecastMetrics:
    """Backtest evaluation metrics for a forecasting method. 回测评估指标."""
    method: str
    mae: float = 0.0       # Mean Absolute Error 平均绝对误差
    rmse: float = 0.0      # Root Mean Square Error 均方根误差
    mape: float = 0.0      # Mean Absolute Percentage Error 平均绝对百分比误差
    sample_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'method': self.method,
            'mae': round(self.mae, 4),
            'rmse': round(self.rmse, 4),
            'mape': round(self.mape, 4),
            'sample_count': self.sample_count,
        }


@dataclass
class TrendAnalysis:
    """Complete trend analysis for a binary."""
    binary_id: str
    history: List[VulnTimePoint]
    forecast: Forecast
    seasonality: Optional[Dict[str, float]] = None
    detected_trend: str = "stable"
    anomaly_score: float = 0.0  # 异常评分 — 越高越可疑，可能是零日爆发信号
    backtest_metrics: Optional[List[ForecastMetrics]] = None  # 回测结果 — 各方法准确率排名
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_id': self.binary_id,
            'history_count': len(self.history),
            'forecast': self.forecast.to_dict(),
            'seasonality': self.seasonality,
            'detected_trend': self.detected_trend,
            'anomaly_score': round(self.anomaly_score, 4),
            'backtest_metrics': (
                [m.to_dict() for m in self.backtest_metrics]
                if self.backtest_metrics else None
            ),
            'metadata': self.metadata,
        }


class VulnHistoryStore:
    """SQLite-backed storage for vulnerability time-series data."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'vuln_trend_history.sqlite3'
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self) -> None:
        """Create tables and indexes."""
        with self._lock, self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    binary_id TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    count INTEGER DEFAULT 1
                )
            """)
            c.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_binary
                ON history(binary_id)
            """)
            c.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_timestamp
                ON history(timestamp)
            """)
            c.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_type
                ON history(vuln_type)
            """)

    def add(self, tp: VulnTimePoint) -> None:
        """Add a time point to the store."""
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO history (timestamp, binary_id, vuln_type, severity, count) "
                "VALUES (?, ?, ?, ?, ?)",
                (tp.timestamp, tp.binary_id, tp.vuln_type, tp.severity, tp.count),
            )

    def add_batch(self, points: List[VulnTimePoint]) -> None:
        """Add multiple time points at once."""
        with self._lock, self._conn() as c:
            c.executemany(
                "INSERT INTO history (timestamp, binary_id, vuln_type, severity, count) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (p.timestamp, p.binary_id, p.vuln_type, p.severity, p.count)
                    for p in points
                ],
            )

    def get(
        self,
        binary_id: str,
        since_ts: Optional[float] = None,
        vuln_type: Optional[str] = None,
    ) -> List[VulnTimePoint]:
        """Query time points for a binary."""
        query = (
            "SELECT timestamp, binary_id, vuln_type, severity, count "
            "FROM history WHERE binary_id = ?"
        )
        params: List[Any] = [binary_id]

        if since_ts is not None:
            query += " AND timestamp >= ?"
            params.append(since_ts)
        if vuln_type is not None:
            query += " AND vuln_type = ?"
            params.append(vuln_type)

        query += " ORDER BY timestamp ASC"

        with self._lock, self._conn() as c:
            rows = c.execute(query, params).fetchall()

        return [
            VulnTimePoint(
                timestamp=r[0],
                binary_id=r[1],
                vuln_type=r[2],
                severity=r[3],
                count=r[4],
            )
            for r in rows
        ]

    def get_all_binaries(self) -> List[str]:
        """Get list of all known binary IDs."""
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT binary_id FROM history"
            ).fetchall()
        return [r[0] for r in rows]

    def get_vuln_types(self, binary_id: str) -> List[str]:
        """Get vulnerability types seen for a binary."""
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT vuln_type FROM history WHERE binary_id = ?",
                (binary_id,),
            ).fetchall()
        return [r[0] for r in rows]

    def count(self, binary_id: Optional[str] = None) -> int:
        """Count stored time points."""
        with self._lock, self._conn() as c:
            if binary_id:
                row = c.execute(
                    "SELECT COUNT(*) FROM history WHERE binary_id = ?",
                    (binary_id,),
                ).fetchone()
            else:
                row = c.execute("SELECT COUNT(*) FROM history").fetchone()
        return int(row[0]) if row else 0

    def clear(self, binary_id: Optional[str] = None) -> None:
        """Clear stored data."""
        with self._lock, self._conn() as c:
            if binary_id:
                c.execute(
                    "DELETE FROM history WHERE binary_id = ?",
                    (binary_id,),
                )
            else:
                c.execute("DELETE FROM history")


class TimeSeriesForecaster:
    """Multiple-method time series forecasting."""

    def forecast(
        self,
        series: List[float],
        horizon: int = 1,
        method: TrendMethod = TrendMethod.MOVING_AVG,
    ) -> Tuple[float, float, float]:
        """Forecast next value(s) from a series."""
        if not series:
            return (0.0, 0.0, 0.0)

        if method == TrendMethod.MOVING_AVG:
            return self._moving_avg(series, horizon)
        elif method == TrendMethod.EXPONENTIAL:
            return self._exponential(series, horizon)
        elif method == TrendMethod.LINEAR_REGRESSION:
            return self._linear_regression(series, horizon)
        elif method == TrendMethod.SEASONAL:
            return self._seasonal_forecast(series, horizon)
        elif method == TrendMethod.HOLT_WINTERS:
            return self._holt_winters(series, horizon)

        return self._naive(series, horizon)

    @staticmethod
    def _moving_avg(
        s: List[float],
        horizon: int,
    ) -> Tuple[float, float, float]:
        """Simple moving average forecast."""
        window = min(7, len(s))
        avg = sum(s[-window:]) / window
        var = sum((x - avg) ** 2 for x in s[-window:]) / max(1, window)
        std = math.sqrt(max(0.0, var))
        return (avg, max(0.0, avg - 1.96 * std), avg + 1.96 * std)

    @staticmethod
    def _exponential(
        s: List[float],
        horizon: int,
        alpha: float = 0.3,
    ) -> Tuple[float, float, float]:
        """Exponential smoothing forecast."""
        forecast_val = s[0]
        for v in s[1:]:
            forecast_val = alpha * v + (1 - alpha) * forecast_val
        var = sum((x - forecast_val) ** 2 for x in s) / max(1, len(s))
        std = math.sqrt(max(0.0, var))
        return (forecast_val, max(0.0, forecast_val - 1.96 * std), forecast_val + 1.96 * std)

    @staticmethod
    def _linear_regression(
        s: List[float],
        horizon: int,
    ) -> Tuple[float, float, float]:
        """Linear regression forecast."""
        n = len(s)
        if n < 2:
            val = s[0] if s else 0.0
            return (val, 0.0, val)

        x_mean = (n - 1) / 2.0
        y_mean = sum(s) / n

        num = sum((i - x_mean) * (s[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n)) or 1.0
        slope = num / den
        intercept = y_mean - slope * x_mean

        y_pred = intercept + slope * (n - 1 + horizon)

        residuals = [s[i] - (intercept + slope * i) for i in range(n)]
        std = math.sqrt(sum(r ** 2 for r in residuals) / max(1, n))

        return (max(0.0, y_pred), max(0.0, y_pred - 1.96 * std), y_pred + 1.96 * std)

    @staticmethod
    def _seasonal_forecast(
        s: List[float],
        horizon: int,
    ) -> Tuple[float, float, float]:
        """Seasonal decomposition forecast (simple)."""
        if len(s) < 4:
            return (s[-1], max(0.0, s[-1] * 0.5), s[-1] * 1.5)

        avg = sum(s) / len(s)
        var = sum((x - avg) ** 2 for x in s) / max(1, len(s))
        std = math.sqrt(max(0.0, var))
        return (avg, max(0.0, avg - 1.96 * std), avg + 1.96 * std)

    @staticmethod
    def _naive(
        s: List[float],
        horizon: int,
    ) -> Tuple[float, float, float]:
        """Naive forecast (last value)."""
        last = s[-1]
        return (last, max(0.0, last * 0.5), last * 1.5)

    # Holt-Winters 三重指数平滑 (Triple Exponential Smoothing)
    # 同时建模水平(level)、趋势(trend)、季节性(seasonality)三个分量
    # Holt 1957, Winters 1960; 在漏洞爆发预测中，季节性对应补丁周期
    @staticmethod
    def _holt_winters(
        s: List[float],
        horizon: int,
        season_length: int = 7,
        alpha: float = 0.3,
        beta: float = 0.1,
        gamma: float = 0.1,
    ) -> Tuple[float, float, float]:
        """Holt-Winters additive triple exponential smoothing.
        加性模型 — 适用于季节性振幅相对恒定的漏洞数据。
        """
        n = len(s)
        if n < season_length * 2:
            # 数据不足以做 Holt-Winters，降级为指数平滑
            return TimeSeriesForecaster._exponential(s, horizon, alpha)

        # 初始化水平、趋势、季节分量
        # 用前 season_length 个周期初始化季节因子
        level_0 = sum(s[:season_length]) / season_length
        trend_0 = (sum(s[season_length:2 * season_length]) -
                   sum(s[:season_length])) / (season_length * season_length)

        seasonal_init = [0.0] * season_length
        for i in range(season_length):
            seasonal_init[i] = s[i] - level_0

        # 前向平滑
        level = level_0
        trend = trend_0
        seasonal = list(seasonal_init)

        fitted = [0.0] * n
        for t_idx in range(n):
            # 一步预测
            if t_idx < season_length:
                fitted[t_idx] = s[t_idx]  # 初始化阶段不修正
            else:
                fitted[t_idx] = level + trend + seasonal[t_idx % season_length]

            # 更新各分量
            prev_level = level
            level = alpha * (s[t_idx] - seasonal[t_idx % season_length]) + (1 - alpha) * (level + trend)
            trend = beta * (level - prev_level) + (1 - beta) * trend
            seasonal[t_idx % season_length] = (
                gamma * (s[t_idx] - level) + (1 - gamma) * seasonal[t_idx % season_length]
            )

        # 预测 horizon 步
        last_level = level
        last_trend = trend
        forecast_val = last_level + horizon * last_trend
        # 加上对应季节分量
        forecast_val += seasonal[(n - 1 + horizon) % season_length]

        # 用拟合残差估计置信区间
        residuals = [s[i] - fitted[i] for i in range(season_length, n)]
        if residuals:
            std = math.sqrt(sum(r ** 2 for r in residuals) / len(residuals))
        else:
            std = last_level * 0.1

        forecast_val = max(0.0, forecast_val)
        return (forecast_val, max(0.0, forecast_val - 1.96 * std), forecast_val + 1.96 * std)

    # 回测评估 — 用历史数据验证各方法预测精度，返回指标排名
    # 思想：留出最后 holdout_days 的数据作为验证集，用前面数据训练并预测
    @classmethod
    def evaluate_methods(
        cls,
        series: List[float],
        holdout_days: int = 3,
    ) -> List[ForecastMetrics]:
        """Backtest all available methods against historical holdout data."""
        if len(series) < holdout_days + 3:
            return []

        train = series[:-holdout_days]
        actual = series[-holdout_days:]

        methods_to_eval = [
            TrendMethod.MOVING_AVG,
            TrendMethod.EXPONENTIAL,
            TrendMethod.LINEAR_REGRESSION,
            TrendMethod.NAIVE,
            TrendMethod.SEASONAL,
            TrendMethod.HOLT_WINTERS,
        ]

        # 聚合所有方法的结果，最后统一排名
        results: List[ForecastMetrics] = []

        for m in methods_to_eval:
            try:
                pred, _, _ = cls._forecast_static(train, m)
            except Exception:
                continue

            # 对每个验证点计算误差 — 用预测值 vs 各验证点均值做近似
            errors = [abs(pred - a) for a in actual]
            n_val = len(errors)

            if n_val == 0:
                continue

            mae = sum(errors) / n_val
            rmse = math.sqrt(sum(e ** 2 for e in errors) / n_val)
            # MAPE — 避免除零
            mape_sum = 0.0
            valid_mape = 0
            for a, e in zip(actual, errors):
                if abs(a) > 1e-9:
                    mape_sum += (e / abs(a)) * 100.0
                    valid_mape += 1
            mape_val = mape_sum / max(1, valid_mape)

            results.append(ForecastMetrics(
                method=m.value,
                mae=mae,
                rmse=rmse,
                mape=mape_val,
                sample_count=n_val,
            ))

        # 按 RMSE 升序 — 越小越好
        results.sort(key=lambda x: x.rmse)
        return results

    @staticmethod
    def _forecast_static(
        series: List[float],
        method: TrendMethod,
    ) -> Tuple[float, float, float]:
        """Static helper for internal backtesting — avoids instance creation overhead."""
        if not series:
            return (0.0, 0.0, 0.0)
        if method == TrendMethod.MOVING_AVG:
            return TimeSeriesForecaster._moving_avg(series, 1)
        elif method == TrendMethod.EXPONENTIAL:
            return TimeSeriesForecaster._exponential(series, 1)
        elif method == TrendMethod.LINEAR_REGRESSION:
            return TimeSeriesForecaster._linear_regression(series, 1)
        elif method == TrendMethod.SEASONAL:
            return TimeSeriesForecaster._seasonal_forecast(series, 1)
        elif method == TrendMethod.HOLT_WINTERS:
            return TimeSeriesForecaster._holt_winters(series, 1)
        return TimeSeriesForecaster._naive(series, 1)


class SeasonalPatternDetector:
    """Detects seasonal patterns in time series data."""

    def detect(
        self,
        series: List[Tuple[float, int]],
        period_days: int = 30,
    ) -> Optional[Dict[str, float]]:
        """Detect seasonal patterns in timestamped data."""
        if len(series) < period_days * 2:
            return None

        seconds_per_period = period_days * 24 * 3600
        buckets: Dict[int, List[int]] = defaultdict(list)

        for ts, v in series:
            bucket = int((ts % seconds_per_period) / seconds_per_period * period_days)
            buckets[bucket].append(v)

        if not buckets:
            return None

        return {
            f"period_{k}": sum(vals) / len(vals)
            for k, vals in buckets.items()
        }


class AnomalyScorer:
    """时序异常检测器 — 识别漏洞数量的异常突增，预警零日漏洞爆发。

    使用改进 Z-Score（Median Absolute Deviation）替代经典 Z-Score，
    对离群值更鲁棒，不会被前一次爆发拉升的均值/MAD 掩盖后续爆发。
    """

    @staticmethod
    def _median(values: List[float]) -> float:
        """安全中位数计算 — 不对原始列表排序以避免副作用。"""
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        m = len(sorted_vals)
        if m % 2 == 1:
            return sorted_vals[m // 2]
        return (sorted_vals[m // 2 - 1] + sorted_vals[m // 2]) / 2.0

    @staticmethod
    def score(series: List[float], window: int = 14) -> float:
        """计算时序的异常评分。

        基于滑动窗口的 Modified Z-Score (MAD-based)：
        - 对每个点计算其相对于窗口内分布的偏离度
        - 取最近 window 个点的最大 Modified Z-Score 作为整体异常评分
        - Modified Z-Score > 3.5 视为异常（对应经典 Z-Score 约 > 3.0）
        """
        n = len(series)
        if n < window:
            if n < 3:
                return 0.0
            window = n

        mad_constant = 0.6745  # MAD → 标准差的一致性常数（正态假设）
        max_modified_z = 0.0

        for i in range(max(window, n - window * 2), n):
            # 取当前点之前的 window 个值作为基线
            win_start = max(0, i - window)
            win_vals = series[win_start:i]
            if len(win_vals) < 3:
                continue

            win_median = AnomalyScorer._median(win_vals)
            # MAD = median(|x_i - median|)
            abs_devs = sorted(abs(x - win_median) for x in win_vals)
            mad = AnomalyScorer._median(abs_devs)

            if mad < 1e-9:
                # 零方差窗口 — 任何非零偏离都算异常
                modified_z = abs(series[i] - win_median) / max(1e-6, win_median)
            else:
                modified_z = mad_constant * abs(series[i] - win_median) / mad

            if modified_z > max_modified_z:
                max_modified_z = modified_z

        # 归一化到 [0, 1] 区间 — Modified Z=3.5 映射到 ~0.7, Z=6 → ~0.95
        return min(1.0, max_modified_z / 7.0)


class VulnTrendForecaster:
    """Main vulnerability trend forecasting engine."""

    def __init__(self) -> None:
        self.store = VulnHistoryStore()
        self.forecaster = TimeSeriesForecaster()
        self.seasonal = SeasonalPatternDetector()
        self.anomaly_scorer = AnomalyScorer()

    def record(self, tp: VulnTimePoint) -> None:
        """Record a vulnerability data point."""
        self.store.add(tp)

    def record_batch(self, points: List[VulnTimePoint]) -> None:
        """Record multiple data points."""
        self.store.add_batch(points)

    def analyze(
        self,
        binary_id: str,
        method: TrendMethod = TrendMethod.MOVING_AVG,
        horizon: int = 7,
    ) -> TrendAnalysis:
        """Analyze vulnerability trends for a binary."""
        history = self.store.get(binary_id)

        if not history:
            return TrendAnalysis(
                binary_id=binary_id,
                history=[],
                forecast=Forecast(
                    binary_id=binary_id,
                    method=method,
                    horizon=horizon,
                    predicted_count=0.0,
                    confidence_low=0.0,
                    confidence_high=0.0,
                ),
                detected_trend="no_data",
            )

        # Aggregate by day
        daily: Dict[int, int] = defaultdict(int)
        for h in history:
            day = int(h.timestamp // 86400)
            daily[day] += h.count

        sorted_days = sorted(daily.items())
        series = [v for _, v in sorted_days]
        ts_series = [(float(k) * 86400, v) for k, v in sorted_days]

        pred, lo, hi = self.forecaster.forecast(series, horizon, method)

        # Predict distribution of vuln types
        type_counter = Counter(h.vuln_type for h in history)
        total = sum(type_counter.values()) or 1
        pred_types = [
            (t, c / total * max(1.0, pred))
            for t, c in type_counter.most_common(5)
        ]

        # Detect trend direction
        if len(series) >= 2:
            recent = sum(series[-3:]) / min(3, len(series))
            earlier = sum(series[:3]) / min(3, len(series))
            if recent > earlier * 1.2:
                trend = "increasing"
            elif recent < earlier * 0.8:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "stable"

        seasonality = self.seasonal.detect(ts_series)

        # 异常评分 - 检测漏洞爆发信号
        anomaly = self.anomaly_scorer.score(series) if len(series) >= 7 else 0.0

        # 回测评估 - 对比所有方法的预测精度
        backtest_metrics = None
        if len(series) >= 10:
            backtest_metrics = TimeSeriesForecaster.evaluate_methods(series)

        return TrendAnalysis(
            binary_id=binary_id,
            history=history,
            forecast=Forecast(
                binary_id=binary_id,
                method=method,
                horizon=horizon,
                predicted_count=round(pred, 2),
                confidence_low=round(lo, 2),
                confidence_high=round(hi, 2),
                predicted_types=pred_types,
            ),
            seasonality=seasonality,
            detected_trend=trend,
            anomaly_score=anomaly,
            backtest_metrics=backtest_metrics,
            metadata={
                'sample_count': len(series),
                'date_range_start': history[0].timestamp if history else 0,
                'date_range_end': history[-1].timestamp if history else 0,
            },
        )

    def compare_binaries(
        self,
        binary_ids: List[str],
        method: TrendMethod = TrendMethod.MOVING_AVG,
    ) -> Dict[str, TrendAnalysis]:
        """Compare trends across multiple binaries."""
        return {
            bid: self.analyze(bid, method=method)
            for bid in binary_ids
        }


def forecast_vuln_trend(
    binary_id: str,
    method: str = "moving_avg",
    horizon: int = 7,
) -> Dict[str, Any]:
    """Convenience function for vulnerability trend forecasting."""
    try:
        m = TrendMethod(method)
    except ValueError:
        m = TrendMethod.MOVING_AVG

    forecaster = VulnTrendForecaster()
    result = forecaster.analyze(binary_id, method=m, horizon=horizon)

    return {
        'success': True,
        'binary_id': result.binary_id,
        'detected_trend': result.detected_trend,
        'anomaly_score': round(result.anomaly_score, 4),
        'forecast': {
            'method': result.forecast.method.value,
            'horizon': result.forecast.horizon,
            'predicted_count': result.forecast.predicted_count,
            'confidence_low': result.forecast.confidence_low,
            'confidence_high': result.forecast.confidence_high,
            'predicted_types': [
                {'type': t, 'predicted': p}
                for t, p in result.forecast.predicted_types
            ],
        },
        'seasonality': result.seasonality,
        'history_count': len(result.history),
        'backtest_metrics': (
            [m.to_dict() for m in result.backtest_metrics]
            if result.backtest_metrics else None
        ),
    }
