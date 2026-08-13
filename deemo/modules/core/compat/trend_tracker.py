# 趋势追踪 — 时间序列聚合、异常检测、预测、相关性分析
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# ===== 基础数据结构 =====
@dataclass
class TrendPoint:
    timestamp: float
    value: float
    label: str = ""
    metadata: dict = field(default_factory=dict)

@dataclass
class TrendData:
    name: str
    points: list[TrendPoint] = field(default_factory=list)
    unit: str = ""
    aggregation: str = "none"

class TrendDirection(Enum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"

class MovingAverageType(Enum):
    SIMPLE = "simple"
    EXPONENTIAL = "exponential"
    WEIGHTED = "weighted"

# ===== 趋势追踪器 =====
class TrendTracker:
    """时间序列数据采集、聚合、异常检测、预测"""

    def __init__(self, name: str = "", max_points: int = 1000):
        self.name = name
        self._points: list[TrendPoint] = []
        self._max_points = max_points
        self._lock = __import__('threading').Lock()

    # ---- 数据录入 ----
    def track(self, timestamp: float, value: float,
              label: Optional[str] = None,
              metadata: Optional[dict] = None) -> TrendPoint:
        pt = TrendPoint(timestamp=timestamp, value=value,
                        label=label or "", metadata=metadata or {})
        with self._lock:
            self._points.append(pt)
            if len(self._points) > self._max_points:
                self._points.pop(0)
        return pt

    def store_analysis_result(self, binary_path: str, binary_hash: str,
                              results: Optional[dict] = None) -> list[tuple[float, float]]:
        """记录一次分析结果，返回更新后的完整时序。"""
        self.track(
            time.time(), 1.0,
            label=binary_hash,
            metadata={'binary_path': binary_path, 'results': results or {}})
        return self.get_series()

    # 别名
    def add_data_point(self, timestamp: float, value: float,
                       label: Optional[str] = None,
                       metadata: Optional[dict] = None) -> TrendPoint:
        return self.track(timestamp, value, label, metadata)

    def record(self, value: float, label: Optional[str] = None,
               metadata: Optional[dict] = None) -> TrendPoint:
        return self.track(time.time(), value, label, metadata)

    # ---- 序列获取 ----
    def get_series(self) -> list[tuple[float, float]]:
        with self._lock:
            return [(p.timestamp, p.value) for p in self._points]

    def get_window(self, start_ts: float, end_ts: float) -> list[TrendPoint]:
        with self._lock:
            return [p for p in self._points if start_ts <= p.timestamp <= end_ts]

    # ---- 聚合 ----
    def aggregate(self, window: str = '1h') -> dict:
        """按时间窗口聚合：mean、min、max、std、count"""
        pts = list(self._points)
        if not pts:
            return {'count': 0}

        bucket_secs = {'1h': 3600, '1d': 86400, '1w': 604800}.get(window, 3600)
        buckets: dict[int, list[float]] = {}
        for p in pts:
            b = int(p.timestamp // bucket_secs) * bucket_secs
            buckets.setdefault(b, []).append(p.value)

        result = {}
        for bkey, vals in sorted(buckets.items()):
            n = len(vals)
            mean_v = sum(vals) / n
            result[bkey] = {
                'mean': mean_v,
                'min': min(vals),
                'max': max(vals),
                'std': math.sqrt(sum((v - mean_v) ** 2 for v in vals) / max(n - 1, 1)),
                'count': n,
            }
        return result

    # ---- 异常检测 ----
    def detect_anomalies(self, sigma: float = 2.0) -> list[TrendPoint]:
        """基于滚动均值/标准差检测异常点"""
        pts = list(self._points)
        if len(pts) < 3:
            return []

        window = min(len(pts) // 2, 20)
        window = max(window, 3)
        anomalies: list[TrendPoint] = []

        for i in range(window, len(pts)):
            chunk = pts[i - window:i]
            vals = [c.value for c in chunk]
            mean_v = sum(vals) / len(vals)
            var = sum((v - mean_v) ** 2 for v in vals) / max(len(vals) - 1, 1)
            std_v = math.sqrt(max(var, 1e-10))

            if abs(pts[i].value - mean_v) > sigma * std_v:
                anomalies.append(pts[i])

        return anomalies

    # ---- 预测 ----
    def forecast(self, steps: int = 10,
                 method: str = 'linear') -> list[tuple[float, float]]:
        """线性回归或 EMA 预测未来 steps 个点"""
        pts = list(self._points)
        if len(pts) < 2:
            return []

        if method == 'ema':
            return self._forecast_ema(pts, steps)
        return self._forecast_linear(pts, steps)

    def _forecast_linear(self, pts: list[TrendPoint], steps: int) -> list[tuple[float, float]]:
        """简单线性回归"""
        n = len(pts)
        xs = [i for i in range(n)]
        ys = [p.value for p in pts]

        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
        den = sum((x - mean_x) ** 2 for x in xs)
        slope = num / den if den != 0 else 0
        intercept = mean_y - slope * mean_x

        last_ts = pts[-1].timestamp
        avg_dt = (pts[-1].timestamp - pts[0].timestamp) / max(n - 1, 1)
        result = []
        for i in range(1, steps + 1):
            pred_ts = last_ts + avg_dt * i
            pred_val = intercept + slope * (n + i)
            result.append((pred_ts, pred_val))
        return result

    def _forecast_ema(self, pts: list[TrendPoint], steps: int,
                      alpha: float = 0.3) -> list[tuple[float, float]]:
        """EMA 预测: 最后一个平滑值外推"""
        vals = [p.value for p in pts]
        ema = vals[0]
        for v in vals[1:]:
            ema = alpha * v + (1 - alpha) * ema

        last_ts = pts[-1].timestamp
        avg_dt = (pts[-1].timestamp - pts[0].timestamp) / max(len(pts) - 1, 1)
        return [(last_ts + avg_dt * i, ema) for i in range(1, steps + 1)]

    # ---- 变化率 ----
    def compute_rate_of_change(self) -> list[float]:
        pts = list(self._points)
        if len(pts) < 2:
            return []
        deltas = []
        for i in range(1, len(pts)):
            dt = pts[i].timestamp - pts[i - 1].timestamp
            dv = pts[i].value - pts[i - 1].value
            deltas.append(dv / max(dt, 1))
        return deltas

    # ---- Holt-Winters 三重指数平滑 (季节性+趋势+水平) ----
    # Hyndman & Athanasopoulos (2018) "Forecasting: Principles and Practice" Ch.7
    # 乘法季节性模型适用于安全事件数据 — 漏洞数量在季度安全审计周期中呈乘法波动
    def holt_winters_forecast(self, steps: int = 10, period: int = 7,
                               alpha: float = 0.3, beta: float = 0.1,
                               gamma: float = 0.1) -> list[tuple[float, float]]:
        pts = list(self._points)
        vals = [p.value for p in pts]
        n = len(vals)
        if n < 2 * period:
            return self.forecast(steps, 'linear')

        # 初始化季节因子
        seasonal = [1.0] * period
        for i in range(period):
            chunk = [vals[j] for j in range(i, n, period) if j < n]
            if chunk:
                seasonal[i] = sum(chunk) / len(chunk) / (sum(vals[:period]) / period) if sum(vals[:period]) else 1.0

        level = sum(vals[:period]) / period
        trend = (sum(vals[period:2*period]) - sum(vals[:period])) / (period * period) if n >= 2*period else 0.0
        smoothed_level = level
        smoothed_trend = trend
        smoothed_seasonal = list(seasonal)

        for t in range(n):
            if t >= period and smoothed_level > 0:
                seasonal[t % period] = gamma * (vals[t] / max(smoothed_level, 1e-10)) + (1 - gamma) * seasonal[t % period]
            new_level = alpha * (vals[t] / max(seasonal[t % period], 1e-10)) + (1 - alpha) * (smoothed_level + smoothed_trend)
            smoothed_trend = beta * (new_level - smoothed_level) + (1 - beta) * smoothed_trend
            smoothed_level = new_level

        last_ts = pts[-1].timestamp
        avg_dt = (pts[-1].timestamp - pts[0].timestamp) / max(n - 1, 1)
        result = []
        for i in range(1, steps + 1):
            pred = (smoothed_level + i * smoothed_trend) * seasonal[(n + i - 1) % period]
            result.append((last_ts + avg_dt * i, max(0.0, pred)))
        return result


# ===== 方向检测 =====
def _detect_direction(points: list[TrendPoint]) -> TrendDirection:
    """线性回归斜率符号 + 变异系数判断波动"""
    if len(points) < 2:
        return TrendDirection.STABLE

    xs = list(range(len(points)))
    ys = [p.value for p in points]
    n = len(points)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    den = sum((x - mean_x) ** 2 for x in xs)
    slope = num / den if den != 0 else 0
    cv = math.sqrt(sum((y - mean_y) ** 2 for y in ys) / n) / max(abs(mean_y), 1e-10)

    if cv > 0.5:
        return TrendDirection.VOLATILE
    if slope > 0.01:
        return TrendDirection.INCREASING
    if slope < -0.01:
        return TrendDirection.DECREASING
    return TrendDirection.STABLE

# ===== 时间序列聚合器 =====
class TimeSeriesAggregator:
    @staticmethod
    def aggregate_hourly(series: list[tuple[float, float]]) -> dict:
        return TimeSeriesAggregator._bucket_by_timestamp(series, 3600)

    @staticmethod
    def aggregate_daily(series: list[tuple[float, float]]) -> dict:
        return TimeSeriesAggregator._bucket_by_timestamp(series, 86400)

    @staticmethod
    def aggregate_weekly(series: list[tuple[float, float]]) -> dict:
        return TimeSeriesAggregator._bucket_by_timestamp(series, 604800)

    @staticmethod
    def _bucket_by_timestamp(series: list[tuple[float, float]],
                              bucket_seconds: int) -> dict:
        buckets: dict[int, list[float]] = {}
        for ts, val in series:
            b = int(ts // bucket_seconds) * bucket_seconds
            buckets.setdefault(b, []).append(val)

        result = {}
        for bkey, vals in sorted(buckets.items()):
            result[bkey] = {
                'sum': sum(vals),
                'mean': sum(vals) / len(vals),
                'count': len(vals),
                'min': min(vals),
                'max': max(vals),
            }
        return result

# ===== 移动平均 =====
def compute_moving_average(series: list[float], window: int = 7,
                           ma_type: MovingAverageType = MovingAverageType.SIMPLE) -> list[float]:
    if len(series) < window:
        return []

    if ma_type == MovingAverageType.EXPONENTIAL:
        alpha = 2.0 / (window + 1)
        result = [series[0]]
        for v in series[1:]:
            result.append(alpha * v + (1 - alpha) * result[-1])
        return result

    if ma_type == MovingAverageType.WEIGHTED:
        result = []
        denom = sum(range(1, window + 1))
        for i in range(window - 1, len(series)):
            chunk = series[i - window + 1:i + 1]
            wsum = sum((j + 1) * chunk[j] for j in range(window))
            result.append(wsum / denom)
        return result

    # SIMPLE
    result = []
    for i in range(window - 1, len(series)):
        result.append(sum(series[i - window + 1:i + 1]) / window)
    return result

# ===== 相关性分析 =====
class CorrelationAnalyzer:
    @staticmethod
    def pearson_correlation(series1: list[float], series2: list[float]) -> float:
        n = min(len(series1), len(series2))
        if n < 2:
            return 0.0

        mean1 = sum(series1[:n]) / n
        mean2 = sum(series2[:n]) / n
        num = sum((series1[i] - mean1) * (series2[i] - mean2) for i in range(n))
        den1 = math.sqrt(sum((x - mean1) ** 2 for x in series1[:n]))
        den2 = math.sqrt(sum((x - mean2) ** 2 for x in series2[:n]))
        den = den1 * den2
        return num / den if den != 0 else 0.0

    @staticmethod
    def detect_correlation(series_dict: dict[str, list[float]]) -> list[tuple[str, str, float]]:
        """检测多序列间的 Pearson 相关性"""
        names = list(series_dict.keys())
        if len(names) < 2:
            return []

        pairs = []
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                corr = CorrelationAnalyzer.pearson_correlation(
                    series_dict[names[i]], series_dict[names[j]])
                pairs.append((names[i], names[j], corr))

        return sorted(pairs, key=lambda x: -abs(x[2]))

# ===== 趋势报告生成 =====
class TrendReport:
    @staticmethod
    def generate_summary(tracker: TrendTracker) -> dict:
        pts = list(tracker._points)
        if not pts:
            return {'name': tracker.name, 'count': 0}

        vals = [p.value for p in pts]
        direction = _detect_direction(pts)
        anomalies = tracker.detect_anomalies()
        forecast_pts = tracker.forecast(steps=5)

        return {
            'name': tracker.name,
            'point_count': len(pts),
            'time_range': (pts[0].timestamp, pts[-1].timestamp),
            'mean': sum(vals) / len(vals),
            'min': min(vals),
            'max': max(vals),
            'std': math.sqrt(sum((v - sum(vals)/len(vals))**2 for v in vals) / max(len(vals)-1, 1)),
            'direction': direction.value,
            'anomaly_count': len(anomalies),
            'forecast': [{'timestamp': ts, 'value': v} for ts, v in forecast_pts],
        }
