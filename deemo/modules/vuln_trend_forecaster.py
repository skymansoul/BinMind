"""
跨项目漏洞趋势预测模块

功能:
    1. 利用时间序列分析历史漏洞数据, 预测特定二进制或软件未来可能出现的漏洞类型和数量
    2. 辅助安全资源规划

核心技术:
    - 时间序列: 简单指数平滑 / 移动平均 / 线性回归
    - 季节性检测 (简化)
    - 概率分布: 漏洞类型出现频率
    - 置信区间
"""

import logging
import os
import json
import time
import math
import sqlite3
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class TrendMethod(Enum):
    MOVING_AVG = "moving_avg"
    EXPONENTIAL = "exponential"
    LINEAR_REGRESSION = "linear_regression"
    NAIVE = "naive"


@dataclass
class VulnTimePoint:
    """时间点数据"""
    timestamp: float
    binary_id: str
    vuln_type: str
    severity: str
    count: int = 1


@dataclass
class Forecast:
    """预测结果"""
    binary_id: str
    method: TrendMethod
    horizon: int
    predicted_count: float
    confidence_low: float
    confidence_high: float
    predicted_types: List[Tuple[str, float]] = field(default_factory=list)
    notes: str = ""


@dataclass
class TrendAnalysis:
    """趋势分析结果"""
    binary_id: str
    history: List[VulnTimePoint]
    forecast: Forecast
    seasonality: Optional[Dict[str, float]] = None
    detected_trend: str = "stable"
    metadata: Dict[str, Any] = field(default_factory=dict)


class VulnHistoryStore:
    """漏洞历史存储"""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data',
                'vuln_trend_history.sqlite3'
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock, self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    binary_id TEXT,
                    vuln_type TEXT,
                    severity TEXT,
                    count INTEGER
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_history_binary "
                      "ON history(binary_id)")

    def add(self, tp: VulnTimePoint):
        with self._lock, self._conn() as c:
            c.execute("""
                INSERT INTO history (timestamp, binary_id, vuln_type, severity, count)
                VALUES (?,?,?,?,?)
            """, (tp.timestamp, tp.binary_id, tp.vuln_type,
                  tp.severity, tp.count))

    def get(self, binary_id: str,
            since_ts: Optional[float] = None) -> List[VulnTimePoint]:
        with self._lock, self._conn() as c:
            if since_ts is not None:
                cur = c.execute("""
                    SELECT timestamp, binary_id, vuln_type, severity, count
                    FROM history
                    WHERE binary_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                """, (binary_id, since_ts))
            else:
                cur = c.execute("""
                    SELECT timestamp, binary_id, vuln_type, severity, count
                    FROM history
                    WHERE binary_id = ?
                    ORDER BY timestamp ASC
                """, (binary_id))
            rows = cur.fetchall()
        return [
            VulnTimePoint(
                timestamp=r[0], binary_id=r[1], vuln_type=r[2],
                severity=r[3], count=r[4]
            )
            for r in rows
        ]


class TimeSeriesForecaster:
    """时间序列预测器"""

    def forecast(self, series: List[float], horizon: int = 1,
                 method: TrendMethod = TrendMethod.MOVING_AVG
                 ) -> Tuple[float, float, float]:
        """返回 (预测值, 下界, 上界)"""
        if not series:
            return 0.0, 0.0, 0.0
        if method == TrendMethod.MOVING_AVG:
            return self._moving_avg(series, horizon)
        elif method == TrendMethod.EXPONENTIAL:
            return self._exponential(series, horizon)
        elif method == TrendMethod.LINEAR_REGRESSION:
            return self._linear_regression(series, horizon)
        return self._naive(series, horizon)

    def _moving_avg(self, s: List[float], horizon: int) -> Tuple[float, float, float]:
        window = min(7, len(s))
        avg = sum(s[-window:]) / window
        var = sum((x - avg) ** 2 for x in s[-window:]) / max(1, window)
        std = math.sqrt(max(0.0, var))
        return avg, max(0, avg - 1.96 * std), avg + 1.96 * std

    def _exponential(self, s: List[float], horizon: int,
                     alpha: float = 0.3) -> Tuple[float, float, float]:
        if not s:
            return 0.0, 0.0, 0.0
        forecast = s[0]
        for v in s[1:]:
            forecast = alpha * v + (1 - alpha) * forecast
        var = sum((x - forecast) ** 2 for x in s) / max(1, len(s))
        std = math.sqrt(max(0.0, var))
        return forecast, max(0, forecast - 1.96 * std), forecast + 1.96 * std

    def _linear_regression(self, s: List[float],
                           horizon: int) -> Tuple[float, float, float]:
        n = len(s)
        if n < 2:
            return s[0] if s else 0.0, 0.0, s[0] if s else 0.0
        x_mean = (n - 1) / 2.0
        y_mean = sum(s) / n
        num = sum((i - x_mean) * (s[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n)) or 1.0
        slope = num / den
        intercept = y_mean - slope * x_mean
        y_pred = intercept + slope * (n - 1 + horizon)
        # 残差
        residuals = [s[i] - (intercept + slope * i) for i in range(n)]
        std = math.sqrt(sum(r ** 2 for r in residuals) / max(1, n))
        return max(0, y_pred), max(0, y_pred - 1.96 * std), y_pred + 1.96 * std

    def _naive(self, s: List[float], horizon: int) -> Tuple[float, float, float]:
        return s[-1], max(0, s[-1] * 0.5), s[-1] * 1.5


class SeasonalPatternDetector:
    """季节性检测"""

    def detect(self, series: List[Tuple[float, int]],
               period_days: int = 30) -> Optional[Dict[str, float]]:
        if len(series) < period_days * 2:
            return None
        # 按月份聚合
        buckets: Dict[int, List[int]] = defaultdict(list)
        for ts, v in series:
            month = int((ts % (365 * 24 * 3600)) / (30 * 24 * 3600))
            buckets[month].append(v)
        if not buckets:
            return None
        return {f"month_{m}": sum(v) / len(v)
                for m, v in buckets.items()}


class VulnTrendForecaster:
    """漏洞趋势预测器"""

    def __init__(self):
        self.store = VulnHistoryStore()
        self.forecaster = TimeSeriesForecaster()
        self.seasonal = SeasonalPatternDetector()

    def record(self, tp: VulnTimePoint):
        self.store.add(tp)

    def analyze(self, binary_id: str,
                method: TrendMethod = TrendMethod.MOVING_AVG,
                horizon: int = 7) -> TrendAnalysis:
        history = self.store.get(binary_id)
        # 按天聚合 count
        daily: Dict[str, int] = defaultdict(int)
        for h in history:
            day = int(h.timestamp // 86400)
            daily[day] += h.count
        if not daily:
            return TrendAnalysis(
                binary_id=binary_id, history=history,
                forecast=Forecast(
                    binary_id=binary_id, method=method, horizon=horizon,
                    predicted_count=0, confidence_low=0, confidence_high=0
                ),
                detected_trend="no_data"
            )
        sorted_days = sorted(daily.items())
        series = [v for _, v in sorted_days]
        ts_series = [(float(k) * 86400, v) for k, v in sorted_days]
        # 预测
        pred, lo, hi = self.forecaster.forecast(series, horizon, method)
        # 类型频率
        type_counter: Counter = Counter(h.vuln_type for h in history)
        total = sum(type_counter.values()) or 1
        pred_types = [
            (t, c / total * max(1.0, pred)) for t, c in type_counter.most_common(5)
        ]
        # 趋势方向
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
        return TrendAnalysis(
            binary_id=binary_id, history=history,
            forecast=Forecast(
                binary_id=binary_id, method=method, horizon=horizon,
                predicted_count=round(pred, 2),
                confidence_low=round(lo, 2),
                confidence_high=round(hi, 2),
                predicted_types=pred_types
            ),
            seasonality=seasonality,
            detected_trend=trend,
            metadata={'sample_count': len(series)}
        )


def forecast_vuln_trend(binary_id: str, method: str = "moving_avg",
                        horizon: int = 7) -> Dict[str, Any]:
    """便捷入口"""
    try:
        m = TrendMethod(method)
    except ValueError:
        m = TrendMethod.MOVING_AVG
    f = VulnTrendForecaster()
    result = f.analyze(binary_id, method=m, horizon=horizon)
    return {
        'success': True,
        'binary_id': result.binary_id,
        'detected_trend': result.detected_trend,
        'forecast': {
            'method': result.forecast.method.value,
            'horizon': result.forecast.horizon,
            'predicted_count': result.forecast.predicted_count,
            'confidence_low': result.forecast.confidence_low,
            'confidence_high': result.forecast.confidence_high,
            'predicted_types': [
                {'type': t, 'predicted': p}
                for t, p in result.forecast.predicted_types
            ]
        },
        'seasonality': result.seasonality,
        'history_count': len(result.history)
    }
