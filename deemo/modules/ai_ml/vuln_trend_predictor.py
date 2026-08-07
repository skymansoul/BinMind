"""
Vulnerability Trend Predictor - Time-series forecasting for CVE/disclosure data.

Simple moving-average-based trend prediction for vulnerability types
across time periods, with risk alerts and rising trend detection.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class VulnTrend:
    """A single vulnerability trend line."""

    __slots__ = (
        'vuln_type', 'period', 'historical_counts',
        'predicted_next', 'trend_direction', 'confidence',
        'anomaly_flags',          # 异常标记 — indices where anomalous counts appear
        'trend_strength',         # 趋势强度 — absolute slope magnitude
        'mean_count',             # 均值 — for baseline comparison
    )

    def __init__(
        self,
        vuln_type: str,
        period: str = "weekly",
        historical_counts: Optional[List[int]] = None,
        predicted_next: int = 0,
        trend_direction: str = "stable",
        confidence: float = 0.0,
        anomaly_flags: Optional[List[int]] = None,
        trend_strength: float = 0.0,
        mean_count: float = 0.0,
    ) -> None:
        self.vuln_type = vuln_type
        self.period = period
        self.historical_counts = historical_counts or []
        self.predicted_next = predicted_next
        self.trend_direction = trend_direction
        self.confidence = confidence
        self.anomaly_flags = anomaly_flags or []
        self.trend_strength = trend_strength
        self.mean_count = mean_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_type': self.vuln_type,
            'period': self.period,
            'historical': self.historical_counts[-12:],
            'predicted_next': self.predicted_next,
            'trend': self.trend_direction,
            'confidence': self.confidence,
            'anomaly_count': len(self.anomaly_flags),
            'trend_strength': round(self.trend_strength, 3),
            'mean_count': round(self.mean_count, 1),
            'total_observations': len(self.historical_counts),
        }


class VulnTrendPredictor:
    """Predicts vulnerability trends using moving average and direction analysis."""

    def __init__(self) -> None:
        self._history: Dict[str, List[int]] = defaultdict(list)
        self._metadata: Dict[str, Dict[str, Any]] = {}

    def add_data_point(
        self,
        vuln_type: str,
        count: int,
        period: str = "weekly",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a data point to the predictor.

        Args:
            vuln_type: Vulnerability type or category.
            count: Occurrence count.
            period: Time period label (weekly, monthly, quarterly).
            metadata: Optional extra data.
        """
        key = f"{vuln_type}:{period}"
        self._history[key].append(count)
        if metadata:
            self._metadata[key] = metadata

    def simple_ma_forecast(
        self,
        counts: List[int],
        window: int = 4,
    ) -> Tuple[int, str, float]:
        """Simple moving average forecast with trend direction.

        Args:
            counts: Historical count series.
            window: Moving average window size.

        Returns:
            Tuple of (predicted_next, trend_direction, confidence).
        """
        if len(counts) < window:
            avg = sum(counts) // max(1, len(counts))
            return (avg, "stable", 0.3)

        recent = counts[-window:]
        predicted = sum(recent) // len(recent)

        # Compare halves for trend direction
        half = window // 2
        first_half_avg = sum(counts[-window:-half]) / max(1, half)
        second_half_avg = sum(counts[-half:]) / max(1, half)

        if second_half_avg > first_half_avg * 1.1:
            direction = "up"
        elif first_half_avg > second_half_avg * 1.1:
            direction = "down"
        else:
            direction = "stable"

        confidence = min(0.3 + len(counts) / 200.0, 0.85)

        return (predicted, direction, confidence)

    def exponential_forecast(
        self,
        counts: List[int],
        alpha: float = 0.3,
    ) -> Tuple[int, str, float]:
        """Exponential smoothing forecast.

        Args:
            counts: Historical count series.
            alpha: Smoothing factor (0-1).

        Returns:
            Tuple of (predicted_next, trend_direction, confidence).
        """
        if not counts:
            return (0, "stable", 0.0)

        forecast_val: float = counts[0]
        for v in counts[1:]:
            forecast_val = alpha * v + (1 - alpha) * forecast_val

        predicted = int(round(forecast_val))

        if len(counts) >= 2 and counts[-1] > counts[-2]:
            direction = "up"
        elif len(counts) >= 2 and counts[-1] < counts[-2]:
            direction = "down"
        else:
            direction = "stable"

        confidence = min(0.3 + len(counts) / 150.0, 0.8)
        return (predicted, direction, confidence)

# 增强功能 1: 异常点检测 (IQR-based 异常 检测)
    # 如果在历史数据中某个点偏离了四分位距的正常范围，标记为 异常
    # 这是为了发现突发漏洞爆发或数据采集异常
    def detect_anomalies(
        self,
        counts: List[int],
        multiplier: float = 1.5,
    ) -> List[int]:
        """Detect anomalous indices using inter-quartile range method.

        Returns list of indices into ``counts`` where the value lies beyond
        ``multiplier * IQR`` from Q1 or Q3. An empty list means no outliers.

        为什么用 IQR？
        比 z-score 更适合漏洞数据 —— 漏洞爆发通常是尖峰分布，IQR 对
        极端值更鲁棒，不会因为一两个爆发数据把整个标准差拉大。
        """
        if len(counts) < 4:
            return []

        sorted_counts = sorted(counts)
        n = len(sorted_counts)

        # Q1 和 Q3 的索引位置
        q1_idx = n // 4
        q3_idx = (3 * n) // 4

        q1 = sorted_counts[q1_idx]
        q3 = sorted_counts[q3_idx]
        iqr = q3 - q1

        if iqr == 0:
            return []

        lower = q1 - multiplier * iqr
        upper = q3 + multiplier * iqr

        anomalies: List[int] = []
        for i, v in enumerate(counts):
            if v < lower or v > upper:
                anomalies.append(i)

        return anomalies

    # ---- 增强功能 2: 趋势强度 (slope-based trend strength) ----
    # 用简单线性回归的斜率来衡量趋势的"劲度"，不是只看方向
    def compute_trend_strength(self, counts: List[int]) -> float:
        """Compute trend strength as the absolute slope of a simple linear
        regression over the historical counts.

        Returns a non-negative float. Larger values indicate a steeper trend
        (either upward or downward). Values near zero mean the series is flat.

        思路：最小二乘法求斜率 b = Σ((x - x̄)(y - ȳ)) / Σ((x - x̄)²)
        不关心正负号，只取绝对值，因为我们已经在方向判断里知道涨跌了。
        """
        n = len(counts)
        if n < 2:
            return 0.0

        mean_x = (n - 1) / 2.0
        mean_y = sum(counts) / n

        numerator = 0.0
        denominator = 0.0

        for i, y in enumerate(counts):
            dx = i - mean_x
            dy = y - mean_y
            numerator += dx * dy
            denominator += dx * dx

        if denominator == 0.0:
            return 0.0

        slope = numerator / denominator

        # 归一化：用均值做分母避免量纲影响跨类型比较
        # 如果 mean_y 接近 0，直接返回未归一化的斜率绝对值
        if abs(mean_y) < 1e-9:
            return abs(slope)

        normalized = abs(slope) / abs(mean_y)
        return normalized

    # ---- 增强功能 3: 预测方法可切换 (pluggable forecast method) ----
    # 允许 analyze() 通过 forecast_method 参数选择 MA 或指数平滑
    # 原先 exponential_forecast 是死代码，现在把它接入主流程
    def _dispatch_forecast(
        self,
        counts: List[int],
        method: str = "moving_average",
        **kwargs: Any,
    ) -> Tuple[int, str, float]:
        """Route to the correct forecasting implementation.

        Args:
            counts: Historical count series.
            method: One of 'moving_average' (default) or 'exponential'.
            **kwargs: Passed through to the forecasting function.

        Returns:
            Tuple of (predicted_next, trend_direction, confidence).
        """
        if method == "exponential":
            alpha = kwargs.get('alpha', kwargs.get('smoothing_factor', 0.3))
            return self.exponential_forecast(counts, alpha=alpha)
        else:
            window = kwargs.get('window', kwargs.get('ma_window', 4))
            return self.simple_ma_forecast(counts, window=window)

    def analyze(
        self,
        historical_data: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Analyze vulnerability trends.

        Args:
            historical_data: Optional list of data point dicts.
            **kwargs: Additional options.
                - forecast_method: 'moving_average' (default) or 'exponential'
                - ma_window: window size for moving average (default 4)
                - alpha: smoothing factor for exponential (default 0.3)
                - anomaly_multiplier: IQR multiplier for outlier detection (default 1.5)

        Returns:
            Analysis result dict.
        """
        forecast_method = kwargs.get('forecast_method', 'moving_average')
        anomaly_mult = kwargs.get('anomaly_multiplier', 1.5)

        if historical_data:
            for d in historical_data:
                self.add_data_point(
                    vuln_type=d.get('vuln_type', 'generic'),
                    count=d.get('count', d.get('nCount', 0)),
                    period=d.get('period', 'weekly'),
                    metadata=d.get('metadata'),
                )

        trends: List[VulnTrend] = []

        for key, counts in self._history.items():
            vuln_type, period = key.rsplit(':', 1)
            predicted, direction, confidence = self._dispatch_forecast(
                counts, method=forecast_method, **kwargs,
            )

            # 异常检测 & 趋势强度
            anomalies = self.detect_anomalies(counts, multiplier=anomaly_mult)
            strength = self.compute_trend_strength(counts)
            mean_val = sum(counts) / max(1, len(counts))

            trends.append(VulnTrend(
                vuln_type=vuln_type,
                period=period,
                historical_counts=list(counts),
                predicted_next=predicted,
                trend_direction=direction,
                confidence=round(confidence, 2),
                anomaly_flags=anomalies,
                trend_strength=strength,
                mean_count=mean_val,
            ))

        # Classify trends
        rising = [t for t in trends if t.trend_direction == "up"]
        falling = [t for t in trends if t.trend_direction == "down"]
        stable = [t for t in trends if t.trend_direction == "stable"]

        total_predicted = sum(t.predicted_next for t in trends)

        # 异常汇总 — 哪些类型在最近窗口里有异常点
        anomalous_trends = [
            t.to_dict() for t in trends
            if t.anomaly_flags and any(idx >= len(t.historical_counts) - 6 for idx in t.anomaly_flags)
        ]

        # Global trend
        if len(rising) > len(trends) * 0.3:
            global_trend = "rising"
        elif len(falling) > len(trends) * 0.3:
            global_trend = "declining"
        else:
            global_trend = "stable"

        # 取趋势强度最高的前几个作为重点关注
        top_strength = sorted(trends, key=lambda t: t.trend_strength, reverse=True)[:5]

        return {
            'success': True,
            'total_trends': len(trends),
            'trends': [t.to_dict() for t in trends[:20]],
            'rising_trends': [t.to_dict() for t in rising[:10]],
            'falling_trends': [t.to_dict() for t in falling[:10]],
            'predicted_total': total_predicted,
            'risk_alert': len(rising) > 3 or global_trend == "rising",
            'global_trend': global_trend,
            'forecast_method_used': forecast_method,
            # 新增字段：异常趋势 & 高强度趋势 — 便于下游做优先级排序
            'anomalous_trends': anomalous_trends[:10],
            'top_strength_trends': [t.to_dict() for t in top_strength],
            'summary': {
                'rising_count': len(rising),
                'falling_count': len(falling),
                'stable_count': len(stable),
                'anomalous_count': len(anomalous_trends),
                'max_trend_strength': round(
                    max((t.trend_strength for t in trends), default=0.0), 4,
                ),
            },
        }

    def get_trend(
        self,
        vuln_type: str,
        period: str = "weekly",
        forecast_method: str = "moving_average",
        **kwargs: Any,
    ) -> Optional[VulnTrend]:
        """Get trend for a specific vulnerability type.

        Args:
            vuln_type: Vulnerability type.
            period: Time period.
            forecast_method: 'moving_average' or 'exponential'.
            **kwargs: Passed to forecast function.

        Returns:
            VulnTrend or None if not found.
        """
        key = f"{vuln_type}:{period}"
        if key not in self._history:
            return None

        counts = self._history[key]
        predicted, direction, confidence = self._dispatch_forecast(
            counts, method=forecast_method, **kwargs,
        )

        anomalies = self.detect_anomalies(counts)
        strength = self.compute_trend_strength(counts)
        mean_val = sum(counts) / max(1, len(counts))

        return VulnTrend(
            vuln_type=vuln_type,
            period=period,
            historical_counts=list(counts),
            predicted_next=predicted,
            trend_direction=direction,
            confidence=round(confidence, 2),
            anomaly_flags=anomalies,
            trend_strength=strength,
            mean_count=mean_val,
        )

    def clear(self) -> None:
        """Clear all stored data."""
        self._history.clear()
        self._metadata.clear()


def predict_vuln_trends(
    historical_data: List[Dict[str, Any]],
    **kwargs: Any,
) -> Dict[str, Any]:
    """Convenience function for vulnerability trend prediction.

    Args:
        historical_data: List of dicts with vuln_type, count, period keys.
        **kwargs: Additional options (forecast_method, ma_window, alpha,
                  anomaly_multiplier).

    Returns:
        Prediction result dict.
    """
    predictor = VulnTrendPredictor()
    return predictor.analyze(historical_data=historical_data, **kwargs)
