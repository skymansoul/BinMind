"""时序隐蔽信道检测器 —— 分析包间到达时间(IAT)的统计异常。

检测原理：IAT分布的熵 + 抖动比 + 自相关。
"""
import math
from statistics import mean, stdev
from typing import List

from ._covert_types import (
    CovertChannelAlert,
    _IAT_JITTER_COVERT,
    _AUTOCORR_THRESHOLD,
)


class TimingChannelDetector:
    @staticmethod
    def shannon_entropy(values: List[float], bins: int = 20) -> float:
        if not values:
            return 0.0
        vm, vx = min(values), max(values)
        if vm == vx:
            return 0.0
        bw = (vx - vm) / bins
        hist = [0] * bins
        for v in values:
            idx = min(int((v - vm) / bw), bins - 1)
            hist[idx] += 1
        n = len(values)
        return -sum((h / n) * math.log2(h / n) for h in hist if h > 0)

    @staticmethod
    def autocorrelation(seq: List[float], lag: int = 1) -> float:
        n = len(seq)
        if n <= lag + 2:
            return 0.0
        m = mean(seq)
        num = sum((seq[i] - m) * (seq[i + lag] - m) for i in range(n - lag))
        den = sum((x - m) ** 2 for x in seq)
        return num / den if den > 1e-9 else 0.0

    def detect(self, iat_sequence: List[float], packet_count: int) -> List[CovertChannelAlert]:
        """分析IAT序列，返回时序信道告警列表"""
        alerts = []
        n = len(iat_sequence)
        if n < 8:
            return alerts

        # 抖动比
        try:
            m = mean(iat_sequence)
            s = stdev(iat_sequence)
            jitter = s / m if m > 0 else 0.0
        except Exception:
            jitter = 0.0

        # 自相关
        ac1 = self.autocorrelation(iat_sequence, 1)
        ac2 = self.autocorrelation(iat_sequence, 2)

        # IAT熵
        iat_entropy = self.shannon_entropy(iat_sequence)

        confidence = 0.0
        reasons = []

        if jitter < _IAT_JITTER_COVERT and n >= 10:
            confidence += 0.4
            reasons.append(f"IAT抖动比={jitter:.4f} —— 极度规律")

        if abs(ac1) > _AUTOCORR_THRESHOLD:
            confidence += 0.3
            reasons.append(f"IAT自相关(1)={ac1:.3f}")

        if iat_entropy < 1.5 and n >= 15:
            confidence += 0.3
            reasons.append(f"IAT熵={iat_entropy:.2f} bits —— 分布集中")

        if confidence >= 0.5:
            alerts.append(CovertChannelAlert(
                channel_type="timing",
                description="; ".join(reasons),
                severity="high" if confidence >= 0.7 else "medium",
                confidence=min(confidence, 1.0),
                evidence={
                    "iat_jitter": round(jitter, 5),
                    "autocorr_lag1": round(ac1, 4),
                    "autocorr_lag2": round(ac2, 4),
                    "iat_entropy": round(iat_entropy, 3),
                    "sample_count": n,
                },
            ))

        return alerts
