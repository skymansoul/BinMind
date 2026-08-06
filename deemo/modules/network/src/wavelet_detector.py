# 小波包隐蔽信道检测器 —— 多分辨率频率域异常检测。
#
# 检测策略: IAT序列→DWPT→提取能量分布特征→与正常1/f分布比较→
# 异常子带能量集中处标识为潜在隐蔽信道。
#
# 1/f分布(粉红噪声): 第k子带能量 ∝ 1/k。
# 偏离正常分布的KL散度≥阈值触发告警。
#
# 子带能量异常→信道类型推断:
#   - 高频子带(HH*, HL*): JitterBug类微小抖动调制
#   - 中频子带: TRCTC类流量时序重放
#   - 低频聚集(非1/f): Model-Based类统计伪装

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from .wavelet_covert_detector import (
    CovertChannelScore, WaveletDecomposition, WaveletPacketDecomposer,
)


class WaveletCovertDetector:
    """小波包隐蔽信道检测器。

    需先通过calibrate_baseline()用正常流量建立基线,
    否则使用理论1/f分布作为参考分布。

    检测阈值kl_threshold控制灵敏度:
      - 0.10: 高灵敏度, 适合初始扫描
      - 0.15: 平衡(默认), 假阳性率可控
      - 0.25: 低灵敏度, 仅报告高置信度异常
    """

    _CHANNEL_PATTERNS = {
        "jitterbug": {"bands": "high", "desc": "高频子带能量异常(JitterBug时钟抖动)"},
        "trctc": {"bands": "mid", "desc": "中频子带能量异常(时序重放)"},
        "model_based": {"bands": "low", "desc": "低频能量偏离1/f(模型伪装)"},
        "generic_timing": {"bands": "any", "desc": "通用时序信道(非特定频带)"},
    }

    def __init__(self, decomposer: Optional[WaveletPacketDecomposer] = None,
                 kl_threshold: float = 0.15):
        self._decomposer = decomposer or WaveletPacketDecomposer()
        self._kl_threshold = kl_threshold
        self._baseline: Optional[List[float]] = None

    def calibrate_baseline(self, normal_iat_samples: List[List[float]]) -> None:
        """用正常流量样本校准基线能量分布。

        normal_iat_samples: 多个正常会话的IAT序列列表。
        基线=所有样本在各子带的平均能量分布。
        """
        if not normal_iat_samples:
            return
        all_dists: List[List[float]] = []
        for iats in normal_iat_samples:
            if len(iats) < 4:
                continue
            decomp = self._decomposer.decompose(iats)
            if decomp.energy_distribution:
                all_dists.append(decomp.energy_distribution)

        if not all_dists:
            return

        n_bands = len(all_dists[0])
        self._baseline = [
            sum(d[i] for d in all_dists) / len(all_dists)
            for i in range(n_bands)
        ]

    def detect(self, iat_sequence: List[float]) -> CovertChannelScore:
        """对单个IAT序列做小波隐蔽信道检测。

        返回CovertChannelScore含检测类型和小波异常得分。
        IAT长度<4时返回空得分(不足以做DWPT分解)。
        """
        if len(iat_sequence) < 4:
            return CovertChannelScore()

        decomp = self._decomposer.decompose(iat_sequence)
        if not decomp.energy_distribution:
            return CovertChannelScore()

        dist = decomp.energy_distribution

        if self._baseline is None or len(self._baseline) != len(dist):
            reference = self._synthetic_1f_distribution(len(dist))
        else:
            reference = self._baseline

        kl_div = self._kl_divergence(dist, reference)
        wavelet_score = 1.0 / (1.0 + math.exp(
            -(kl_div - self._kl_threshold) * 10))

        dominant_band, channel_type = self._identify_anomalous_band(
            dist, reference, decomp)

        details: List[Dict[str, Any]] = []
        last_level = decomp.max_level
        for sb in decomp.subbands:
            if sb.level == last_level and sb.energy_ratio > 0.01:
                ref_val = reference[sb.index] if sb.index < len(reference) else 0.0
                details.append({
                    "band": f"L{last_level}_{sb.index}",
                    "energy_ratio": round(sb.energy_ratio, 5),
                    "expected": round(ref_val, 5),
                    "deviation": round(sb.energy_ratio - ref_val, 5),
                })

        return CovertChannelScore(
            channel_type=channel_type,
            wavelet_score=round(wavelet_score, 4),
            dominant_frequency_band=dominant_band,
            energy_deviation=round(kl_div, 4),
            subband_details=sorted(details,
                                   key=lambda d: abs(d["deviation"]),
                                   reverse=True)[:5],
        )

    @staticmethod
    def _synthetic_1f_distribution(n_bands: int) -> List[float]:
        weights = [1.0 / (k + 1) for k in range(n_bands)]
        total = sum(weights)
        return [w / total for w in weights]

    @staticmethod
    def _kl_divergence(p: List[float], q: List[float]) -> float:
        """对称KL散度: D_KL(P||Q) + D_KL(Q||P)"""
        kl_pq, kl_qp = 0.0, 0.0
        eps = 1e-12
        for pi, qi in zip(p, q):
            pi_safe = max(pi, eps)
            qi_safe = max(qi, eps)
            kl_pq += pi_safe * math.log2(pi_safe / qi_safe)
            kl_qp += qi_safe * math.log2(qi_safe / pi_safe)
        return (kl_pq + kl_qp) / 2.0

    def _identify_anomalous_band(self, dist: List[float],
                                  reference: List[float],
                                  decomp: WaveletDecomposition
                                  ) -> Tuple[str, str]:
        if not dist:
            return "none", ""

        deviations = [
            (i, dist[i] - reference[i] if i < len(reference) else 0.0)
            for i in range(len(dist))
        ]
        max_dev = max(deviations, key=lambda x: abs(x[1]))

        n = len(dist)
        band_pos = max_dev[0]
        if band_pos < n // 3:
            band_label, ch_type = "low", "model_based"
        elif band_pos < 2 * n // 3:
            band_label, ch_type = "mid", "trctc"
        else:
            band_label, ch_type = "high", "jitterbug"

        dominant = f"L{decomp.max_level}_B{band_pos}_{band_label}"
        return dominant, ch_type


def detect_covert_timing_wavelet(iat_sequence: List[float],
                                  baseline_samples: Optional[List[List[float]]] = None
                                  ) -> CovertChannelScore:
    """便捷入口: IAT序列→小波隐蔽信道检测。

    baseline_samples: 可选正常流量基线(未提供则使用理论1/f分布)。
    """
    detector = WaveletCovertDetector()
    if baseline_samples:
        detector.calibrate_baseline(baseline_samples)
    return detector.detect(iat_sequence)


__all__ = ["WaveletCovertDetector", "detect_covert_timing_wavelet"]
