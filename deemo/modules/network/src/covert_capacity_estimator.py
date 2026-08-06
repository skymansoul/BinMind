# 创建: 2026-08-11  修改: 2026-08-13 (修正SNR估计: 噪声功率改用信号/可分辨级数而非var/std比)
# 时序隐蔽信道容量估计 —— 从观测IAT分布推断理论最大信息速率。
#
# 现有covert_channel_detector和wavelet_covert_detector回答"是否存在
# 隐蔽信道"(二分类检测)。本模块回答"若存在, 其理论容量上限是多少",
# 用于风险评估优先级排序。
#
# 方法: 基于信息论的隐蔽信道容量公式:
#   C = max_{p(x)} I(X;Y) = max_{p(x)} [H(Y) - H(Y|X)]
#   其中X=发送方编码符号, Y=接收方观测IAT。
#
# 对常见时序信道类型的容量估计:
#   1. JitterBug: 微小IAT抖动编码→C≈log₂(可区分抖动级数)/T_bit
#   2. 开关信道(On/Off): 有/无包编码→C≈1/T_window (1 bit/window)
#   3. IPD(包间延迟): IAT值分箱编码→C≈log₂(n_bins)/T_pkt
#   4. 速率调制: 包速率编码→C≈log₂(n_rates)/T_window
#
# 估计器输入: 观测IAT序列→噪声模型→信道容量上界。
# 容量的实际可达性取决于接收方的解码能力和噪声水平。
#
# 未见2024-2025文献涉及时序信道容量自动化估计用于风险排序。

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CapacityEstimate:
    """单种信道类型的容量估计"""
    channel_type: str          # "jitterbug"/"on_off"/"ipd"/"rate_mod"
    estimated_capacity_bps: float  # bits/sec
    noise_floor_bps: float     # 噪声导致的容量损失
    effective_capacity_bps: float  # 有效容量 = est - noise
    signal_bins: int           # 可区分信号级数
    risk_level: str            # "critical"/"high"/"medium"/"low"
    assumptions: str = ""


@dataclass
class CovertCapacityReport:
    """隐蔽信道容量完整报告"""
    total_iat_samples: int
    observation_duration_s: float
    mean_iat_ms: float
    max_capacity_bps: float       # 所有信道类型的最大容量
    channel_estimates: List[CapacityEstimate]
    overall_risk: str
    # 外泄风险评估
    exfil_mb_per_hour: float      # 最坏情况: MB/小时
    recommendation: str = ""


class CovertCapacityEstimator:
    """时序隐蔽信道容量估计器。

    基于观测IAT序列的统计特征, 估计不同类型隐蔽信道的
    理论最大容量。噪声水平从IAT抖动自动估计。
    """

    def __init__(self):
        pass

    def estimate(self, iats: List[float]) -> CovertCapacityReport:
        """从IAT序列估计各类隐蔽信道容量。"""
        n = len(iats)
        if n < 10:
            return CovertCapacityReport(
                total_iat_samples=n,
                observation_duration_s=0.0, mean_iat_ms=0.0,
                max_capacity_bps=0.0, channel_estimates=[],
                overall_risk="low", exfil_mb_per_hour=0.0)

        total_time = sum(iats)
        mean_iat = total_time / n
        mean_iat_ms = mean_iat * 1000.0
        # IAT抖动(标准差)
        var_iat = sum((x - mean_iat) ** 2 for x in iats) / n
        std_iat = math.sqrt(var_iat)

        estimates: List[CapacityEstimate] = []

        # 1. JitterBug: 微小抖动编码
        # 可区分级数 ≈ IAT范围 / 最小可分辨抖动(≈噪声std)
        jitter_range = max(iats) - min(iats)
        jitter_levels = max(2, int(jitter_range / max(std_iat, 1e-9)))
        # 每包携带log₂(levels) bit, 包速率 = 1/mean_iat
        jitter_capacity = math.log2(jitter_levels) / max(mean_iat, 1e-9)
        # 噪声损失: 信号=抖动范围/可分辨级数, 噪声=标准差
        signal_power = (jitter_range / max(jitter_levels, 2)) ** 2
        noise_power = max(std_iat ** 2, 1e-12)
        snr = signal_power / noise_power if noise_power > 0 else 10.0
        noise_loss = jitter_capacity * max(0.0, 1.0 - min(snr / 10.0, 1.0))
        estimates.append(CapacityEstimate(
            channel_type="jitterbug",
            estimated_capacity_bps=round(jitter_capacity, 4),
            noise_floor_bps=round(noise_loss, 4),
            effective_capacity_bps=round(jitter_capacity - noise_loss, 4),
            signal_bins=jitter_levels,
            risk_level=self._risk(jitter_capacity - noise_loss),
            assumptions=f"{jitter_levels}抖动级数, SNR≈{snr:.1f}",
        ))

        # 2. 开关信道(On/Off): 包存在/不存在编码
        # 时间窗 = 2×mean_iat (Nyquist采样)
        window_s = max(mean_iat * 2, 0.001)
        on_off_capacity = 1.0 / window_s
        estimates.append(CapacityEstimate(
            channel_type="on_off",
            estimated_capacity_bps=round(on_off_capacity, 4),
            noise_floor_bps=0.0,
            effective_capacity_bps=round(on_off_capacity, 4),
            signal_bins=2,
            risk_level=self._risk(on_off_capacity),
            assumptions=f"窗口={window_s*1000:.1f}ms",
        ))

        # 3. IPD(包间延迟): IAT值直接编码
        # 可区分延迟级数: 基于人类反应时间下限(~1ms)和观测抖动
        min_resolvable = max(std_iat, 0.001)
        iat_range = max(iats) - min(iats)
        ipd_levels = max(2, int(iat_range / min_resolvable))
        ipd_capacity = math.log2(ipd_levels) / max(mean_iat, 1e-9)
        estimates.append(CapacityEstimate(
            channel_type="ipd",
            estimated_capacity_bps=round(ipd_capacity, 4),
            noise_floor_bps=round(ipd_capacity * 0.3, 4),
            effective_capacity_bps=round(ipd_capacity * 0.7, 4),
            signal_bins=ipd_levels,
            risk_level=self._risk(ipd_capacity * 0.7),
            assumptions=f"{ipd_levels}可区分延迟级",
        ))

        # 4. 速率调制: 包速率编码
        pkt_rate = n / max(total_time, 1e-9)
        rate_levels = max(2, min(16, int(pkt_rate / 2.0)))
        rate_capacity = math.log2(rate_levels) / max(mean_iat * 5, 1e-9)
        estimates.append(CapacityEstimate(
            channel_type="rate_mod",
            estimated_capacity_bps=round(rate_capacity, 4),
            noise_floor_bps=round(rate_capacity * 0.2, 4),
            effective_capacity_bps=round(rate_capacity * 0.8, 4),
            signal_bins=rate_levels,
            risk_level=self._risk(rate_capacity * 0.8),
            assumptions=f"包速率={pkt_rate:.1f}/s, {rate_levels}级",
        ))

        max_cap = max(e.effective_capacity_bps for e in estimates)
        exfil_mbph = max_cap * 3600 / (8 * 1024 * 1024)

        if max_cap > 100:
            overall = "critical"
            rec = "高容量隐蔽信道——建议立即隔离并排查"
        elif max_cap > 10:
            overall = "high"
            rec = "中等容量信道——建议加强监控和速率限制"
        else:
            overall = "low"
            rec = "低容量或无可利用信道"

        return CovertCapacityReport(
            total_iat_samples=n,
            observation_duration_s=round(total_time, 4),
            mean_iat_ms=round(mean_iat_ms, 3),
            max_capacity_bps=round(max_cap, 4),
            channel_estimates=estimates,
            overall_risk=overall,
            exfil_mb_per_hour=round(exfil_mbph, 6),
            recommendation=rec,
        )

    @staticmethod
    def _risk(capacity_bps: float) -> str:
        if capacity_bps > 100:
            return "critical"
        elif capacity_bps > 10:
            return "high"
        elif capacity_bps > 1:
            return "medium"
        return "low"


def estimate_covert_capacity(iats: List[float]) -> CovertCapacityReport:
    """便捷入口: IAT序列→隐蔽信道容量估计→CovertCapacityReport。"""
    return CovertCapacityEstimator().estimate(iats)


__all__ = [
    "CapacityEstimate", "CovertCapacityReport",
    "CovertCapacityEstimator", "estimate_covert_capacity",
]
