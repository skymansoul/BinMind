# 创建: 2026-06-19  修改: 2026-08-14 (增加多变量协方差追踪MCUSUM, 从独立维度升级为联合分布漂移检测)
# 网络设备行为漂移检测器 —— 独立CUSUM+多变量协方差MCUSUM联合判定。
#
# 网络设备(服务器/IoT/工控)在正常运行中维持稳定的行为剖面:
# 通信对端集合、端口使用模式、流量对称性、协议偏好。
# 当设备被入侵、固件变更或身份冒充时, 行为剖面发生漂移。
#
# CUSUM(Cumulative Sum)序贯检验: 对每个行为维度的观测值计算
# 累积偏差和 S_t = max(0, S_{t-1} + x_t - μ_0 - k)。
# 当S_t超过阈值H时触发漂移告警。
# 相比EWMA阈值: CUSUM对渐进漂移更敏感, 对瞬时尖峰更鲁棒。
#
# 多维度融合: 5个行为维度独立追踪CUSUM, 多数维度触发→
# 综合漂移告警。单维度触发→记录为疑似。
#
# 未见2024-2025文献涉及CUSUM多维度行为漂移用于网络设备安全。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class DeviceProfile:
    """设备行为剖面 —— 基线期的统计特征"""
    device_id: str
    # 维度1: 通信对端多样性(每窗口唯一IP数)
    peer_diversity_mean: float = 0.0
    peer_diversity_std: float = 0.0
    # 维度2: 端口使用熵(目的端口分布)
    port_entropy_mean: float = 0.0
    port_entropy_std: float = 0.0
    # 维度3: 流量不对称比(出/入)
    asymmetry_mean: float = 0.0
    asymmetry_std: float = 0.0
    # 维度4: 平均包长
    pkt_size_mean: float = 0.0
    pkt_size_std: float = 0.0
    # 维度5: 新对端出现率(每窗口新增IP比例)
    new_peer_rate_mean: float = 0.0
    new_peer_rate_std: float = 0.0
    baseline_windows: int = 0


@dataclass
class CusumTracker:
    """单维度的CUSUM追踪器"""
    dimension: str
    s_high: float = 0.0       # 上偏累积和(值异常变大)
    s_low: float = 0.0        # 下偏累积和(值异常变小)
    reference_mean: float = 0.0  # μ_0 基线均值
    k: float = 0.5            # 允许偏差(σ的倍数)
    h: float = 5.0            # 告警阈值(σ的倍数)
    triggered: bool = False
    trigger_direction: str = ""  # "high"/"low"/""


@dataclass
class DriftAlert:
    """行为漂移告警"""
    device_id: str
    window_index: int
    triggered_dimensions: List[str]
    drift_severity: float     # [0,1] 触发维度比例
    dimension_details: Dict[str, float] = field(default_factory=dict)
    # {dim: cusum_value}
    description: str = ""


class BehavioralDriftDetector:
    """CUSUM多维度行为漂移检测器。

    基线期(min_baseline_windows个窗口)收集统计特征;
    检测期每窗口计算各维度值→更新CUSUM→多数维度触发时告警。
    """

    def __init__(self, min_baseline_windows: int = 10,
                 cusum_k: float = 0.5,
                 cusum_h: float = 5.0,
                 trigger_ratio: float = 0.4):
        self._min_baseline = min_baseline_windows
        self._k = cusum_k
        self._h = cusum_h
        self._trigger_ratio = trigger_ratio
        self._profiles: Dict[str, DeviceProfile] = {}
        self._trackers: Dict[str, Dict[str, CusumTracker]] = {}
        self._baseline_data: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list))
        self._window_idx: Dict[str, int] = defaultdict(int)
        self._alerts: List[DriftAlert] = []
        # MCUSUM: 多变量协方差追踪
        self._cov_baseline: Dict[str, Dict] = {}  # {device: {mean, inv_cov}}
        self._mcusum: Dict[str, float] = defaultdict(float)

    def feed_window(self, device_id: str,
                    peer_diversity: float,
                    port_entropy: float,
                    asymmetry: float,
                    avg_pkt_size: float,
                    new_peer_rate: float) -> Optional[DriftAlert]:
        """每窗口调用 —— 输入设备的5维度观测值, 返回漂移告警或None。"""
        w = self._window_idx[device_id]
        self._window_idx[device_id] = w + 1

        dims = {
            "peer_diversity": peer_diversity,
            "port_entropy": port_entropy,
            "asymmetry": asymmetry,
            "pkt_size": avg_pkt_size,
            "new_peer_rate": new_peer_rate,
        }

        # 基线期: 缓存数据
        if w < self._min_baseline:
            for dim, val in dims.items():
                self._baseline_data[device_id][dim].append(val)
            if w == self._min_baseline - 1:
                self._finalize_baseline(device_id)
            return None

        # 确保基线已就绪
        if device_id not in self._profiles:
            return None

        # 检测期: 更新CUSUM并检查告警
        profile = self._profiles[device_id]
        triggered: List[str] = []
        dim_details: Dict[str, float] = {}

        for dim, val in dims.items():
            tracker = self._trackers[device_id][dim]
            mean_ref = tracker.reference_mean
            std_ref = getattr(profile, f"{dim}_std" if dim != "pkt_size"
                             else "pkt_size_std", 1.0)
            if std_ref < 1e-6:
                std_ref = abs(mean_ref) * 0.1 if abs(mean_ref) > 0 else 1.0

            # 标准化偏差
            z = (val - mean_ref) / std_ref
            k_scaled = self._k

            # CUSUM更新
            tracker.s_high = max(0.0, tracker.s_high + z - k_scaled)
            tracker.s_low = max(0.0, tracker.s_low - z - k_scaled)

            dim_details[dim] = max(tracker.s_high, tracker.s_low)

            h_scaled = self._h
            if tracker.s_high > h_scaled:
                tracker.triggered = True
                tracker.trigger_direction = "high"
                triggered.append(dim)
            elif tracker.s_low > h_scaled:
                tracker.triggered = True
                tracker.trigger_direction = "low"
                triggered.append(dim)

        # MCUSUM: 多变量Mahalanobis距离累积——即使单维度正常, 协方差结构变化也可检出
        mcusum_triggered = False
        if device_id in getattr(self, '_cov_baseline', {}):
            cov_data = self._cov_baseline[device_id]
            baseline_mean = cov_data['mean']      # 5维均值向量
            inv_cov = cov_data.get('inv_cov')     # 5×5逆协方差矩阵
            if inv_cov is not None:
                mcusum_val = self._mcusum.get(device_id, 0.0)
                vec = [dims[d] for d in ['peer_diversity', 'port_entropy',
                        'asymmetry', 'pkt_size', 'new_peer_rate']]
                diff = [vec[i] - baseline_mean[i] for i in range(5)]
                mahal_sq = sum(diff[i] * sum(inv_cov[i][j] * diff[j]
                               for j in range(5)) for i in range(5))
                mahal = math.sqrt(max(mahal_sq, 0.0))
                mcusum_val = max(0.0, mcusum_val + mahal - 1.5)
                self._mcusum[device_id] = mcusum_val
                if mcusum_val > 6.0:
                    mcusum_triggered = True
                    if 'covariance' not in triggered:
                        triggered.append('covariance')
                    dim_details['covariance'] = mcusum_val

        n_triggered = len(triggered)
        if n_triggered >= max(1, int(len(dims) * self._trigger_ratio)) or mcusum_triggered:
            severity = max(n_triggered / len(dims), 0.4)
            desc = (f"设备{device_id}: {n_triggered}/5维度漂移"
                   f"({', '.join(triggered)})")
            if mcusum_triggered:
                desc += f"; 协方差漂移(MCUSUM={mcusum_val:.1f})"
            alert = DriftAlert(
                device_id=device_id, window_index=w,
                triggered_dimensions=triggered,
                drift_severity=round(severity, 2),
                dimension_details=dim_details,
                description=desc,
            )
            self._alerts.append(alert)
            return alert

        return None

    def _finalize_baseline(self, device_id: str) -> None:
        data = self._baseline_data[device_id]
        profile = DeviceProfile(device_id=device_id,
                                baseline_windows=self._min_baseline)
        trackers: Dict[str, CusumTracker] = {}
        for dim in ['peer_diversity', 'port_entropy', 'asymmetry', 'pkt_size', 'new_peer_rate']:
            vals = data.get(dim, [0.0])
            n = len(vals)
            mean_v = sum(vals) / n if n > 0 else 0.0
            var_v = sum((x - mean_v) ** 2 for x in vals) / n if n > 0 else 1.0
            setattr(profile, f"{dim}_mean", mean_v)
            setattr(profile, f"{dim}_std", math.sqrt(max(var_v, 1e-6)))
            trackers[dim] = CusumTracker(dimension=dim, reference_mean=mean_v,
                                         k=self._k, h=self._h)
        self._profiles[device_id] = profile
        self._trackers[device_id] = trackers
        # 5维协方差+逆(MCUSUM)
        if self._min_baseline >= 5:
            dims_m = ['peer_diversity', 'port_entropy', 'asymmetry', 'pkt_size', 'new_peer_rate']
            means = [getattr(profile, f'{d}_mean') for d in dims_m]
            obs = [[data[dim][w] for w in range(self._min_baseline)] for dim in dims_m]
            cov = [[sum((obs[i][w]-means[i])*(obs[j][w]-means[j])
                       for w in range(self._min_baseline))/(self._min_baseline-1)
                   for j in range(5)] for i in range(5)]
            self._cov_baseline[device_id] = {'mean': means, 'cov': cov,
                                              'inv_cov': self._invert_5x5(cov)}

    @staticmethod
    def _invert_5x5(a: List[List[float]]) -> Optional[List[List[float]]]:
        """5x5 Gauss-Jordan求逆, 奇异返回None。"""
        n = 5
        aug = [[a[i][j] if j < n else (1.0 if i == j - n else 0.0)
                for j in range(2 * n)] for i in range(n)]
        for col in range(n):
            pivot = max(range(col, n), key=lambda r: abs(aug[r][col]))
            if abs(aug[pivot][col]) < 1e-10:
                return None
            aug[col], aug[pivot] = aug[pivot], aug[col]
            piv_val = aug[col][col]
            for j in range(2 * n):
                aug[col][j] /= piv_val
            for row in range(n):
                if row != col:
                    f = aug[row][col]
                    for j in range(2 * n):
                        aug[row][j] -= f * aug[col][j]
        return [[aug[i][j + n] for j in range(n)] for i in range(n)]

    def summary(self) -> Dict[str, Any]:
        return {
            "devices_monitored": len(self._profiles),
            "total_alerts": len(self._alerts),
            "by_device": {a.device_id: a.description
                         for a in self._alerts[-10:]},
            "mean_severity": (sum(a.drift_severity for a in self._alerts) /
                             max(len(self._alerts), 1)),
        }

    def get_profile(self, device_id: str) -> Optional[DeviceProfile]:
        return self._profiles.get(device_id)


def detect_device_behavioral_drift(
    device_windows: Dict[str, List[Dict[str, float]]]
) -> List[DriftAlert]:
    """便捷入口: {设备ID→[窗口观测值]}→CUSUM漂移检测→告警列表。

    device_windows[device_id] = [
        {"peer_diversity": 5.0, "port_entropy": 2.1, "asymmetry": 1.5,
         "avg_pkt_size": 512.0, "new_peer_rate": 0.1},
        ...
    ]
    """
    detector = BehavioralDriftDetector()
    alerts: List[DriftAlert] = []
    for device_id, windows in device_windows.items():
        for w in windows:
            alert = detector.feed_window(
                device_id,
                w.get("peer_diversity", 0.0),
                w.get("port_entropy", 0.0),
                w.get("asymmetry", 0.0),
                w.get("avg_pkt_size", 0.0),
                w.get("new_peer_rate", 0.0),
            )
            if alert:
                alerts.append(alert)
    return alerts


__all__ = [
    "DeviceProfile", "CusumTracker", "DriftAlert",
    "BehavioralDriftDetector", "detect_device_behavioral_drift",
]
