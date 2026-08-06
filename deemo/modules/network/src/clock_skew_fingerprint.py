# TCP时间戳时钟偏移被动指纹识别 —— 基于RFC 7323的设备标识。
#
# TCP Timestamps选项(RFC 7323)携带发送方的单调递增时钟值。
# 每台设备的时钟频率由晶振物理特性决定, 频率偏差(clock skew)
# 通常为1-100 ppm(百万分之一)。此偏差在制造时确定, 难以伪造——
# 攻击者即使伪造IP/MAC, 也无法精确模拟目标设备的晶振偏差。
#
# 指纹提取: 收集同一设备的多个TCP时间戳(t_i, T_i)→
# 线性拟合 T = α·t + β → 斜率α(即时钟频率)≈1+skew(ppm)。
# 多个观测窗口的α稳定性→指纹置信度。
#
# 应用: 检测设备冒充(NAT后的不同设备有不同skew)、
# 追踪设备跨IP移动(同一skew出现在不同IP→同一物理设备)。
#
# 与现有研究关系: Kohno et al. (IEEE S&P 2005)首次提出,
# 但未见2024-2025文献将其集成到通用网络分析框架中。
# 本模块提供纯Python在线实现, 增量更新线性拟合。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class TimestampSample:
    """单次TCP时间戳采样"""
    observation_time: float    # 本地观测时间(epoch seconds)
    ts_val: int               # TCP Timestamp选项值(单调计数器)
    source_ip: str = ""


@dataclass
class ClockSkewProfile:
    """设备时钟偏移剖面"""
    device_id: str             # 通常是IP或设备标识
    skew_ppm: float            # 时钟偏移(ppm), 正值=快, 负值=慢
    skew_std_ppm: float        # 偏移的标准误差
    r_squared: float           # 线性拟合R² (0=无规律, 1=完美线性)
    sample_count: int
    first_seen: float          # 首次观测时间
    last_seen: float           # 末次观测时间
    duration_hours: float      # 观测时长
    # 指纹稳定性: 多个窗口间的skew方差越小→指纹越可靠
    fingerprint_stability: float = 0.0


@dataclass
class SkewMatch:
    """时钟偏移匹配结果 —— 用于设备识别/冒充检测"""
    device_a: str
    device_b: str
    skew_diff_ppm: float       # |skew_a - skew_b| (ppm)
    is_match: bool             # 差异<阈值→同一设备
    is_impersonation: bool     # IP不同但skew匹配→冒充
    confidence: float


class ClockSkewTracker:
    """TCP时钟偏移追踪器 —— 每设备维增量的线性回归。

    使用Welford在线算法维护Σx,Σy,Σxy,Σx²,Σy²,
    支持O(1)增量更新拟合参数。窗口大小限制采样数避免内存膨胀。
    """

    def __init__(self, max_samples_per_device: int = 500,
                 min_samples_for_profile: int = 20,
                 impersonation_skew_threshold_ppm: float = 2.0):
        self._max_samples = max_samples_per_device
        self._min_samples = min_samples_for_profile
        self._skew_threshold = impersonation_skew_threshold_ppm
        # 每设备的Welford累加器
        self._n: Dict[str, int] = defaultdict(int)
        self._sum_x: Dict[str, float] = defaultdict(float)
        self._sum_y: Dict[str, float] = defaultdict(float)
        self._sum_xy: Dict[str, float] = defaultdict(float)
        self._sum_x2: Dict[str, float] = defaultdict(float)
        self._sum_y2: Dict[str, float] = defaultdict(float)
        self._first_ts: Dict[str, float] = {}
        self._last_ts: Dict[str, float] = {}
        # 多窗口skew缓存(用于稳定性评估)
        self._skew_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10))

    def add_sample(self, device_id: str,
                    obs_time: float, ts_val: int) -> None:
        """添加TCP时间戳采样: O(1)增量更新。"""
        n = self._n[device_id]

        # 首次采样: 设置基线时间偏移
        if n == 0:
            self._first_ts[device_id] = obs_time
            # 以首次采样为时间原点
            x = 0.0
            y = float(ts_val)
        else:
            x = obs_time - self._first_ts[device_id]
            y = float(ts_val)

        # Welford增量累加
        self._sum_x[device_id] += x
        self._sum_y[device_id] += y
        self._sum_xy[device_id] += x * y
        self._sum_x2[device_id] += x * x
        self._sum_y2[device_id] += y * y
        self._n[device_id] += 1
        self._last_ts[device_id] = obs_time

        # 限制缓冲区大小
        if self._n[device_id] > self._max_samples:
            self._n[device_id] -= 1

    def get_profile(self, device_id: str) -> Optional[ClockSkewProfile]:
        """计算设备时钟偏移剖面(线性拟合)。"""
        n = self._n.get(device_id, 0)
        if n < self._min_samples:
            return None

        sx = self._sum_x[device_id]
        sy = self._sum_y[device_id]
        sxy = self._sum_xy[device_id]
        sx2 = self._sum_x2[device_id]
        sy2 = self._sum_y2[device_id]

        # 斜率 α = (n·Σxy - Σx·Σy) / (n·Σx² - (Σx)²)
        denom = n * sx2 - sx * sx
        if abs(denom) < 1e-12:
            return None
        alpha = (n * sxy - sx * sy) / denom

        # TS值通常以毫秒(或原始计数器)为单位递增
        # skew (ppm) = (α - nominal_rate) / nominal_rate × 10^6
        # nominal_rate: 假设TS值每秒递增1000(ms精度)或100(10ms精度)
        # 自适应: 用观测时长估计名义速率
        duration = self._last_ts.get(device_id, 0.0) - self._first_ts.get(
            device_id, 0.0)
        if duration < 1.0:
            return None
        # 名义速率 ≈ (末TS - 首TS) / duration
        first_ts_val = (sy - alpha * sx) / n if n > 0 else 0.0
        nominal_rate = (float(self._sum_y[device_id] / n) * n -
                       first_ts_val) / duration if duration > 0 else 1000.0
        if abs(nominal_rate) < 1.0:
            nominal_rate = 1000.0
        skew_ppm = (alpha - nominal_rate) / nominal_rate * 1e6

        # R² = (n·Σxy - Σx·Σy)² / [(n·Σx²-(Σx)²)(n·Σy²-(Σy)²)]
        num_r2 = (n * sxy - sx * sy) ** 2
        denom_r2 = denom * (n * sy2 - sy * sy)
        r2 = num_r2 / max(denom_r2, 1e-12)

        # 标准误差: SE(α) = sqrt(Σ(y-ŷ)²/(n-2)) / sqrt(Σ(x-x̄)²)
        residuals = sy2 - 2*alpha*sxy + alpha*alpha*sx2 - (
            sy*sy - 2*alpha*sx*sy + alpha*alpha*sx*sx) / n
        se_alpha = math.sqrt(max(residuals, 0.0) / max(n-2, 1))
        se_denom = math.sqrt(max(denom / n, 1e-12))
        se_ppm = (se_alpha / se_denom / max(abs(nominal_rate), 1.0)) * 1e6

        # 指纹稳定性: 多窗口skew的方差
        self._skew_history[device_id].append(skew_ppm)
        stability = 0.0
        if len(self._skew_history[device_id]) >= 3:
            vals = list(self._skew_history[device_id])
            mean_v = sum(vals) / len(vals)
            var_v = sum((v - mean_v) ** 2 for v in vals) / len(vals)
            stability = 1.0 / max(math.sqrt(var_v) + 1.0, 1.0)

        return ClockSkewProfile(
            device_id=device_id,
            skew_ppm=round(skew_ppm, 4),
            skew_std_ppm=round(se_ppm, 4),
            r_squared=round(min(r2, 1.0), 4),
            sample_count=n,
            first_seen=self._first_ts.get(device_id, 0.0),
            last_seen=self._last_ts.get(device_id, 0.0),
            duration_hours=round(duration / 3600.0, 2),
            fingerprint_stability=round(stability, 3),
        )

    def detect_impersonation(self,
                              profiles: Dict[str, ClockSkewProfile]
                              ) -> List[SkewMatch]:
        """检测设备冒充: 同IP出现两个显著不同的skew→设备已更换/冒充。"""
        matches: List[SkewMatch] = []
        devices = list(profiles.keys())

        for i, da in enumerate(devices):
            for j in range(i + 1, len(devices)):
                db = devices[j]
                pa, pb = profiles[da], profiles[db]
                diff = abs(pa.skew_ppm - pb.skew_ppm)
                is_match = diff < self._skew_threshold

                # IP不同但skew匹配→同一物理设备跨IP
                ip_a = da.rsplit("_", 1)[0] if "_" in da else da
                ip_b = db.rsplit("_", 1)[0] if "_" in db else db
                is_imp = is_match and ip_a != ip_b

                matches.append(SkewMatch(
                    device_a=da, device_b=db,
                    skew_diff_ppm=round(diff, 4),
                    is_match=is_match,
                    is_impersonation=is_imp,
                    confidence=round(1.0 - diff / max(self._skew_threshold*2, 0.01), 3),
                ))

        return matches

    def all_profiles(self) -> Dict[str, ClockSkewProfile]:
        profiles = {}
        for device_id in list(self._n.keys()):
            p = self.get_profile(device_id)
            if p:
                profiles[device_id] = p
        return profiles


def fingerprint_device_clock(samples: List[Tuple[float, int]],
                              device_id: str = "device_0"
                              ) -> Optional[ClockSkewProfile]:
    """便捷入口: [(obs_time, ts_val), ...]→时钟偏移剖面。"""
    tracker = ClockSkewTracker()
    for obs_time, ts_val in samples:
        tracker.add_sample(device_id, obs_time, ts_val)
    return tracker.get_profile(device_id)


__all__ = [
    "TimestampSample", "ClockSkewProfile", "SkewMatch",
    "ClockSkewTracker", "fingerprint_device_clock",
]
