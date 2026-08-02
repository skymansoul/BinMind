# 2026-08-04

"""覆盖率异常检测 -- 识别模糊测试中非预期的覆盖行为。

参考:
  EcoFuzz (USENIX 2020)     -- 覆盖增长停滞检测, 自适应状态切换
  AFL++ CmpLog               -- 比较日志插桩, 发现接近但未翻转的比较指令
  FuzzBench 指标体系         -- 覆盖曲线形状异常作为 fuzzer 失效信号
  统计过程控制 (SPC) 理论    -- 控制图/CUSUM 用于变化点检测

应用场景:
  1. 覆盖增长突然停止 (可能: 目标已完全覆盖或 fuzzer 陷入局部最优)
  2. 覆盖逆增长 (可能: 非确定性执行 / ASLR 干扰 / fuzzer bug)
  3. 边覆盖分布偏移 (可能: 新变异策略改变探索方向)
  4. 单一边异常高频 (可能: 无限循环 / 路径爆炸)
"""

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AnomalyAlert:
    """一条异常告警。"""
    alert_type: str              # stagnation / regression / skew / hotspot / frequency_spike
    severity: str                # info / warning / critical
    description: str
    detected_at: float
    current_value: float
    expected_value: float
    deviation_sigma: float       # 偏离期望值的标准差倍数


class CoverageAnomalyDetector:
    """多维度覆盖异常检测器。

    检测维度:
      1. 增长停滞 (Growth Stagnation)
      2. 覆盖逆增长 (Coverage Regression)
      3. 覆盖分布偏移 (Distribution Shift)
      4. 单边热点 (Edge Hotspot)
    """

    def __init__(self, history_size: int = 60,
                 stagnation_threshold: int = 10,
                 regression_sigma: float = 3.0):
        """
        history_size: 保留最近多少个周期的覆盖数据
        stagnation_threshold: 连续多少周期无增长即报警
        regression_sigma: 偏离预期值多少σ即报警
        """
        self.history_size = history_size
        self.stagnation_threshold = stagnation_threshold
        self.regression_sigma = regression_sigma

        # 时序列
        self._edge_counts: deque = deque(maxlen=history_size)
        self._timestamps: deque = deque(maxlen=history_size)
        self._edge_freq: Dict[int, int] = defaultdict(int)
        self._stagnation_counter: int = 0
        self._last_alert_time: float = 0.0
        self._alert_cooldown: float = 60.0  # 两次同类告警的最短间隔(秒)
        self._alerts: List[AnomalyAlert] = []

    def record(self, edges_covered: int,
               edge_freqs: Optional[Dict[int, int]] = None) -> List[AnomalyAlert]:
        """记录一个周期的覆盖数据, 返回本轮检测到的异常告警。"""
        now = time.time()
        self._edge_counts.append(edges_covered)
        self._timestamps.append(now)

        new_alerts: List[AnomalyAlert] = []

        # 检测1: 增长停滞
        alert = self._check_stagnation(edges_covered, now)
        if alert:
            new_alerts.append(alert)

        # 检测2: 逆增长
        alert = self._check_regression(edges_covered, now)
        if alert:
            new_alerts.append(alert)

        # 检测3: 边缘覆盖频次异常 (如果提供了 edge_freqs)
        if edge_freqs:
            alert = self._check_hotspot(edge_freqs, now)
            if alert:
                new_alerts.append(alert)

        self._alerts.extend(new_alerts)
        return new_alerts

    def _check_stagnation(self, current: int, now: float) -> Optional[AnomalyAlert]:
        if len(self._edge_counts) < 5:
            return None

        # 与上一周期的差值
        prev = list(self._edge_counts)[-2] if len(self._edge_counts) >= 2 else current
        if current <= prev:
            self._stagnation_counter += 1
        else:
            self._stagnation_counter = 0

        if self._stagnation_counter >= self.stagnation_threshold:
            if now - self._last_alert_time > self._alert_cooldown:
                self._last_alert_time = now
                return AnomalyAlert(
                    alert_type="stagnation",
                    severity="warning",
                    description=f"覆盖率连续{self._stagnation_counter}周期无增长",
                    detected_at=now,
                    current_value=float(current),
                    expected_value=float(prev),
                    deviation_sigma=0.0,
                )

        return None

    def _check_regression(self, current: int, now: float) -> Optional[AnomalyAlert]:
        if len(self._edge_counts) < 10:
            return None

        values = list(self._edge_counts)
        recent = values[-5:]
        older = values[-10:-5]

        mean_older = sum(older) / max(1, len(older))
        std_older = self._stddev(older)

        if std_older <= 0:
            return None

        mean_recent = sum(recent) / max(1, len(recent))
        z_score = (mean_recent - mean_older) / std_older

        # 覆盖显著下降 (>3σ)
        if z_score < -self.regression_sigma:
            return AnomalyAlert(
                alert_type="regression",
                severity="critical",
                description=f"覆盖可能退化: 近期均值{mean_recent:.0f} vs 早期{mean_older:.0f} (z={z_score:.1f}σ)",
                detected_at=now,
                current_value=mean_recent,
                expected_value=mean_older,
                deviation_sigma=abs(z_score),
            )

        return None

    def _check_hotspot(self, edge_freqs: Dict[int, int],
                       now: float) -> Optional[AnomalyAlert]:
        """检测异常高频边 (可能是无限循环导致的路径爆炸)。"""
        if not edge_freqs:
            return None

        # 计算频率阈值: mean + 5*stddev
        counts = list(edge_freqs.values())
        if len(counts) < 3:
            return None

        avg = sum(counts) / len(counts)
        std = self._stddev(counts)
        threshold = avg + 5 * std

        hotspots = [(eid, cnt) for eid, cnt in edge_freqs.items() if cnt > threshold]
        if hotspots:
            top = sorted(hotspots, key=lambda x: x[1], reverse=True)[:3]
            return AnomalyAlert(
                alert_type="hotspot",
                severity="info",
                description=f"异常高频边: {[(hex(e), c) for e, c in top]}",
                detected_at=now,
                current_value=float(top[0][1]),
                expected_value=avg,
                deviation_sigma=(top[0][1] - avg) / max(1, std),
            )

        return None

    def _stddev(self, values: List) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    def get_alerts(self, alert_type: Optional[str] = None) -> List[AnomalyAlert]:
        if alert_type:
            return [a for a in self._alerts if a.alert_type == alert_type]
        return list(self._alerts)

    def recent_alerts(self, count: int = 10) -> List[AnomalyAlert]:
        return sorted(self._alerts, key=lambda a: a.detected_at, reverse=True)[:count]


# ===== CUSUM 变化点检测 =====

class CUSUMDetector:
    """累积和控制图 (CUSUM) — 检测覆盖增长率的微妙变化点。

    比简单的滑动窗口更早检测到增长减速, 用于提前触发策略切换。
    """

    def __init__(self, target_mean: float = 0.0,
                 k_slack: float = 0.5,
                 h_threshold: float = 5.0):
        """
        target_mean: 期望的每周期新边数
        k_slack: 允许的松弛量 (降低误报)
        h_threshold: CUSUM 报警阈值
        """
        self.target = target_mean
        self.k = k_slack
        self.h = h_threshold
        self._c_pos: float = 0.0   # 向上累积
        self._c_neg: float = 0.0   # 向下累积
        self._n: int = 0

    def update(self, value: float) -> Tuple[bool, str]:
        """喂入一个新样本值, 返回 (是否检测到变化点, 方向)。"""
        if self._n == 0:
            self.target = value
        self._n += 1

        self._c_pos = max(0.0, self._c_pos + (value - self.target) - self.k)
        self._c_neg = max(0.0, self._c_neg + (self.target - value) - self.k)

        # 指数加权更新目标均值
        self.target = 0.95 * self.target + 0.05 * value

        if self._c_pos > self.h:
            self._c_pos = 0.0
            return True, "up"
        if self._c_neg > self.h:
            self._c_neg = 0.0
            return True, "down"

        return False, "stable"

    def reset(self) -> None:
        self._c_pos = 0.0
        self._c_neg = 0.0
        self._n = 0
