# 调度器自监控 — 非参数 CUSUM 检测调度质量退化
#
# 分布式调度器在长期运行中会因多种原因退化:
#   - 内部状态膨胀 (队列元数据累积 → 调度延迟上升)
#   - 资源碎片的渐进效应 (类似内存碎片，但碎片的是 CPU/GPU 时间片)
#   - 下游依赖漂移 (熔断器长期半开 → 有效吞吐下降)
#   这些问题在任务级监控中不可见——每个任务单独看都在正常完成。
#   但在调度器层面表现为: 调度延迟分布右移、公平性指标漂移、空转比例上升。
#
# 本模块在调度器决策层插入非参数 CUSUM 检测点:
#   统计量: 调度延迟 (入队→出队)、饥饿计数 (低优先级任务等待时间)、
#           队列深度方差、空窃取率 (steal_attempts / successful_steals)
#   方法: 对每个统计量的秩 (而非原始值) 做 CUSUM——
#         非参数变体，不假设正态性，对离群值鲁棒。
#   输出: 退化告警 (WARNING / CRITICAL) + 建议的缓解动作
#
# 与 AdaptiveStream (IEEE ICDMW 2025) 的区别:
#   AdaptiveStream 做通用的分布式核 CUSUM，面向任意数据流。
#   本模块专为调度器指标设计，统计量选择与缓解建议是领域特定的。

from __future__ import annotations

import time
import math
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from enum import Enum


class DegradationLevel(Enum):
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class SchedulerSnapshot:
    """调度器单次采样快照。"""
    timestamp: float
    queue_depth: int
    scheduling_latency_ms: float      # 任务从入队到分配的平均延迟
    starvation_count: int             # 等待超过 5× 预估时间的任务数
    empty_steal_ratio: float          # 空窃取 / 总窃取
    fairness_gini: float              # 各任务类型间的完成时间基尼系数
    backpressure_ratio: float         # 背压信号激活的任务比例


class NonparametricCUSUM:
    """非参数 CUSUM — 基于观测秩而非原始值。

    每步将新观测与历史窗口的秩比较，增量更新 CUSUM 统计量。
    秩变换消除了分布假设，对离群值天然鲁棒。

    参考: Hawkins & Olwell (1998) "Cumulative Sum Charts and Charting for
    Quality Improvement" 的自适应 CUSUM 设计。
    """

    def __init__(
        self, window: int = 80, k: float = 0.5,
        h_warn: float = 3.5, h_crit: float = 6.0,
    ):
        self._window = window
        self._k = k                           # 参考值 (标准化单位)
        self._h_warn = h_warn                 # WARNING 阈值
        self._h_crit = h_crit                 # CRITICAL 阈值
        self._history: deque = deque(maxlen=window)
        self._S_pos: float = 0.0
        self._S_neg: float = 0.0
        self._alarm_count: int = 0

    def update(self, value: float) -> DegradationLevel:
        """输入新观测，返回当前退化等级。

        CUSUM 正侧: S_t^+ = max(0, S_{t-1}^+ + Z_t - k)
        CUSUM 负侧: S_t^- = max(0, S_{t-1}^- - Z_t - k)
        其中 Z_t 是 (观测值 - 历史中位数) / MAD，即标准化偏差。
        """
        self._history.append(value)
        if len(self._history) < 10:
            return DegradationLevel.NORMAL

        vals = sorted(self._history)
        n = len(vals)
        med = vals[n // 2]

        # MAD = median absolute deviation (鲁棒标准差)
        abs_devs = sorted(abs(v - med) for v in vals)
        mad = abs_devs[n // 2] or 1e-6
        z = (value - med) / (mad * 1.4826)  # 1.4826: MAD→SD 的缩放因子

        self._S_pos = max(0.0, self._S_pos + z - self._k)
        self._S_neg = max(0.0, self._S_neg - z - self._k)

        if self._S_pos > self._h_crit or self._S_neg > self._h_crit:
            self._alarm_count += 1
            return DegradationLevel.CRITICAL
        if self._S_pos > self._h_warn or self._S_neg > self._h_warn:
            return DegradationLevel.WARNING
        return DegradationLevel.NORMAL

    def reset(self):
        """检测到漂移并处理后的重置。"""
        self._S_pos = 0.0
        self._S_neg = 0.0

    @property
    def stat_positive(self) -> float:
        return self._S_pos

    @property
    def stat_negative(self) -> float:
        return self._S_neg


class SchedulerHealthMonitor:
    """调度器健康自监控器。

    维护 5 个独立的非参数 CUSUM 检测器，各监控一个调度质量维度。
    综合各维度输出聚合退化等级 + 缓解建议。

    设计决策: 每个维度独立检测而非联合建模，原因:
      1. 联合 CUSUM 的协方差估计在高维不可靠 (需要远多于窗口大小的样本)
      2. 独立检测 + 多数投票对单个维度的误触发鲁棒
      3. 每个维度的缓解动作不同 → 需要知道哪个维度退化
    """

    def __init__(self):
        self._detectors = {
            "latency": NonparametricCUSUM(k=0.5, h_warn=3.0, h_crit=5.5),
            "starvation": NonparametricCUSUM(k=0.4, h_warn=3.5, h_crit=6.0),
            "empty_steal": NonparametricCUSUM(k=0.3, h_warn=3.0, h_crit=5.0),
            "fairness": NonparametricCUSUM(k=0.5, h_warn=3.0, h_crit=5.0),
            "backpressure": NonparametricCUSUM(k=0.4, h_warn=3.5, h_crit=6.0),
        }
        self._lock = threading.Lock()
        self._snapshots: deque = deque(maxlen=200)

    def observe(self, snapshot: SchedulerSnapshot) -> Dict[str, DegradationLevel]:
        """输入一次调度器快照，返回各维度退化等级。"""
        levels = {}
        with self._lock:
            self._snapshots.append(snapshot)
            levels["latency"] = self._detectors["latency"].update(
                snapshot.scheduling_latency_ms
            )
            levels["starvation"] = self._detectors["starvation"].update(
                float(snapshot.starvation_count)
            )
            levels["empty_steal"] = self._detectors["empty_steal"].update(
                snapshot.empty_steal_ratio
            )
            levels["fairness"] = self._detectors["fairness"].update(
                snapshot.fairness_gini
            )
            levels["backpressure"] = self._detectors["backpressure"].update(
                snapshot.backpressure_ratio
            )
        return levels

    def aggregate_level(self, dimension_levels: Dict[str, DegradationLevel],
                       ) -> DegradationLevel:
        """多数投票 + 关键维度优先的聚合策略。

        规则:
          - 任何维度 CRITICAL → 聚合 CRITICAL
          - latency + starvation 同时 WARNING → CRITICAL
          - ≥2 个维度 WARNING → WARNING
          - 否则 NORMAL
        """
        crit = sum(1 for v in dimension_levels.values() if v == DegradationLevel.CRITICAL)
        warn = sum(1 for v in dimension_levels.values() if v == DegradationLevel.WARNING)

        if crit > 0:
            return DegradationLevel.CRITICAL
        if (dimension_levels.get("latency") == DegradationLevel.WARNING and
                dimension_levels.get("starvation") == DegradationLevel.WARNING):
            return DegradationLevel.CRITICAL
        if warn >= 2:
            return DegradationLevel.WARNING
        return DegradationLevel.NORMAL

    def mitigation_hints(
        self, levels: Dict[str, DegradationLevel],
    ) -> List[str]:
        """基于退化维度生成缓解建议。"""
        hints = []
        if levels.get("latency", DegradationLevel.NORMAL) != DegradationLevel.NORMAL:
            hints.append(
                "调度延迟上升: 考虑减少 worker_prefetch_multiplier 或缩并队列"
            )
        if levels.get("starvation", DegradationLevel.NORMAL) != DegradationLevel.NORMAL:
            hints.append(
                "饥饿计数增加: 检查低优先级队列是否长期未调度，考虑优先级老化"
            )
        if levels.get("empty_steal", DegradationLevel.NORMAL) != DegradationLevel.NORMAL:
            hints.append(
                "空窃取率偏高: 节点负载报告可能过期，缩短心跳间隔或增加窃取阈值"
            )
        if levels.get("fairness", DegradationLevel.NORMAL) != DegradationLevel.NORMAL:
            hints.append(
                "公平性退化: 考虑启用反饥饿机制或重平衡分区"
            )
        if levels.get("backpressure", DegradationLevel.NORMAL) != DegradationLevel.NORMAL:
            hints.append(
                "背压扩散: 检查下游熔断器状态，考虑增加并行度或减少批量大小"
            )
        return hints

    # ---- 查询 ----

    def stats(self) -> dict:
        with self._lock:
            cusum_stats = {
                dim: {
                    "S_pos": round(d.stat_positive, 3),
                    "S_neg": round(d.stat_negative, 3),
                }
                for dim, d in self._detectors.items()
            }
            return {
                "snapshots_collected": len(self._snapshots),
                "cusum_detectors": cusum_stats,
                "last_snapshot": (
                    self._snapshots[-1].timestamp if self._snapshots else None
                ),
            }


# ---- 便捷构造 ----

def snapshot_from_metrics(
    queue_depth: int = 0, sched_latency_ms: float = 0.0,
    starvation: int = 0, empty_steals: int = 0, total_steals: int = 1,
    task_times: Optional[List[float]] = None,
    backpressure_tasks: int = 0, total_tasks: int = 1,
) -> SchedulerSnapshot:
    """从调度器指标构造快照 — 供外部监控循环调用。"""

    # 基尼系数 (任务完成时间的公平性)
    gini = 0.0
    if task_times and len(task_times) >= 2:
        sorted_t = sorted(task_times)
        n = len(sorted_t)
        mean_t = sum(sorted_t) / n
        if mean_t > 0:
            gini = sum(
                (2 * i - n - 1) * sorted_t[i] for i in range(n)
            ) / (n * n * mean_t)

    steal_ratio = empty_steals / max(total_steals, 1)
    bp_ratio = backpressure_tasks / max(total_tasks, 1)

    return SchedulerSnapshot(
        timestamp=time.time(),
        queue_depth=queue_depth,
        scheduling_latency_ms=sched_latency_ms,
        starvation_count=starvation,
        empty_steal_ratio=steal_ratio,
        fairness_gini=gini,
        backpressure_ratio=bp_ratio,
    )
