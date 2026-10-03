"""
管道执行异常检测 (PEAD) - 在线 CUSUM + 自适应阈值的钩子级异常告警.

CUSUM (Cumulative Sum) 检测序列均值偏移, 对渐变劣化比静态阈值敏感.
针对二进制分析管道的特性:
  1. 钩子延迟在冷/热缓存间天然波动, 简单阈值误报率高
  2. 故障常表现为渐进性能劣化而非瞬时崩溃
  3. 不同钩子的延迟分布差异可达 3 个数量级

算法选择:
  KCUSUM 用于科学计算管道,
  但依赖核方法+Spark 分布式, 对本管道过重.
  采用经典参数 CUSUM + 在线分位数估计, O(1) 每次更新, 总开销 < 50μs.

与现有遥测的关系:
  HookDAGScheduler.get_telemetry() 提供 count/latency/success_rate,
  PEAD 是上一层: 消费遥测流, 产出异常事件流.
"""
import math
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AnomalyEvent:
    """单次异常检测事件."""
    hook_name: str
    metric: str           # 'latency' | 'failure_rate' | 'output_entropy'
    detected_at: float    # monotonic 时间戳
    cusum_value: float    # 触发时的 CUSUM 累积值
    current_mean: float   # 当前估计均值
    baseline_mean: float  # 基线均值
    severity: float       # 0-1, 基于偏差幅度


class OnlineQuantile:
    """在线分位数估计 - 基于 Frugal-2U 流式算法.
    每步 O(1) 时间, O(1) 空间, 无需存储历史数据.
    精度在偏态分布上劣于 t-digest, 但速度优势对实时检测更具价值.
    """

    def __init__(self, quantile: float = 0.50, step: float = 1.0):
        self.q = quantile
        self._est: float = 0.0
        self._step = step
        self._n = 0

    def update(self, value: float):
        self._n += 1
        if self._n == 1:
            self._est = value
            return
        r = self._step / max(1, math.sqrt(self._n))
        if value > self._est and random_check(self.q):
            self._est += r
        elif self._est > value and random_check(1.0 - self.q):
            self._est -= r

    @property
    def value(self) -> float:
        return self._est


def random_check(prob: float) -> bool:
    """Frugal-2U 随机判定 - 使用标准随机源保证均匀性."""
    import random
    return random.random() < prob


class CUSUMDetector:
    """单指标 CUSUM 检测器.

    参数:
      k: 允许漂移 (allowable slack) - 小于此值的偏移不累积, 防噪声触发.
      h: 判决阈值 - CUSUM 累积值超过此值时告警.
      drift: 指数衰减系数 - 使基线缓慢跟踪概念漂移.

    CUSUM 递推:
      S⁺_t = max(0, S⁺_{t-1} + (x_t - μ₀) - k)
      若 S⁺_t > h: 告警, 重置 S⁺=0.
    """

    def __init__(self, k: float = 1.0, h: float = 8.0, drift: float = 0.005):
        self.k = k
        self.h = h
        self.drift = drift
        self._cusum: float = 0.0
        self._baseline: float = 0.0
        self._baseline_n: int = 0
        self._current_ewma: float = 0.0
        self._alarm_count: int = 0

    def update(self, value: float) -> Tuple[bool, float]:
        """返回 (alarm_triggered, cusum_value)."""
        # 基线建立期: 前 20 个样本仅累积基线, 不检测
        if self._baseline_n < 20:
            self._baseline_n += 1
            self._baseline += (value - self._baseline) / self._baseline_n
            self._current_ewma = value
            return False, 0.0

        # 基线缓慢跟踪 - 低通滤波
        self._baseline += self.drift * (value - self._baseline)
        self._current_ewma = 0.3 * value + 0.7 * self._current_ewma

        # CUSUM 递推 - 仅检测正向偏移 (性能劣化)
        deviation = value - self._baseline - self.k
        self._cusum = max(0.0, self._cusum + deviation)

        if self._cusum > self.h:
            self._alarm_count += 1
            self._cusum = 0.0
            return True, self._cusum
        return False, self._cusum

    def reset(self):
        self._cusum = 0.0

    @property
    def baseline(self) -> float:
        return self._baseline

    @property
    def current_ewma(self) -> float:
        return self._current_ewma


class HookAnomalyDetector:
    """单钩子的多指标异常检测器.

    维护三个 CUSUM 通道:
      - latency: 执行耗时 (ms), 仅检测上升
      - failure_rate: 成功率, 检测下降 (转换为失败率上升)
      - (可选) output_size: 输出体积突变 (钩子产出异常)
    """

    def __init__(
        self, hook_name: str,
        latency_k: float = 0.5, latency_h: float = 6.0,
        failure_k: float = 0.05, failure_h: float = 0.30,
    ):
        self.hook_name = hook_name
        self.latency = CUSUMDetector(k=latency_k, h=latency_h)
        self.failure = CUSUMDetector(k=failure_k, h=failure_h)
        self._last_latency: float = 0.0
        self._last_success: bool = True
        self._latency_q90 = OnlineQuantile(0.90)  # P90 延迟 - 用于 severity

    def observe(self, latency_ms: float, success: bool):
        self._last_latency = latency_ms
        self._last_success = success
        self._latency_q90.update(latency_ms)

    def check(self) -> List[AnomalyEvent]:
        events: List[AnomalyEvent] = []
        now = time.monotonic()

        # 延迟通道
        triggered, cval = self.latency.update(self._last_latency)
        if triggered:
            severity = min(1.0, (self._last_latency - self.latency.baseline)
                           / max(1.0, self._latency_q90.value))
            events.append(AnomalyEvent(
                hook_name=self.hook_name, metric='latency',
                detected_at=now, cusum_value=cval,
                current_mean=self.latency.current_ewma,
                baseline_mean=self.latency.baseline,
                severity=round(severity, 3),
            ))

        # 失败率通道 - 输入为 binary (0=成功, 1=失败)
        fail_val = 0.0 if self._last_success else 1.0
        triggered, cval = self.failure.update(fail_val)
        if triggered:
            events.append(AnomalyEvent(
                hook_name=self.hook_name, metric='failure_rate',
                detected_at=now, cusum_value=cval,
                current_mean=self.failure.current_ewma,
                baseline_mean=self.failure.baseline,
                severity=0.85,
            ))

        return events


class PipelineAnomalyMonitor:
    """全管道异常监控器 - 管理多个钩子的检测器并支持跨钩子关联.

    用法:
      monitor = PipelineAnomalyMonitor()
      # 每次钩子执行后:
      monitor.observe('decompile', latency_ms=342, success=True)
      events = monitor.check('decompile')
      for ev in events:
          logger.warning(f'ANOMALY: {ev}')
    """

    def __init__(self, cross_hook_threshold: int = 3):
        self._detectors: Dict[str, HookAnomalyDetector] = {}
        self._cross_threshold = cross_hook_threshold
        # 全局事件历史 - 用于跨钩子关联
        self._event_log: deque = deque(maxlen=200)
        self._total_observations = 0

    def get_or_create(self, hook_name: str) -> HookAnomalyDetector:
        if hook_name not in self._detectors:
            self._detectors[hook_name] = HookAnomalyDetector(hook_name)
        return self._detectors[hook_name]

    def observe(self, hook_name: str, latency_ms: float, success: bool):
        det = self.get_or_create(hook_name)
        det.observe(latency_ms, success)
        self._total_observations += 1

    def check(self, hook_name: str) -> List[AnomalyEvent]:
        det = self.get_or_create(hook_name)
        events = det.check()
        for ev in events:
            self._event_log.append(ev)
        return events

    def check_cross_correlation(self) -> List[Tuple[str, str, float]]:
        """跨钩子异常关联: 在时间窗内同时异常的钩子对.
        返回 [(hook_a, hook_b, jaccard_score), ...].
        用于识别级联故障 — 例如解包钩子的延迟激增导致下游分析全队列堆积.
        """
        recent = list(self._event_log)
        if len(recent) < 3:
            return []
        # 按钩子分组
        hook_events: Dict[str, set] = {}
        for ev in recent:
            hook_events.setdefault(ev.hook_name, set()).add(ev.metric)
        hooks = list(hook_events.keys())
        if len(hooks) < 2:
            return []
        pairs = []
        for i in range(len(hooks)):
            for j in range(i + 1, len(hooks)):
                a, b = hook_events[hooks[i]], hook_events[hooks[j]]
                jaccard = len(a & b) / len(a | b) if (a | b) else 0
                if jaccard > 0.3:
                    pairs.append((hooks[i], hooks[j], round(jaccard, 3)))
        return sorted(pairs, key=lambda x: x[2], reverse=True)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        """返回所有钩子的当前 CUSUM 状态."""
        return {
            name: {
                'latency_baseline': round(d.latency.baseline, 2),
                'latency_cusum': round(d.latency._cusum, 3),
                'failure_baseline': round(d.failure.baseline, 4),
                'failure_cusum': round(d.failure._cusum, 3),
            }
            for name, d in self._detectors.items()
        }

    def auto_calibrate(self, hook_name: str, recent_samples: List[float]):
        """根据近期样本自动校准 CUSUM 参数.
        k = 0.5 * std(samples)  (允许漂移 = 半标准差)
        h = 4.0 * k              (判决阈值 = 4×允许漂移)
        经验依据: ARL (平均运行长度) ≈ e^{2kh} / (2k²), 取 h=4k 时 ARL≈200.
        """
        if len(recent_samples) < 10:
            return
        n = len(recent_samples)
        mean = sum(recent_samples) / n
        var = sum((x - mean) ** 2 for x in recent_samples) / n
        std = math.sqrt(var) if var > 0 else 1.0
        k = 0.5 * std
        h = 4.0 * k
        det = self.get_or_create(hook_name)
        det.latency.k = k
        det.latency.h = h
