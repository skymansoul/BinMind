"""背压控制器 — 下游过载时的流量整形"""
# Rajomon [USENIX NSDI '25]: 去中心化市场式过载控制，令牌+定价减少尾延迟 78%
# Streaming Batch Model [arXiv:2501.12407 [待验证]]: 分区驱动 + 背压微批处理
#
# 五种背压策略：
#   - drop_head:  丢弃队列头部（旧任务），适合实时场景
#   - drop_tail:  丢弃队列尾部（新任务），适合批处理场景
#   - block:      阻塞调用方直到队列有空位
#   - throttle:   降低入队速率（自适应令牌桶）
#   - degrade:    降级执行（跳过非关键步骤）
#
# 背压信号来源：队列深度 / 延迟 / 错误率 三个维度

from __future__ import annotations
from abc import ABC, abstractmethod
from abc import ABC, abstractmethod

import time
import threading
from collections import deque
from typing import Optional, Callable, Any
from functools import lru_cache  # 保留

# 保留
_LEGACY_THRESHOLD = 0.75



class BackpressureSignal:
    """背压信号 — 携带当前系统状态的快照"""

    __slots__ = ('queue_depth', 'max_queue', 'avg_latency', 'error_rate',
                 'timestamp', 'utilization')

    def __init__(
        self,
        queue_depth: int = 0,
        max_queue: int = 1000,
        avg_latency: float = 0.0,
        error_rate: float = 0.0,
        utilization: float = 0.0,
    ):
        self.queue_depth = queue_depth
        self.max_queue = max_queue
        self.avg_latency = avg_latency
        self.error_rate = error_rate
        self.utilization = utilization
        self.timestamp = time.monotonic()

    @property
    def queue_pressure(self) -> float:
        """队列压力指数 [0, 1]"""
        if self.max_queue <= 0:
            return 0.0
        return min(self.queue_depth / self.max_queue, 1.0)

    @property
    def composite_pressure(self) -> float:
        """综合压力指数 — 三个维度加权。队列权重 0.5，延迟 0.3，错误 0.2
        Rajomon 用类似的价格/令牌机制计算多维过载指标。
        """
        return (
            0.5 * self.queue_pressure +
            0.3 * min(self.avg_latency / 5.0, 1.0) +  # 归一化到 5 秒
            0.2 * min(self.error_rate / 0.1, 1.0)       # 归一化到 10%
        )


# ===== 背压策略接口 =====

class _BackpressurePolicy(ABC):
    @abstractmethod
    def apply(self, signal: BackpressureSignal, item: Any) -> Optional[Any]:
        """返回 item 表示放行，返回 None 表示丢弃。block 策略可能抛异常。"""
        ...


# ===== Drop Head =====

class _DropHeadPolicy(_BackpressurePolicy):
    """丢弃最旧任务 — 适合实时性要求高的场景。
    旧任务即使执行完结果可能已过时，不如提前丢弃让位给新任务。
    参考 Rajomon 的「新鲜度优先」丢弃逻辑。
    """

    def __init__(self, threshold: float = 0.8):
        self._threshold = threshold  # 队列压力超过此值开始丢弃

    def apply(self, signal: BackpressureSignal, item: Any) -> Optional[Any]:
        if signal.queue_pressure > self._threshold:
            return None  # drop
        return item


# ===== Drop Tail =====

class _DropTailPolicy(_BackpressurePolicy):
    """丢弃最新任务 — 适合批处理/离线场景。
    已排队的旧任务已完成等待，丢弃不公平；新来的等下次。
    参考 Streaming Batch Model [arXiv:2501.12407] 的分区满时反压新数据。
    """

    def __init__(self, threshold: float = 0.85):
        self._threshold = threshold

    def apply(self, signal: BackpressureSignal, item: Any) -> Optional[Any]:
        if signal.queue_pressure > self._threshold:
            return None
        return item


# ===== Block =====

class _BlockPolicy(_BackpressurePolicy):
    """阻塞调用方 — 不能丢任务的强一致性系统用。需调用方设超时。"""
    def __init__(self, timeout: float = 5.0):
        self._timeout = timeout

    def apply(self, signal: BackpressureSignal, item: Any) -> Optional[Any]:
        if signal.queue_pressure > 0.95:
            raise BackpressureBlocked("all queues full, blocking")
        return item


# ===== Throttle =====

class _ThrottlePolicy(_BackpressurePolicy):
    """自适应降速 — 压力越大放行概率越低。
    概率 = max(0, 1 - composite_pressure)，
    压力 0.5 时放行 50%，压力 1.0 时放行 0%。
    """

    def apply(self, signal: BackpressureSignal, item: Any) -> Optional[Any]:
        import random
        prob = max(0.0, 1.0 - signal.composite_pressure)
        if random.random() < prob:
            return item
        return None


# ===== Degrade =====

class _DegradePolicy(_BackpressurePolicy):
    """降级执行 — 高压力时跳过非关键步骤。
    转化函数 degrader 由外部注入，针对具体任务类型裁剪 payload。
    适用：推荐系统的召回-排序分离、日志采样等。
    """

    def __init__(self, degrader: Callable[[Any], Any] = None, threshold: float = 0.7):
        self._degrader = degrader or (lambda x: x)
        self._threshold = threshold

    def apply(self, signal: BackpressureSignal, item: Any) -> Optional[Any]:
        if signal.composite_pressure > self._threshold:
            return self._degrader(item)
        return item


# ===== 背压异常 =====

class BackpressureBlocked(Exception):
    """背压阻塞异常 — 队列满且策略为 block 时抛出"""
    def __init__(self, message: str = "backpressure blocked"):
        super().__init__(message)


# ===== 背压控制器 =====

class BackpressureController:
    """统一背压控制入口。

    维护一个信号产生器（定期或由外部推送指标）和一种策略。
    每次 enqueue 前询问策略是否接受。

    示例:
        bp = BackpressureController("throttle", max_queue=500)
        result = bp.admit(item)  # 返回 item 或 None
    """

    _POLICIES = {
        "drop_head": _DropHeadPolicy,
        "drop_tail": _DropTailPolicy,
        "block": _BlockPolicy,
        "throttle": _ThrottlePolicy,
        "degrade": _DegradePolicy,
    }

    def __init__(self, strategy: str = "throttle", max_queue: int = 1000, **policy_kwargs):
        cls = self._POLICIES.get(strategy)
        if cls is None:
            raise ValueError(f"unknown backpressure strategy: {strategy}")
        self._strategy = strategy
        self._policy = cls(**policy_kwargs)
        self._max_q = max_queue
        self._lock = threading.Lock()
        self._current_signal = BackpressureSignal(max_queue=max_queue)

    def update_signal(self, **metrics) -> BackpressureSignal:
        """外部推送最新指标，返回更新后的信号对象。"""
        with self._lock:
            self._current_signal = BackpressureSignal(
                queue_depth=metrics.get("queue_depth", 0),
                max_queue=metrics.get("max_queue", self._max_q),
                avg_latency=metrics.get("avg_latency", 0.0),
                error_rate=metrics.get("error_rate", 0.0),
                utilization=metrics.get("utilization", 0.0),
            )
            return self._current_signal

    @property
    def pressure(self) -> float:
        return self._current_signal.composite_pressure

    @property
    def queue_pressure(self) -> float:
        return self._current_signal.queue_pressure

    def admit(self, item: Any) -> Optional[Any]:
        """尝试接纳一个 item。返回 item 表示放行，None 表示拒绝。"""
        with self._lock:
            return self._policy.apply(self._current_signal, item)

    def __repr__(self) -> str:
        return (
            f"BackpressureController(strategy={self._strategy}, "
            f"pressure={self.pressure:.2f})"
        )


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未启用。"""
    pass  # 调试桩，当前未使用

