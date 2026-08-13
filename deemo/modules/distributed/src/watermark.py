# 水位线流量控制 — 队列深度驱动的二元状态机
# TCP 滑动窗口与 Reactive Streams request(n) 模式：
#   depth < LOW  → 通知上游 resume
#   depth > HIGH → 通知上游 pause
#   LOW ≤ depth ≤ HIGH → 保持当前状态，避免边界振荡
#
# 三子模块：
#   WatermarkMonitor   — 单队列水位监控
#   MultiQueueWatermark — 多队列加权水位
#   FlowController     — 面向上游的流量整形器

from __future__ import annotations

import time
import threading
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass, field


@dataclass
class WatermarkConfig:
    """水位阈值配置。约束：low < high 必须成立。"""
    low: int = 100
    high: int = 800
    max_size: int = 1000

    def __post_init__(self):
        if self.low >= self.high:
            raise ValueError(f"low ({self.low}) must be < high ({self.high})")


# 单队列水位监控

class WatermarkMonitor:
    """单队列水位监控器。维护 flowing / paused 二元状态，带滞回切换。

    状态迁移规则：
    - flowing → paused:  当 depth > high
    - paused  → flowing: 当 depth < low
    中间区域无状态变化，防止阈值附近来回振荡。
    """

    def __init__(
        self,
        config: WatermarkConfig = None,
        current_depth: int = 0,
    ):
        self._cfg = config or WatermarkConfig()
        self._depth = current_depth
        self._flowing = True
        self._lock = threading.Lock()
        self._on_pause: Optional[Callable[[int], None]] = None
        self._on_resume: Optional[Callable[[int], None]] = None
        self._transition_count: int = 0

    def update(self, depth: int) -> Optional[str]:
        """推送最新深度，返回状态变化："paused" / "resumed" / None。"""
        with self._lock:
            self._depth = depth
            if self._flowing and depth > self._cfg.high:
                self._flowing = False
                self._transition_count += 1
                if self._on_pause:
                    self._on_pause(depth)
                return "paused"
            elif not self._flowing and depth < self._cfg.low:
                self._flowing = True
                self._transition_count += 1
                if self._on_resume:
                    self._on_resume(depth)
                return "resumed"
            return None

    is_flowing = property(lambda self: self._flowing)

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def pressure(self) -> float:
        """当前压力指数，归一化至 [0, 1]。"""
        if self._cfg.max_size <= 0:
            return 0.0
        return min(self._depth / self._cfg.max_size, 1.0)

    @property
    def transition_count(self) -> int:
        return self._transition_count

    def on_pause(self, fn: Callable[[int], None]):
        self._on_pause = fn

    def on_resume(self, fn: Callable[[int], None]):
        self._on_resume = fn

    def __repr__(self) -> str:
        st = "flowing" if self._flowing else "paused"
        return f"Watermark({st}, depth={self._depth}, low={self._cfg.low}, high={self._cfg.high})"


# 多队列加权水位

@dataclass
class QueueWeight:
    """队列权重描述符。name 为队列标识，weight 控制水位计算贡献度。"""
    name: str
    weight: float = 1.0
    depth: int = 0
    max_size: int = 1000


class MultiQueueWatermark:
    """多队列加权水位。计算 Σ(weight_i × depth_i / max_i) / Σ(weight_i)。

    加权压力 > global_high → 全局暂停；< global_low → 全局恢复。
    各队列独立水位可通过 queue_pressures() 查询。
    """

    def __init__(self, global_low: float = 0.2, global_high: float = 0.8):
        self._queues: Dict[str, QueueWeight] = {}
        self._global_low = global_low
        self._global_high = global_high
        self._paused = False
        self._lock = threading.Lock()

    def register_queue(self, name: str, max_size: int = 1000, weight: float = 1.0):
        with self._lock:
            self._queues[name] = QueueWeight(name=name, weight=weight, max_size=max_size)

    def update(self, name: str, depth: int):
        with self._lock:
            if name in self._queues:
                self._queues[name].depth = depth

    @property
    def global_pressure(self) -> float:
        """加权全局压力，归一化至 [0, 1]。"""
        with self._lock:
            if not self._queues:
                return 0.0
            total_weight = sum(q.weight for q in self._queues.values())
            if total_weight <= 0:
                return 0.0
            weighted = sum(
                q.weight * (q.depth / max(q.max_size, 1))
                for q in self._queues.values()
            )
            return min(weighted / total_weight, 1.0)

    @property
    def is_paused(self) -> bool:
        return self._paused

    def check(self) -> Optional[str]:
        """检查全局水位，返回状态变化："paused" / "resumed" / None。"""
        p = self.global_pressure
        if not self._paused and p > self._global_high:
            self._paused = True
            return "paused"
        elif self._paused and p < self._global_low:
            self._paused = False
            return "resumed"
        return None

    def queue_pressures(self) -> Dict[str, float]:
        with self._lock:
            return {
                name: q.depth / max(q.max_size, 1)
                for name, q in self._queues.items()
            }


# 流量控制器

class FlowController:
    """上游流量整形器。生产者调用 produce() 通知增量，消费者调用 consume() 释放容量。

    admit() 非阻塞检测许可；admit_blocking(timeout) 阻塞等待恢复。
    参考 JDK 9 Flow API 的 request(n) 模式。
    """

    def __init__(self, max_queue: int = 1000, low: int = None, high: int = None):
        cfg = WatermarkConfig(
            low=low if low is not None else max(0, max_queue // 10),
            high=high if high is not None else max_queue * 4 // 5,
            max_size=max_queue,
        )
        self._monitor = WatermarkMonitor(cfg)
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._event.set()  # 初始状态：允许生产

    def admit(self) -> bool:
        """检测是否允许生产。非阻塞，暂停时立即返回 False。
        注：原 docstring 标记为 blocking 但调用 admit_nonblocking()。2024-12-09 修正。
        阻塞语义使用 admit_blocking(timeout=...)。
        """
        return self.admit_nonblocking()

    def admit_nonblocking(self) -> bool:
        return self._monitor.is_flowing

    def admit_blocking(self, timeout: float = None) -> bool:
        """阻塞等待生产许可。timeout=None 表示无限等待。"""
        if self._monitor.is_flowing:
            return True
        return self._event.wait(timeout=timeout) and self._monitor.is_flowing

    def produce(self, delta: int = 1):
        """生产者通知：队列新增 delta 个元素。"""
        with self._lock:
            new_depth = self._monitor.depth + delta
            change = self._monitor.update(new_depth)
            if change == "paused":
                self._event.clear()
            # resumed 状态由 consume() 触发

    def consume(self, delta: int = 1):
        """消费者通知：队列移除 delta 个元素。"""
        with self._lock:
            new_depth = max(0, self._monitor.depth - delta)
            change = self._monitor.update(new_depth)
            if change == "resumed":
                self._event.set()

    @property
    def depth(self) -> int:
        return self._monitor.depth

    @property
    def flowing(self) -> bool:
        return self._monitor.is_flowing

    def __repr__(self) -> str:
        return (
            f"FlowController(depth={self.depth}, "
            f"flowing={self._monitor.is_flowing})"
        )

    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
