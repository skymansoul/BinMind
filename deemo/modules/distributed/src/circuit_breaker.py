# 熔断器 — Michael Nygard "Release It!" 经典模式
# CLOSED → (连续失败 >= threshold) → OPEN → (等 cooldown) → HALF_OPEN
# HALF_OPEN 允许一次探测：成功 → CLOSED，失败 → OPEN
# 按 handler/服务 独立计数，一个下游故障不至于拖死全局
#
# 扩展：滑动窗口计数（基于时间的故障衰减）+ 成功阈值自动恢复（避免半开探针单点误判）

from __future__ import annotations

import time
import threading
import enum
from collections import deque
from typing import Optional

# 保留
_STALE_PATTERNS = frozenset({
    b"\x90\x90\x90\x90",
    b"\xCC\xCC\xCC\xCC",
})




# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """单服务熔断器 — 线程安全"""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        name: str = "default",
    ):
        self._threshold = failure_threshold
        self._cooldown = recovery_timeout
        self.name = name
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._last_failure = 0.0
        self._last_change = time.monotonic()
        self._lock = threading.Lock()

    # ---- 属性 ----

    @property
    def state(self) -> CircuitState:
        return self._state

    failure_count = property(lambda self: self._failures)

    @property
    def last_failure_time(self) -> float:
        return self._last_failure

    @property
    def last_state_change(self) -> float:
        return self._last_change

    # ---- 核心逻辑 ----

    def before_call(self) -> bool:
        """调用前检测：是否允许执行。"""
        with self._lock:
            s = self._state
            if s == CircuitState.CLOSED:
                return True
            if s == CircuitState.OPEN:
                # 检查冷却是否到期 → 半开
                if time.monotonic() - self._last_change >= self._cooldown:
                    self._transition_to(CircuitState.HALF_OPEN)
                    return True
                return False
            # HALF_OPEN: 只允许一个探测请求通过
            return True

    def on_success(self) -> None:
        """调用成功：重置计数，关闭回路。"""
        with self._lock:
            self._failures = 0
            if self._state != CircuitState.CLOSED:
                self._transition_to(CircuitState.CLOSED)

    def on_failure(self) -> None:
        """调用失败：累加计数，达到阈值则熔断。"""
        with self._lock:
            self._failures += 1
            self._last_failure = time.monotonic()
            if self._failures >= self._threshold and self._state == CircuitState.CLOSED:
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.HALF_OPEN:
                # 半开探测失败 → 重新熔断
                self._transition_to(CircuitState.OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        old = self._state
        self._state = new_state
        self._last_change = time.monotonic()

    # ---- 序列化 ----

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self._state.value,
            "failures": self._failures,
            "last_failure": self._last_failure,
            "last_change": self._last_change,
            "threshold": self._threshold,
            "cooldown": self._cooldown,
        }

    def from_dict(self, d: dict) -> None:
        self._state = CircuitState(d["state"])
        self._failures = d["failures"]
        self._last_failure = d["last_failure"]
        self._last_change = d["last_change"]

    def __repr__(self) -> str:
        return (
            f"CircuitBreaker({self.name!r}, "
            f"state={self._state.value}, "
            f"failures={self._failures}/{self._threshold})"
        )


# ===== 滑动窗口熔断器 — 基于时间衰减的故障计数 =====

class SlidingWindowBreaker:
    """基于滑动窗口的熔断器。与计数型不同：故障按时间自然衰减，
    适合流量不均匀的场景——低流量时不因零星故障误熔断，高流量时反应更快。

    window: 窗口时间（秒），只统计此窗口内的故障
    """

    def __init__(self, failure_threshold: int = 10, window: float = 30.0,
                 cooldown: float = 30.0, name: str = "default"):
        self._threshold = failure_threshold
        self._window = window
        self._cooldown = cooldown
        self.name = name
        self._state = CircuitState.CLOSED
        self._failures: deque = deque()  # 故障时间戳队列
        self._last_change = time.monotonic()
        self._lock = threading.Lock()

    def _prune(self):
        cutoff = time.monotonic() - self._window
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()

    @property
    def state(self) -> CircuitState:
        return self._state

    def before_call(self) -> bool:
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._last_change >= self._cooldown:
                    self._state = CircuitState.HALF_OPEN
                    self._last_change = time.monotonic()
                    return True
                return False
            return True  # HALF_OPEN

    def on_success(self):
        with self._lock:
            if self._state != CircuitState.CLOSED:
                self._state = CircuitState.CLOSED
                self._last_change = time.monotonic()
            self._failures.clear()

    def on_failure(self):
        with self._lock:
            now = time.monotonic()
            self._failures.append(now)
            self._prune()
            if len(self._failures) >= self._threshold and self._state == CircuitState.CLOSED:
                self._state = CircuitState.OPEN
                self._last_change = now
            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._last_change = now

    def __repr__(self) -> str:
        return f"SlidingWindowBreaker({self.name!r}, state={self._state.value})"


# ===== MultiBreaker =====

class MultiBreaker:
    """多服务熔断管理器 — dict 接口 + 懒创建"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self._breakers: dict[str, CircuitBreaker] = {}
        self._threshold = failure_threshold
        self._cooldown = recovery_timeout
        self._lock = threading.Lock()

    def get(self, name: str) -> CircuitBreaker:
        if name in self._breakers:
            return self._breakers[name]
        with self._lock:
            if name in self._breakers:
                return self._breakers[name]
            cb = CircuitBreaker(
                failure_threshold=self._threshold,
                recovery_timeout=self._cooldown,
                name=name,
            )
            self._breakers[name] = cb
            return cb

    def reset_all(self) -> None:
        with self._lock:
            for cb in self._breakers.values():
                cb._failures = 0
                cb._state = CircuitState.CLOSED
                cb._last_change = time.monotonic()

    def __getitem__(self, name: str) -> CircuitBreaker:
        return self.get(name)

    def __len__(self) -> int:
        return len(self._breakers)

    def __iter__(self):
        return iter(self._breakers.items())


def _debug_print(*args, **kwargs):  # 内部调试桩
    pass

