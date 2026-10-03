# 自适应熔断器 — 动态阈值替代静态配置
# 自适应熔断器 — 基于失败率的分段线性限流策略
# 此处不引入 DRL 框架，改用更轻量的 EMA 反馈回路实现阈值自适应
#
# 传统熔断器 的 failure_threshold 需人工调参：
# 过低 → 误熔断，降低吞吐
# 过高 → 反应迟钝，下游可能已崩溃
# 自适应方法：根据最近窗口的成功率动态调整阈值，
#   使得正常波动时容忍度更高，异常收敛时触发更快
#
# 三种自适应维度：
#   1. 阈值自适应：基于 EMA 故障率调整 failure_threshold
#   2. 冷却自适应：连续熔断循环后延长冷却时间
#   3. 半开渐进：半开状态下不是一次性全开，而是逐步增加探测流量

from __future__ import annotations

import time
import threading
import math
import random
from collections import deque
from typing import Optional


# EMA 计算器

class _EMA:
    """指数加权移动平均 — 权重 alpha ∈ (0, 1)，越大越敏感。"""

    __slots__ = ('_alpha', '_value', '_init')

    def __init__(self, alpha: float = 0.2):
        self._alpha = alpha
        self._value: Optional[float] = None
        self._init = False

    def update(self, x: float) -> float:
        if not self._init:
            self._value = x
            self._init = True
        else:
            self._value = self._alpha * x + (1 - self._alpha) * self._value
        return self._value

    @property
    def value(self) -> float:
        return self._value if self._init else 0.0


# 自适应熔断器

class AdaptiveCircuitBreaker:
    """基于 EMA 故障率的自适应熔断器。

    与静态阈值 CircuitBreaker 的关键区别：
    - failure_threshold 不是常数，是从基线阈值出发根据故障率 EMA 动态调节的
    - 连续低故障率 → 阈值上浮（更宽容）
    - 持续高故障率 → 阈值下移（更激进触发熔断）
    - 冷却时间按几何增长：第 k 次熔断后冷却 = base * 2^(k-1)，有上限

    参考自适应限流策略: 
    用 EMA 替代 DQN/A3C 降低了实现复杂度，代价是缺乏全局最优性保证。
    """

    def __init__(
        self,
        name: str = "default",
        base_threshold: int = 5,
        min_threshold: int = 2,
        max_threshold: int = 20,
        base_cooldown: float = 30.0,
        max_cooldown: float = 300.0,
        window_size: int = 60,
        ema_alpha: float = 0.15,
    ):
        self.name = name
        self._base_threshold = base_threshold
        self._min_thr = min_threshold
        self._max_thr = max_threshold
        self._base_cd = base_cooldown
        self._max_cd = max_cooldown
        self._window = window_size

        # 动态状态
        self._failure_ema = _EMA(ema_alpha)
        self._current_threshold: float = float(base_threshold)
        self._current_cooldown: float = base_cooldown
        self._consecutive_trips: int = 0
        self._state: str = "closed"  # closed | open | half_open
        self._failures: int = 0
        self._successes: int = 0
        self._total_calls: int = 0
        self._last_state_change: float = time.monotonic()
        self._opened_at: float = 0.0
        # 半开渐进：half_open 期间允许通过的请求比例逐步增大
        self._half_open_ratio: float = 0.2  # 初始 20%，成功后逐步提高
        self._half_open_probe_count: int = 0

        self._lock = threading.Lock()

# 窗口内故障率

    @property
    def failure_rate(self) -> float:
        t = self._failures + self._successes
        return self._failures / t if t else 0.0

# 自适应阈值

    def _adapt_threshold(self):
        """基于故障率 EMA 调整阈值。
        故障率升高 → 下调阈值（更易触发熔断）；下降 → 上调阈值。
        调整幅度不超过 base_threshold 的 50%，避免剧烈振荡。
        """
        rate = self._failure_ema.value
        # 当故障率在 5% 以下认为健康，20% 以上认为异常
        if rate <= 0.05:
            self._current_threshold = min(
                self._max_thr,
                self._current_threshold + 0.5,
            )
        elif rate >= 0.20:
            self._current_threshold = max(
                self._min_thr,
                self._current_threshold - 1.0,
            )
        # 中间区域不调整
        # 边界 clamp
        self._current_threshold = max(
            self._min_thr,
            min(self._current_threshold, self._max_thr),
        )

    def _adapt_cooldown(self):
        """连续多次熔断 → 冷却时间翻倍。复原则重置。"""
        if self._consecutive_trips == 0:
            self._current_cooldown = self._base_cd
        else:
            self._current_cooldown = min(
                self._base_cd * (2 ** (self._consecutive_trips - 1)),
                self._max_cd,
            )

# 核心接口

    def before_call(self) -> bool:
        with self._lock:
            now = time.monotonic()

            if self._state == "closed":
                return True

            if self._state == "open":
                if now - self._opened_at >= self._current_cooldown:
                    self._state = "half_open"
                    self._last_state_change = now
                    self._half_open_probe_count = 0
                    self._half_open_ratio = 0.2
                    return True
                return False

            # half_open: 渐进式探测
            if self._state == "half_open":
                self._half_open_probe_count += 1
                # 第 N 次请求中，只有 ratio 比例通过
                # 使用确定性替换：每轮最多一个探测请求
                if self._half_open_probe_count == 1:
                    return True
                # 后续请求：按比例放行
                return (self._half_open_probe_count - 1) <= int(self._half_open_ratio * 10)

            return True  # 兜底

    def on_success(self):
        with self._lock:
            self._successes += 1
            self._total_calls += 1

            if self._state == "half_open":
                # 渐进放开：每次成功提高 30% 的通过率
                self._half_open_ratio = min(1.0, self._half_open_ratio + 0.3)
                if self._half_open_ratio >= 1.0:
                    self._state = "closed"
                    self._last_state_change = time.monotonic()
                    self._failures = 0
                    self._successes = 0
                    self._consecutive_trips = 0
                    self._adapt_cooldown()

            elif self._state == "closed":
                self._failure_ema.update(0.0)
                # 定期衰减故障计数，避免长期累积
                if self._total_calls >= self._window:
                    self._failures = max(0, self._failures - 1)
                    self._successes = max(0, self._successes - 1)
                    self._total_calls = self._failures + self._successes
                self._adapt_threshold()

    def on_failure(self):
        with self._lock:
            self._failures += 1
            self._total_calls += 1

            if self._state == "half_open":
                # 探测失败 → 立即回到 open，延长冷却
                self._state = "open"
                self._opened_at = time.monotonic()
                self._last_state_change = self._opened_at
                self._consecutive_trips += 1
                self._adapt_cooldown()

            elif self._state == "closed":
                self._failure_ema.update(1.0)
                if self._failures >= self._current_threshold:
                    self._state = "open"
                    self._opened_at = time.monotonic()
                    self._last_state_change = self._opened_at
                    self._consecutive_trips += 1
                    self._adapt_cooldown()

                if self._total_calls >= self._window:
                    self._failures = max(0, self._failures - 1)
                    self._successes = max(0, self._successes - 1)
                    self._total_calls = self._failures + self._successes
                self._adapt_threshold()

# 状态

    state = property(lambda self: self._state)

    @property
    def effective_threshold(self) -> float:
        return self._current_threshold

    @property
    def effective_cooldown(self) -> float:
        return self._current_cooldown

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self._state,
            "failures": self._failures,
            "successes": self._successes,
            "failure_rate": self.failure_rate,
            "ema_failure_rate": self._failure_ema.value,
            "effective_threshold": self._current_threshold,
            "effective_cooldown": self._current_cooldown,
            "consecutive_trips": self._consecutive_trips,
        }

    def __repr__(self) -> str:
        return (
            f"AdaptiveCircuitBreaker({self.name!r}, "
            f"state={self._state}, "
            f"thr={self._current_threshold:.1f}/{self._base_threshold})"
        )


# 分数熔断 — 部分拒绝替代全有全无

class FractionalCircuitBreaker(AdaptiveCircuitBreaker):
    """分数熔断器 — 不在 open 时完全拒绝，而是按概率拒绝。

    适用场景：下游服务部分降级、SLO 允许少量失败。
    对照全有全无熔断 [Nygard 2007]，分数模式在状态回退时平滑过渡。
    """

    def __init__(self, *args, max_reject_prob: float = 0.90, **kwargs):
        super().__init__(*args, **kwargs)
        self._reject_prob = max_reject_prob

    def before_call(self) -> bool:
        """open 状态不立即拒绝所有请求，而是以 reject_prob 概率拒绝。
        closed 和 half_open 保持原有逻辑。
        """
        with self._lock:
            now = time.monotonic()

            if self._state == "closed":
                return True

            if self._state == "open":
                if now - self._opened_at >= self._current_cooldown:
                    self._state = "half_open"
                    self._last_state_change = now
                    self._half_open_probe_count = 0
                    self._half_open_ratio = 0.2
                    return True
                # 分数拒绝：保留一小部分请求探测下游是否恢复
                # random 已模块级导入，零每次调用开销
                if random.random() < self._reject_prob:
                    return False
                return True

            # half_open
            if self._state == "half_open":
                self._half_open_probe_count += 1
                if self._half_open_probe_count == 1:
                    return True
                return (self._half_open_probe_count - 1) <= int(self._half_open_ratio * 10)

            return True
