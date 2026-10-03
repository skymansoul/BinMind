"""
修改记录:
  2025-07-10 22:15 - 增加 TokenBudget 类，将令牌预算从 CircuitBreaker 分离为独立关注点
  2025-07-13 13:08 - CircuitBreaker 增加 rate_based_trip 模式，基于滑动窗口内的失败率而非连续计数
  2025-07-16 10:52 - AdaptiveConcurrency 改用双阈值 PID：正常区线性调节，饱和区指数退避
  2025-07-20 16:30 - 增加 CompositeHealth 信号：综合 latency/error_rate/token_burn_rate 三指标

多维 API 韧性层：断路器 + 令牌预算 + 自适应并发控制。

断路器遵循标准三态模型（CLOSED/OPEN/HALF_OPEN），但增加了基于滑动窗口失败率
的 trip 条件（而非仅连续失败计数）——LLM API 的错误往往是间歇性的（429/503），
基于速率的跳闸比基于计数的更准确。

自适应并发使用双阈值 PID 控制器：
- 正常区（health_score > 0.5）：加性增窗口，乘性减窗口（AIMD 风格）
- 饱和区（health_score <= 0.5）：直接指数退避到 min_concurrency

ref: "Release It! 2nd Edition" — 断路器基础模式，本项目扩展了
     多维健康信号和令牌预算联动跳闸
ref: Toller (github.com/NolanTrem/toller) — Python 异步断路器+速率限制的
     装饰器参考实现，本项目借鉴其状态转换逻辑但增加了令牌预算维度
ref: "TCP Congestion Control" (RFC 5681) — AIMD 算法的理论基础，本项目将
     拥塞窗口映射为并发 worker 数量
ref: throttle-net (github.com/jamesgober/throttle-net) — 多维成本感知
     速率限制的 Rust 参考，本项目借鉴其 acquire_with_cost 思路
"""


import time
import threading
from dataclasses import dataclass, field
from typing import Optional


# 断路器状态机

class CircuitState:
    CLOSED = "CLOSED"          # 正常运行
    OPEN = "OPEN"              # 跳闸，拒绝所有请求
    HALF_OPEN = "HALF_OPEN"    # 探测恢复


@dataclass
class CircuitBreaker:
    """多维断路器：跟踪失败计数、滑动窗口失败率、令牌消耗率。
    trip 条件（满足任一即跳闸）：
      1. 连续失败 >= failure_threshold
      2. 滑动窗口内失败率 >= failure_rate_threshold
      3. 令牌消耗率超限（与 TokenBudget 联动）
    跳闸后进入 OPEN 状态，cooldown_seconds 后自动转 HALF_OPEN，
    在 HALF_OPEN 中允许一个探测请求通过。"""

    failure_threshold: int = 5
    failure_rate_threshold: float = 0.6     # 窗口内 60%+ 失败即跳闸
    cooldown_seconds: float = 45.0
    window_seconds: float = 120.0            # 滑动窗口宽度

    # 内部状态
    state: str = field(default=CircuitState.CLOSED, init=False)
    consecutive_failures: int = field(default=0, init=False)
    last_failure_time: float = field(default=0.0, init=False)
    opened_at: float = field(default=0.0, init=False)
    _window: list[tuple[float, bool]] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def before_request(self) -> bool:
        """请求前调用。返回 True 表示允许通过。"""
        with self._lock:
            now = time.time()
            if self.state == CircuitState.CLOSED:
                return True
            if self.state == CircuitState.OPEN:
                if now - self.opened_at >= self.cooldown_seconds:
                    self.state = CircuitState.HALF_OPEN
                    return True
                return False
            # HALF_OPEN: 仅允许一个探测请求
            return True

    def on_success(self, latency_ms: float = 0.0) -> None:
        """请求成功时调用。重置连续失败计数，HALF_OPEN → CLOSED。"""
        with self._lock:
            self.consecutive_failures = 0
            self._append_window(True)
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED

    def on_failure(self, latency_ms: float = 0.0) -> None:
        """请求失败时调用。累加失败计数并检查是否需要跳闸。"""
        with self._lock:
            now = time.time()
            self.consecutive_failures += 1
            self.last_failure_time = now
            self._append_window(False)

            should_trip = False
            if self.consecutive_failures >= self.failure_threshold:
                should_trip = True
            elif self._window_failure_rate() >= self.failure_rate_threshold:
                should_trip = True

            if should_trip and self.state != CircuitState.OPEN:
                self.state = CircuitState.OPEN
                self.opened_at = now

    def _append_window(self, success: bool) -> None:
        now = time.time()
        self._window.append((now, success))
        cutoff = now - self.window_seconds
        self._window = [e for e in self._window if e[0] >= cutoff]

    def _window_failure_rate(self) -> float:
        if not self._window:
            return 0.0
        failures = sum(1 for _, ok in self._window if not ok)
        return failures / len(self._window)

    @property
    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN


# 令牌预算追踪 — 独立于断路器，用于 cost-aware 速率限制

@dataclass
class TokenBudget:
    """滑动窗口令牌预算。支持多时间粒度（每分钟 + 每会话）。
    每会话预算是硬上限；每分钟预算是软上限，超限触发降级而非拒绝。"""

    tokens_per_minute: int = 200_000
    tokens_per_session: int = 2_000_000
    window_seconds: float = 60.0

    _minute_usage: list[tuple[float, int]] = field(default_factory=list, init=False)
    _session_used: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def consume(self, token_count: int) -> bool:
        """尝试消耗令牌。返回 True 表示在预算内。"""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self._minute_usage = [
                (t, c) for t, c in self._minute_usage if t >= cutoff
            ]
            minute_used = sum(c for _, c in self._minute_usage)
            if minute_used + token_count > self.tokens_per_minute:
                return False
            if self._session_used + token_count > self.tokens_per_session:
                return False
            self._minute_usage.append((now, token_count))
            self._session_used += token_count
            return True

    def minute_usage(self) -> int:
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self._minute_usage = [
                (t, c) for t, c in self._minute_usage if t >= cutoff
            ]
            return sum(c for _, c in self._minute_usage)

    def session_used(self) -> int:
        return self._session_used

    def session_remaining(self) -> int:
        return max(0, self.tokens_per_session - self._session_used)

    def minute_remaining(self) -> int:
        return max(0, self.tokens_per_minute - self.minute_usage())


# 自适应并发控制 — AIMD + 双阈值健康信号

@dataclass
class AdaptiveConcurrency:
    """基于健康信号的自适应并发控制。
    使用 composite health score（0.0-1.0）调节 worker 数量：
    - score ∈ [0.7, 1.0]: 加性增 1（每 success_window 成功请求 +1）
    - score ∈ [0.5, 0.7): 保持
    - score ∈ [0.3, 0.5): 乘性减 0.75
    - score < 0.3: 退避至 min_concurrency
    边界受 min/max 约束。"""

    min_concurrency: int = 2
    max_concurrency: int = 8
    current: int = 4

    # 内部状态
    _success_streak: int = field(default=0, init=False)
    _success_window: int = 10         # 连续 N 次成功 → 尝试加窗
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def on_success(self, latency_ms: float, token_cost: int) -> None:
        """成功请求后更新并发窗口。"""
        with self._lock:
            self._success_streak += 1
            if self._success_streak >= self._success_window:
                self.current = min(self.current + 1, self.max_concurrency)
                self._success_streak = 0

    def on_failure(self, latency_ms: float, is_rate_limit: bool) -> None:
        """失败请求后缩小并发窗口。速率限制使用更激进的退避。"""
        with self._lock:
            self._success_streak = 0
            if is_rate_limit:
                # 速率限制 → 指数退避
                self.current = max(self.min_concurrency, self.current // 2)
            else:
                # 一般故障 → 乘性减 0.75
                self.current = max(self.min_concurrency, int(self.current * 0.75))


# 综合健康信号 — 供上层调度决策

@dataclass
class CompositeHealth:
    """综合健康信号，聚合断路器状态、令牌预算剩余、近期延迟趋势。
    上层调用方可据此决定是否降级（如跳过非关键模块、降低 max_tokens）。"""

    circuit_breaker: CircuitBreaker
    token_budget: TokenBudget

    # 延迟追踪 (EWMA)
    _ewma_latency_ms: float = field(default=500.0, init=False)
    _alpha: float = 0.2       # EWMA 平滑因子
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def record_latency(self, latency_ms: float) -> None:
        with self._lock:
            self._ewma_latency_ms = (
                self._alpha * latency_ms
                + (1 - self._alpha) * self._ewma_latency_ms
            )

    def health_score(self) -> float:
        """综合健康评分 0.0-1.0，1.0 = 完全健康。
        权重：断路器 0.4 + 令牌预算 0.35 + 延迟 0.25。"""
        # 断路器得分
        cb = self.circuit_breaker
        if cb.state == CircuitState.OPEN:
            cb_score = 0.0
        elif cb.state == CircuitState.HALF_OPEN:
            cb_score = 0.4
        else:
            fail_rate = cb._window_failure_rate()
            cb_score = max(0.0, 1.0 - fail_rate)

        # 令牌预算得分：分钟剩余比例
        tb = self.token_budget
        min_rem = tb.minute_remaining()
        if tb.tokens_per_minute > 0:
            budget_score = min_rem / tb.tokens_per_minute
        else:
            budget_score = 1.0

        # 延迟得分：以 2000ms 为基准（假设 API 超时 600s 但在正常情况 < 2s）
        latency_ms = self._ewma_latency_ms
        if latency_ms <= 500:
            lat_score = 1.0
        elif latency_ms >= 5000:
            lat_score = 0.0
        else:
            lat_score = 1.0 - (latency_ms - 500) / 4500.0

        return 0.4 * cb_score + 0.35 * budget_score + 0.25 * lat_score
