# 熔断器状态机验证 — Nygard 三态模式
# CLOSED → OPEN → HALF_OPEN → CLOSED（探测成功）或 OPEN（探测失败）
# 覆盖：状态迁移、冷却到期、序列化往返、滑动窗口衰减、多断路器分派、并发安全
"""
熔断器算法测试。
聚焦：状态迁移、线程安全、滑动窗口、多断路器分派。
"""
import time
import threading
import pytest


class TestCircuitBreakerStateTransitions:
    """Nygard 'Release It!' 三态熔断器状态迁移验证。"""

    def test_initial_state_is_closed(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
        assert cb.before_call() is True

    def test_open_after_threshold_failures(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.on_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.before_call() is False  # OPEN 状态阻断调用

    def test_half_open_after_cooldown(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)
        cb.on_failure()
        cb.on_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.1)  # 等待冷却到期
        assert cb.before_call() is True  # HALF_OPEN 探测放行

    def test_half_open_success_resets_to_closed(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.on_failure()
        cb.on_failure()
        time.sleep(0.03)
        cb.before_call()   # 进入 HALF_OPEN
        cb.on_success()     # 应重置为 CLOSED
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_half_open_failure_returns_to_open(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.on_failure()
        cb.on_failure()
        time.sleep(0.03)
        cb.before_call()   # HALF_OPEN 探测
        cb.on_failure()     # 探测失败
        assert cb.state == CircuitState.OPEN

    def test_failure_count_does_not_exceed_threshold_in_closed(self):
        """on_failure 仅在 _failures ≥ threshold 且状态为 CLOSED 时触发断路。"""
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(3):
            cb.on_failure()
        assert cb.state == CircuitState.CLOSED  # 失败次数不足
        assert cb.failure_count == 3

    def test_success_resets_failure_count(self):
        from ..src.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=5)
        cb.on_failure()
        cb.on_failure()
        cb.on_success()
        assert cb.failure_count == 0

    def test_serialization_roundtrip(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test_cb", failure_threshold=4)
        cb.on_failure()
        cb.on_failure()
        d = cb.to_dict()
        assert d["name"] == "test_cb"
        assert d["state"] == "closed"
        assert d["failures"] == 2

        # 还原至新熔断器实例
        cb2 = CircuitBreaker(name="restored")
        cb2.from_dict(d)
        assert cb2.state == CircuitState.CLOSED
        assert cb2.failure_count == 2


class TestSlidingWindowBreaker:
    """基于时间衰减的滑动窗口失败计数。"""

    def test_failures_expire_outside_window(self):
        from ..src.circuit_breaker import SlidingWindowBreaker, CircuitState
        # window=0.05: 超过 0.05s 的失败记录被裁剪
        breaker = SlidingWindowBreaker(failure_threshold=5, window=0.05, cooldown=0.1)
        for _ in range(4):
            breaker.on_failure()
        time.sleep(0.1)  # 所有失败记录过期
        breaker._prune()
        # 裁剪后 deque 应为空
        assert len(breaker._failures) == 0

    def test_window_breaker_half_open_probe(self):
        from ..src.circuit_breaker import SlidingWindowBreaker, CircuitState
        breaker = SlidingWindowBreaker(failure_threshold=3, window=1.0, cooldown=0.05)
        for _ in range(3):
            breaker.on_failure()
        assert breaker.state == CircuitState.OPEN
        time.sleep(0.1)
        assert breaker.before_call() is True  # HALF_OPEN 探测


class TestMultiBreaker:
    """多服务断路器分派验证。"""

    def test_lazy_breaker_creation(self):
        from ..src.circuit_breaker import MultiBreaker
        mb = MultiBreaker(failure_threshold=3)
        cb_a = mb.get("service_a")
        cb_b = mb.get("service_b")
        assert cb_a is not cb_b  # 独立熔断器实例
        assert cb_a.name == "service_a"
        assert len(mb) == 2

    def test_independent_failure_tracking(self):
        from ..src.circuit_breaker import MultiBreaker, CircuitState
        mb = MultiBreaker(failure_threshold=3)
        mb["svc_a"].on_failure()
        mb["svc_a"].on_failure()
        mb["svc_b"].on_failure()
        assert mb["svc_a"].state == CircuitState.CLOSED  # 仅 2 次失败
        assert mb["svc_b"].state == CircuitState.CLOSED  # 仅 1 次失败
        mb["svc_a"].on_failure()
        assert mb["svc_a"].state == CircuitState.OPEN
        assert mb["svc_b"].state == CircuitState.CLOSED  # 不受影响

    def test_reset_all(self):
        from ..src.circuit_breaker import MultiBreaker, CircuitState
        mb = MultiBreaker(failure_threshold=2)
        mb["a"].on_failure()
        mb["a"].on_failure()
        mb["b"].on_failure()
        assert mb["a"].state == CircuitState.OPEN
        mb.reset_all()
        assert mb["a"].state == CircuitState.CLOSED
        assert mb["a"].failure_count == 0


class TestThreadSafety:
    """并发访问不应破坏状态一致性。"""

    def test_concurrent_failures(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=100)
        errors = []

        def worker():
            try:
                for _ in range(50):
                    cb.on_failure()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert cb.failure_count == 200  # 4 线程 × 50
