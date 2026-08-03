# 幂等性与优先级队列测试 — IdempotencyKey 基于 SHA256(sorted JSON) 确定性构造
# PriorityTaskQueue 基于 heapq，O(log n) 复杂度；DeadLetterQueue 为有界循环缓冲
# 两者共同支撑 exactly-once 语义与负载下的公平调度
"""
幂等性与优先级队列测试。
"""
import pytest
from ..src.idempotency import idempotency_key, IdempotencyGuard
from ..src.priority import PriorityTaskQueue, DeadLetterQueue


class TestIdempotencyKey:
    """确定性键构造验证。"""

    def test_same_args_same_key(self):
        k1 = idempotency_key("analyze", "binary.exe", {"timeout": 30})
        k2 = idempotency_key("analyze", "binary.exe", {"timeout": 30})
        assert k1 == k2
        assert len(k1) == 64  # SHA256 十六进制摘要长度

    def test_different_args_different_key(self):
        k1 = idempotency_key("analyze", "a.exe")
        k2 = idempotency_key("analyze", "b.exe")
        assert k1 != k2

    def test_kwargs_order_independent(self):
        k1 = idempotency_key("task", a=1, b=2)
        k2 = idempotency_key("task", b=2, a=1)
        assert k1 == k2

    def test_type_affects_key(self):
        k1 = idempotency_key("type_a", "data")
        k2 = idempotency_key("type_b", "data")
        assert k1 != k2


class TestIdempotencyGuardLocal:
    """本地 LRU 回退（无 Redis）。"""

    def test_first_call_returns_none(self):
        guard = IdempotencyGuard(redis_client=None)
        result = guard.execute_once("key1", lambda x: x * 2, 21)
        assert result == 42

    def test_repeated_call_returns_none(self):
        guard = IdempotencyGuard(redis_client=None)
        guard.execute_once("key2", lambda: "first")
        result = guard.execute_once("key2", lambda: "second")
        assert result is None  # 已处理，跳过

    def test_mark_processed_first_time(self):
        guard = IdempotencyGuard(redis_client=None)
        assert guard.mark_processed("fresh_key") is True
        assert guard.mark_processed("fresh_key") is False

    def test_is_duplicate_after_mark(self):
        guard = IdempotencyGuard(redis_client=None)
        guard.mark_processed("dup_check")
        assert guard.is_duplicate("dup_check") is True
        assert guard.is_duplicate("never_seen") is False

    def test_clear_removes_record(self):
        guard = IdempotencyGuard(redis_client=None)
        guard.mark_processed("temp_key")
        assert guard.is_duplicate("temp_key") is True
        guard.clear("temp_key")
        assert guard.is_duplicate("temp_key") is False

    def test_lru_eviction(self):
        guard = IdempotencyGuard(redis_client=None, local_capacity=5)
        for i in range(10):
            guard.mark_processed(f"key_{i}")
        # key_0 至 key_4 应已 FIFO 淘汰
        # key_5 至 key_9 应仍存在
        assert guard.is_duplicate("key_0") is False  # 已淘汰
        assert guard.is_duplicate("key_9") is True   # 仍存在


class TestPriorityTaskQueue:
    """最小堆优先级队列验证。"""

    def test_higher_priority_pops_first(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        pq.push(FakeTask("low"), priority=10)
        pq.push(FakeTask("high"), priority=1)
        pq.push(FakeTask("mid"), priority=5)

        assert pq.pop().id == "high"
        assert pq.pop().id == "mid"
        assert pq.pop().id == "low"

    def test_same_priority_fifo_order(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        pq.push(FakeTask("first"), priority=0)
        pq.push(FakeTask("second"), priority=0)
        pq.push(FakeTask("third"), priority=0)

        assert [pq.pop().id for _ in range(3)] == ["first", "second", "third"]

    def test_pop_empty_returns_none(self):
        pq = PriorityTaskQueue()
        assert pq.pop() is None

    def test_len_reflects_unique_tasks(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        for i in range(5):
            pq.push(FakeTask(f"t{i}"))
        assert len(pq) == 5
        pq.pop()
        assert len(pq) == 4

    def test_remove_cancels_task(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        pq.push(FakeTask("keep"))
        pq.push(FakeTask("cancel"))
        assert pq.remove("cancel") is True
        assert pq.remove("nonexistent") is False
        assert len(pq) == 1

    def test_contains(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        pq.push(FakeTask("in_queue"))
        assert "in_queue" in pq
        assert "not_in_queue" not in pq

    def test_pop_batch(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        for i in range(10):
            pq.push(FakeTask(f"t{i}"), priority=i)
        batch = pq.pop_batch(3)
        assert len(batch) == 3
        assert [t.id for t in batch] == ["t0", "t1", "t2"]
        assert len(pq) == 7

    def test_peek_does_not_remove(self):
        from dataclasses import dataclass

        @dataclass
        class FakeTask:
            id: str

        pq = PriorityTaskQueue()
        pq.push(FakeTask("peek_me"))
        assert pq.peek().id == "peek_me"
        assert len(pq) == 1  # peek 不移除


class TestDeadLetterQueue:
    """有界循环缓冲死信队列验证。"""

    def test_push_and_pop(self):
        dlq = DeadLetterQueue(max_size=100)
        dlq.push("task1", "timeout")
        dlq.push("task2", "oom")
        item, reason = dlq.pop()
        assert item == "task1"
        assert reason == "timeout"

    def test_fifo_order(self):
        dlq = DeadLetterQueue(max_size=100)
        for i in range(5):
            dlq.push(f"task_{i}", "error")
        items = []
        while len(dlq) > 0:
            items.append(dlq.pop()[0])
        assert items == [f"task_{i}" for i in range(5)]

    def test_max_size_eviction(self):
        dlq = DeadLetterQueue(max_size=3)
        dlq.push("a", "err")
        dlq.push("b", "err")
        dlq.push("c", "err")
        dlq.push("d", "err")  # 淘汰 "a"
        assert dlq.pop()[0] == "b"  # "a" 已移除

    def test_peek_does_not_remove(self):
        dlq = DeadLetterQueue(max_size=10)
        dlq.push("item", "reason")
        peeked = dlq.peek(5)
        assert len(peeked) == 1
        assert len(dlq) == 1

    def test_retry_all(self):
        dlq = DeadLetterQueue(max_size=10)
        dlq.push("task_a", "timeout")
        dlq.push("task_b", "crash")
        retried = []

        dlq.retry_all(lambda t: retried.append(t))
        assert retried == ["task_a", "task_b"]
        assert len(dlq) == 0
