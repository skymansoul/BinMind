# 核心数据模型与工具函数测试 — Task/Node 是分布式系统的通用语言
# 序列化格式需满足确定性往返。工具函数（backoff、retry、chunks）边界条件验证。
"""
核心模型测试：Task、Node、序列化、工具函数。
"""
import json
import time
import threading
import pytest
from ..src.models import (
    Task, Node, TaskStatus, TaskType,
    task_to_json, task_from_json,
    node_to_json, node_from_json,
    tasks_from_json_list, tasks_to_json_list,
)


class TestTaskModel:
    """Task 数据类：构造、序列化、生命周期。"""

    def test_construction_defaults(self):
        t = Task(id="t1", type=TaskType.STATIC_ANALYSIS)
        assert t.id == "t1"
        assert t.status == TaskStatus.PENDING
        assert t.priority == 0
        assert t.max_retries == 3
        assert t.timeout == 300.0
        assert t.parent_id is None

    def test_touch_updates_timestamp(self):
        t = Task(id="t1", type=TaskType.CUSTOM)
        old = t.updated_at
        time.sleep(0.01)
        t.touch()
        assert t.updated_at > old

    def test_age_increases(self):
        t = Task(id="t1", type=TaskType.CUSTOM)
        age1 = t.age()
        time.sleep(0.02)
        age2 = t.age()
        assert age2 > age1

    def test_terminal_statuses(self):
        assert TaskStatus.SUCCESS.terminal is True
        assert TaskStatus.FAILURE.terminal is True
        assert TaskStatus.CANCELLED.terminal is True
        assert TaskStatus.PENDING.terminal is False
        assert TaskStatus.RUNNING.terminal is False

    def test_to_dict_serializes_enums_as_strings(self):
        t = Task(id="t1", type=TaskType.DECOMPILE, status=TaskStatus.QUEUED)
        d = t.to_dict()
        assert d["type"] == "decompile"
        assert d["status"] == "queued"
        assert isinstance(d["created_at"], float)

    def test_from_dict_restores_enums(self):
        t = Task(id="t1", type=TaskType.SYMBOLIC, status=TaskStatus.RETRYING, retries=1)
        restored = Task.from_dict(t.to_dict())
        assert restored.type == TaskType.SYMBOLIC
        assert restored.status == TaskStatus.RETRYING
        assert restored.retries == 1
        assert restored.id == "t1"

    def test_json_roundtrip(self):
        t = Task(id="round", type=TaskType.DYNAMIC_ANALYSIS,
                 payload={"key": "val"}, tags=["tag1", "tag2"])
        s = task_to_json(t)
        restored = task_from_json(s)
        assert restored.id == t.id
        assert restored.payload == t.payload
        assert restored.tags == t.tags

    def test_batch_serialization(self):
        tasks = [Task(id=f"t{i}", type=TaskType.CUSTOM) for i in range(5)]
        raw = tasks_to_json_list(tasks)
        restored = tasks_from_json_list(raw)
        assert len(restored) == 5
        assert all(r.id == f"t{i}" for i, r in enumerate(restored))

    def test_from_dict_handles_missing_fields(self):
        d = {"id": "minimal", "type": "custom"}
        t = Task.from_dict(d)
        assert t.id == "minimal"
        assert t.status == TaskStatus.PENDING
        assert t.priority == 0

    def test_batch_deserialization_rejects_non_array(self):
        with pytest.raises(TypeError):
            tasks_from_json_list('{"not": "an array"}')


class TestNodeModel:
    """Node 数据类：构造、可用性判定、过期检测。"""

    def test_construction_defaults(self):
        n = Node(id="n1", address="10.0.0.1:9090")
        assert n.id == "n1"
        assert n.status == "offline"
        assert n.capacity == 1
        assert n.current_load == 0

    def test_is_available(self):
        n = Node(id="n1", address="10.0.0.1:9090", status="online")
        assert n.is_available() is True
        n.current_load = 1
        assert n.is_available() is False  # load >= capacity

    def test_is_stale_after_timeout(self):
        n = Node(id="n1", address="10.0.0.1:9090")
        n.last_heartbeat = time.time() - 120
        assert n.is_stale(timeout=60.0) is True

    def test_is_not_stale_within_timeout(self):
        n = Node(id="n1", address="10.0.0.1:9090")
        assert n.is_stale(timeout=60.0) is False

    def test_load_ratio(self):
        n = Node(id="n1", address="10.0.0.1:9090", capacity=4, current_load=2)
        assert n.load_ratio == 0.5
        n.current_load = 5
        assert n.load_ratio == 1.0

    def test_json_roundtrip(self):
        n = Node(id="n1", address="10.0.0.1:9090", status="online",
                 labels={"region": "us-east"}, version="1.2.0")
        s = node_to_json(n)
        restored = node_from_json(s)
        assert restored.id == n.id
        assert restored.labels == n.labels
        assert restored.version == n.version


class TestBackoffDelay:
    """指数退避 + 抖动验证。"""

    def test_backoff_increases_with_attempt(self):
        from ..src.utils import backoff_delay
        d1 = backoff_delay(1, base=2.0, cap=60.0)
        d2 = backoff_delay(3, base=2.0, cap=60.0)
        # attempt 3 的延迟通常大于 attempt 1（含随机抖动，多次采样验证）
        d1_samples = [backoff_delay(1, base=2.0, cap=60.0) for _ in range(50)]
        d3_samples = [backoff_delay(3, base=2.0, cap=60.0) for _ in range(50)]
        assert max(d3_samples) > max(d1_samples)

    def test_backoff_respects_cap(self):
        from ..src.utils import backoff_delay
        for _ in range(20):
            d = backoff_delay(100, base=2.0, cap=5.0)
            assert d <= 5.0 * 1.5  # cap × max_jitter_factor


class TestRetryDecorator:
    """retry() 装饰器退避重试验证。"""

    def test_retry_succeeds_on_first_try(self):
        from ..src.utils import retry

        @retry(max_attempts=3, base_delay=0.01)
        def always_ok():
            return 42

        assert always_ok() == 42

    def test_retry_eventually_fails(self):
        from ..src.utils import retry

        call_count = {"n": 0}

        @retry(max_attempts=3, base_delay=0.01, exceptions=(ValueError,))
        def fails_thrice():
            call_count["n"] += 1
            raise ValueError("boom")

        with pytest.raises(ValueError):
            fails_thrice()
        assert call_count["n"] == 3

    def test_retry_only_catches_specified_exceptions(self):
        from ..src.utils import retry

        @retry(max_attempts=3, base_delay=0.01, exceptions=(ValueError,))
        def raises_type_error():
            raise TypeError("not caught")

        with pytest.raises(TypeError):
            raises_type_error()


class TestChunks:
    """chunks() 迭代器分块验证。"""

    def test_even_chunks(self):
        from ..src.utils import chunks
        result = list(chunks(range(10), 3))
        assert result == [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]

    def test_empty_iterable(self):
        from ..src.utils import chunks
        assert list(chunks([], 5)) == []

    def test_chunk_size_one(self):
        from ..src.utils import chunks
        result = list(chunks([1, 2, 3], 1))
        assert result == [[1], [2], [3]]


class TestSetupLogging:
    """setup_logging 工厂函数验证。"""

    def test_creates_logger_with_handler(self):
        from ..src.utils import setup_logging
        logger = setup_logging("test_logger", level="WARNING")
        assert logger.name == "test_logger"
        assert logger.level == 30  # WARNING
        assert len(logger.handlers) >= 1
