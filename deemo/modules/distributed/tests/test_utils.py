# 工具与序列化测试
# utils.py 提供 retry/backoff/logging/memoize/chunks。
# serialization.py 处理 JSON/msgpack/gzip/lz4。两者必须在
# 边界条件下正确：空输入、大输入、格式检测。
"""工具与序列化测试。"""
import json
import time
import pytest
from ..src.serialization import (
    serialize, deserialize,
    serialize_stream, deserialize_stream,
    _detect_format, _detect_compression,
)


class TestSerialization:
    """JSON/msgpack 往返序列化。"""

    def test_json_roundtrip(self):
        data = {"key": "value", "nested": [1, 2, 3]}
        raw = serialize(data, fmt="json")
        restored = deserialize(raw, fmt="json")
        assert restored == data

    def test_json_with_gzip(self):
        data = {"large": "x" * 1000}
        raw = serialize(data, fmt="json", compress="gzip")
        restored = deserialize(raw)
        assert restored == data

    def test_format_detection_json(self):
        raw = b'{"hello": "world"}'
        assert _detect_format(raw) == "json"

    def test_format_detection_empty(self):
        assert _detect_format(b"") == "json"

    def test_compression_detection_gzip(self):
        import gzip
        raw = gzip.compress(b"test data")
        assert _detect_compression(raw) == "gzip"

    def test_compression_detection_none(self):
        assert _detect_compression(b"plain text") is None


class TestSerializationStream:
    """流式 (JSONL) 序列化。"""

    def test_stream_roundtrip(self):
        items = [{"i": i} for i in range(10)]
        chunks = list(serialize_stream(iter(items), fmt="json"))
        restored = list(deserialize_stream(iter(chunks), fmt="json"))
        assert restored == items

    def test_empty_stream(self):
        assert list(serialize_stream(iter([]))) == []
        assert list(deserialize_stream(iter([]))) == []


class TestMemoize:
    """memoize 装饰器。"""

    def test_caches_results(self):
        from ..src.utils import memoize
        calls = []

        @memoize(maxsize=10)
        def expensive(x):
            calls.append(x)
            return x * 2

        assert expensive(5) == 10
        assert expensive(5) == 10  # 已缓存
        assert len(calls) == 1  # 仅调用一次

    def test_cache_clear(self):
        from ..src.utils import memoize
        calls = []

        @memoize(maxsize=10)
        def fn(x):
            calls.append(x)
            return x

        fn(1)
        fn.cache_clear()
        fn(1)
        assert len(calls) == 2


class TestWorkerConfig:
    """WorkerConfig 默认值与优先级层级设置。"""

    def test_default_config(self):
        from ..worker_v1 import WorkerConfig
        cfg = WorkerConfig()
        assert cfg.queue == "binmind:tasks"
        assert cfg.poll_timeout == 5
        assert cfg.max_retries == 3
        assert cfg.max_workers == 4
        assert cfg.job_timeout == 300
        assert cfg.breaker_threshold == 5
        assert cfg.priority_tiers == {}

    def test_custom_config(self):
        from ..worker_v1 import WorkerConfig
        cfg = WorkerConfig(
            redis_url="redis://custom:6379/2",
            queue="my:tasks",
            max_workers=8,
            priority_tiers={"high": 5, "low": 1},
        )
        assert cfg.redis_url == "redis://custom:6379/2"
        assert cfg.queue == "my:tasks"
        assert cfg.max_workers == 8
        assert cfg.priority_tiers == {"high": 5, "low": 1}
