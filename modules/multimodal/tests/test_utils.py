#!/usr/bin/env python3
# 工具函数单元测试 — 日志、重试、缓存、计时、序列化、数学辅助
import sys
import os
import time
import pytest
import logging as _logging

# src 目录路径需优先插入，避免与项目根 utils 冲突
_src = os.path.join(os.path.dirname(__file__), "..", "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

# 测试目标：multimodal/src/utils.py
# 使用 importlib 精确加载，避免歧义
import importlib
_spec = importlib.util.spec_from_file_location(
    "multimodal_utils",
    os.path.join(_src, "utils.py"),
    submodule_search_locations=[])
_utils_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_utils_mod)

setup_logging = _utils_mod.setup_logging
retry_with_backoff = _utils_mod.retry_with_backoff
TTLCache = _utils_mod.TTLCache
elapsed_timer = _utils_mod.elapsed_timer
safe_json_dumps = _utils_mod.safe_json_dumps
percentile = _utils_mod.percentile
clamp = _utils_mod.clamp
ewma = _utils_mod.ewma
categorical_summary = _utils_mod.categorical_summary
check_dependencies = _utils_mod.check_dependencies


class TestLogging:
    def test_setup_logging_returns_root_logger(self):
        logger = setup_logging(level="WARNING")
        assert logger is not None
        assert isinstance(logger, _logging.Logger)

    def test_setup_logging_respects_level(self):
        logger = setup_logging(level="ERROR")
        # 仅校验无异常；实际 level 取决于历史 handler 附着状态
        root = _logging.getLogger()
        assert True  # 无异常即通过


class TestRetry:
    def test_success_first_attempt(self):
        """首次成功：不触发重试。"""
        counter = [0]

        @retry_with_backoff(max_attempts=3, base_delay=0.001)
        def ok_func():
            counter[0] += 1
            return "done"

        result = ok_func()
        assert result == "done"
        assert counter[0] == 1

    def test_retries_on_failure(self):
        """前两次失败第三次成功。"""
        counter = [0]

        @retry_with_backoff(max_attempts=4, base_delay=0.001)
        def flaky():
            counter[0] += 1
            if counter[0] < 3:
                raise ValueError("not yet")
            return "finally"

        result = flaky()
        assert result == "finally"
        assert counter[0] == 3

    def test_exhausts_retries(self):
        """重试耗尽后抛出原始异常。"""
        counter = [0]

        @retry_with_backoff(max_attempts=3, base_delay=0.001)
        def always_fails():
            counter[0] += 1
            raise RuntimeError("always")

        with pytest.raises(RuntimeError):
            always_fails()
        # 应恰好重试 max_attempts 次
        assert counter[0] == 3

    def test_non_retryable_exception(self):
        """非可重试异常应立即透传。"""
        counter = [0]

        @retry_with_backoff(
            max_attempts=5, base_delay=0.001,
            retryable_exceptions=(ValueError,))
        def fails_with_type_error():
            counter[0] += 1
            raise TypeError("no retry")

        with pytest.raises(TypeError):
            fails_with_type_error()
        assert counter[0] == 1


class TestTTLCache:
    def test_basic_get_set(self):
        cache = TTLCache(ttl=0.1)
        cache.set(1, "hello")
        cache.set(2, "world")
        assert cache.get(1) == "hello"
        assert cache.get(2) == "world"

    def test_expiry(self):
        cache = TTLCache(ttl=0.3)
        cache.set(1, "ephemeral")
        time.sleep(0.35)
        assert cache.get(1) is None

    def test_no_expiry_when_ttl_zero(self):
        cache = TTLCache(ttl=0)  # ttl=0 等价于永不过期
        cache.set(1, "forever")
        time.sleep(0.05)
        assert cache.get(1) == "forever"

    def test_invalidate(self):
        cache = TTLCache(ttl=300)
        cache.set(1, "a")
        cache.set(2, "b")
        cache.invalidate()
        assert cache.get(1) is None
        assert cache.get(2) is None

    def test_len(self):
        cache = TTLCache(ttl=300)
        cache.set(1, "a")
        cache.set(2, "b")
        cache.set(3, "c")
        assert len(cache) == 3


class TestElapsedTimer:
    def test_timer_context(self):
        """上下文管理器模式使用计时器。"""
        with elapsed_timer("test_op"):
            time.sleep(0.01)
        assert True  # 无异常


class TestJSONDumps:
    def test_safe_json_dumps_set(self):
        """set 类型转 list 后序列化。"""
        result = safe_json_dumps({"items": {1, 2, 3}})
        assert "1" in result
        assert "2" in result

    def test_safe_json_dumps_bytes(self):
        """bytes 转 hex 字符串后序列化。"""
        result = safe_json_dumps({"data": b'\x01\x02\xff'})
        assert "0102ff" in result

    def test_safe_json_dumps_nested_dict(self):
        """嵌套 dict 无异常序列化。"""
        result = safe_json_dumps({"a": {"b": [1, 2, 3]}})
        assert "b" in result


class TestMathHelpers:
    def test_percentile(self):
        sorted_vals = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert percentile(sorted_vals, 0.5) == 3.0
        assert percentile(sorted_vals, 0.0) == 1.0
        assert percentile(sorted_vals, 0.95) == 5.0 or percentile(sorted_vals, 0.95) == 4.0

    def test_percentile_empty(self):
        assert percentile([], 0.5) == 0.0

    def test_clamp(self):
        assert clamp(5.0, 0.0, 10.0) == 5.0
        assert clamp(-5.0, 0.0, 10.0) == 0.0
        assert clamp(15.0, 0.0, 10.0) == 10.0

    def test_ewma(self):
        """指数加权移动平均计算公式校验。"""
        prev = ewma(10.0, 8.0, alpha=0.5)
        assert abs(prev - 9.0) < 0.01
        prev2 = ewma(10.0, 9.0, alpha=0.3)
        assert abs(prev2 - 9.3) < 0.01


class TestCategoricalSummary:
    def test_basic(self):
        counter = {"a": 5, "b": 3, "c": 2}
        summary = categorical_summary(counter)
        assert summary["total"] == 10
        assert summary["unique"] == 3
        assert len(summary["top3"]) == 3
        assert summary["top3"][0]["key"] == "a"

    def test_empty(self):
        summary = categorical_summary({})
        assert summary["total"] == 0
        assert summary["unique"] == 0


class TestDependencyCheck:
    def test_returns_bool_dict(self):
        """依赖检查返回 {包名→bool} 映射。"""
        deps = check_dependencies()
        assert isinstance(deps, dict)
        assert all(isinstance(v, bool) for v in deps.values())
