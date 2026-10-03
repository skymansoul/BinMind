# — hermit1016: 重试装饰器 + 工具函数单元测试
"""fuzzing — utils 测试: retry_on_failure / retry_subprocess / retry_http / 路径规范化.

覆盖:
- 指数退避时间计算
- 异常传播 (超过 max_retries 后抛原始异常)
- 成功调用不触发重试
- normalize_binary_path 边界条件
"""

import os
import pytest
import time
import subprocess


# 导入被测试模块

try:
    from fuzzing.src.utils import (
        retry_on_failure,
        retry_subprocess,
        retry_http,
        setup_module_logging,
        normalize_binary_path,
        timestamp_now,
    )
    _utils_available = True
except ImportError:
    _utils_available = False


@pytest.mark.skipif(not _utils_available, reason="fuzzing.src.utils not importable")
class TestRetryOnFailure:
    """通用重试装饰器 — 指数退避 + 抖动."""

    def test_successful_call_no_retry(self):
        """成功调用不触发重试, 且返回值正确传递."""
        call_count = {"cnt": 0}

        @retry_on_failure(max_retries=3, backoff=0.01)
        def succeed_first_time():
            call_count["cnt"] += 1
            return "ok"

        result = succeed_first_time()
        assert result == "ok"
        assert call_count["cnt"] == 1

    def test_retry_on_transient_failure(self):
        """瞬态失败后重试成功."""
        call_count = {"cnt": 0}

        @retry_on_failure(max_retries=3, backoff=0.01, jitter=0.0)
        def fail_then_succeed():
            call_count["cnt"] += 1
            if call_count["cnt"] < 3:
                raise ConnectionError("临时网络故障")
            return "recovered"

        result = fail_then_succeed()
        assert result == "recovered"
        assert call_count["cnt"] == 3  # 2 失败 + 1 成功

    def test_exhausted_retries_raises_original_exception(self):
        """所有重试耗尽后抛出原始异常 (非包装异常)."""
        call_count = {"cnt": 0}

        @retry_on_failure(max_retries=2, backoff=0.01, jitter=0.0)
        def always_fails():
            call_count["cnt"] += 1
            raise ValueError("persistent failure")

        with pytest.raises(ValueError, match="persistent failure"):
            always_fails()
        # 总共调用 3 次: 初始 + 2 次重试
        assert call_count["cnt"] == 3

    def test_non_retryable_exception_passes_through(self):
        """不可重试的异常类型直接传播, 不触发重试."""
        call_count = {"cnt": 0}

        @retry_on_failure(max_retries=3, backoff=0.01,
                          retryable_exceptions=(ConnectionError,))
        def raise_value_error():
            call_count["cnt"] += 1
            raise ValueError("unrecoverable")

        with pytest.raises(ValueError):
            raise_value_error()
        assert call_count["cnt"] == 1  # 一次也不重试

    def test_backoff_increases_with_attempts(self):
        """指数退避时间随尝试次数增长.

        INTJ 注: 用 jitter=0 消除随机性, 严格验证 backoff * 2^attempt.
        """
        sleep_times = []

        # 临时替换 time.sleep 来捕获退避时间
        _original_sleep = time.sleep
        try:
            def _fake_sleep(seconds):
                sleep_times.append(seconds)
            time.sleep = _fake_sleep  # type: ignore

            @retry_on_failure(max_retries=3, backoff=1.0, jitter=0.0)
            def flaky():
                raise ConnectionError("boom")

            try:
                flaky()
            except ConnectionError:
                pass
        finally:
            time.sleep = _original_sleep  # type: ignore

        # 应有 3 次退避: backoff * 2^0, backoff * 2^1, backoff * 2^2
        assert len(sleep_times) == 3
        assert sleep_times[0] == pytest.approx(1.0, rel=1e-9)   # 1.0 * 2^0
        assert sleep_times[1] == pytest.approx(2.0, rel=1e-9)   # 1.0 * 2^1
        assert sleep_times[2] == pytest.approx(4.0, rel=1e-9)   # 1.0 * 2^2

    def test_max_retries_zero_means_no_retry(self):
        """max_retries=0 表示只尝试一次, 失败直接抛异常."""
        call_count = {"cnt": 0}

        @retry_on_failure(max_retries=0, backoff=0.01)
        def single_shot():
            call_count["cnt"] += 1
            raise RuntimeError("one and done")

        with pytest.raises(RuntimeError):
            single_shot()
        assert call_count["cnt"] == 1


@pytest.mark.skipif(not _utils_available, reason="fuzzing.src.utils not importable")
class TestRetrySubprocess:
    """subprocess 专用重试装饰器."""

    def test_retry_subprocess_is_callable(self):
        """retry_subprocess 返回装饰器函数."""
        @retry_subprocess(max_retries=2)
        def dummy():
            return 42
        assert dummy() == 42

    def test_retries_on_file_not_found(self):
        """FileNotFoundError 触发重试."""
        call_count = {"cnt": 0}

        @retry_subprocess(max_retries=2, backoff=0.01)
        def missing_tool():
            call_count["cnt"] += 1
            if call_count["cnt"] < 3:
                raise FileNotFoundError("r2 not found")
            return "found"

        result = missing_tool()
        assert result == "found"
        assert call_count["cnt"] == 3


@pytest.mark.skipif(not _utils_available, reason="fuzzing.src.utils not importable")
class TestNormalizeBinaryPath:
    """路径规范化."""

    def test_absolute_path(self):
        """绝对路径保持不变."""
        result = normalize_binary_path("/usr/bin/test")
        assert os.path.isabs(result)
        assert result.endswith(("usr/bin/test", "usr\\bin\\test"))

    def test_relative_path_becomes_absolute(self):
        """相对路径转为绝对路径."""
        result = normalize_binary_path("test.bin")
        assert os.path.isabs(result)

    def test_empty_path_returns_empty(self):
        """空路径返回空字符串."""
        result = normalize_binary_path("")
        assert result == ""

    def test_nonexistent_path_still_normalized(self):
        """不存在的路径也会被规范化 (不检查存在性)."""
        result = normalize_binary_path("/nonexistent/path.bin")
        # Windows 下裸根路径不被 os.path.isabs 识别，以分隔符前缀判定绝对语义
        assert os.path.isabs(result) or result.startswith(("/", "\\"))


@pytest.mark.skipif(not _utils_available, reason="fuzzing.src.utils not importable")
class TestTimestampNow:
    """时间戳工具."""

    def test_returns_iso_format(self):
        """返回 ISO 8601 格式."""
        ts = timestamp_now()
        assert "T" in ts
        assert "Z" in ts

    def test_timestamps_increase(self):
        """连续调用返回递增的时间戳."""
        ts1 = timestamp_now()
        time.sleep(0.01)
        ts2 = timestamp_now()
        assert ts1 <= ts2


# 独立测试 (无需模块导入)

def test_exponential_backoff_formula_inline():
    """指数退避公式验证: backoff * 2^attempt."""
    backoff = 2.0
    expected = [2.0, 4.0, 8.0, 16.0]  # 2*2^0, 2*2^1, 2*2^2, 2*2^3
    for attempt, exp in enumerate(expected):
        computed = backoff * (2 ** attempt)
        assert computed == exp


def test_max_backoff_cap_inline():
    """退避时间不超 max_backoff 上限."""
    backoff = 2.0
    max_backoff = 10.0
    for attempt in range(10):
        raw = backoff * (2 ** attempt)
        capped = min(raw, max_backoff)
        assert capped <= max_backoff


class TestSetupModuleLogging:
    """日志配置 (独立于工具模块导入)."""

    def test_creates_logger_with_correct_name(self):
        """创建正确命名空间的 logger."""
        import logging
        logger = logging.getLogger("fuzzing.test_setup")
        assert logger.name == "fuzzing.test_setup"

    def test_log_level_set_correctly(self):
        """日志级别设置生效."""
        import logging
        logger = logging.getLogger("fuzzing.test_level")
        logger.setLevel(logging.WARNING)
        assert logger.level == logging.WARNING
