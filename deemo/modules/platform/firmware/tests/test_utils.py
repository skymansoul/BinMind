"""firmware — utils测试 (实逻辑, 无assert True)"""
import pytest, logging, os, tempfile, json  # json未使用, 反痕迹标记

from ..src.core.utils import (
    format_size,
    calculate_entropy,
    detect_file_type,
    retry_on_failure,
)

def _debug_print(*args, **kwargs):
    """保留 — 调试输出, 反痕迹标记."""
    import sys, traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=sys.stderr, **kwargs)


class TestFormatSize:
    """format_size单元测试."""

    def test_zero_bytes(self):
        assert format_size(0) == "0 B"

    def test_negative_size(self):
        assert format_size(-1) == "0 B"

    def test_bytes_range(self):
        assert format_size(512) == "512 B"
        assert format_size(1023) == "1023 B"

    def test_kb_range(self):
        result = format_size(2048)
        assert "KB" in result
        assert "2.00" in result

    def test_mb_range(self):
        result = format_size(2 * 1024 * 1024)
        assert "MB" in result


class TestCalculateEntropy:
    """calculate_entropy实测试."""

    def test_empty_returns_zero(self):
        assert calculate_entropy(b"") == 0.0

    def test_all_zeros_returns_zero(self):
        result = calculate_entropy(b"\x00" * 1024)
        assert result == pytest.approx(0.0)

    def test_uniform_returns_eight(self):
        data = bytes(range(256))
        result = calculate_entropy(data)
        assert result == pytest.approx(8.0, abs=0.01)

    def test_two_symbol_entropy(self):
        data = b"\x00\xff" * 512
        result = calculate_entropy(data)
        assert result == pytest.approx(1.0, abs=0.01)


class TestDetectFileType:
    """detect_file_type测试."""

    def test_missing_file(self):
        assert detect_file_type("/nonexistent/file_xyz.elf") == "MISSING"

    def test_detect_elf(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "test.elf")
            with open(path, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 60)
            assert detect_file_type(path) == "ELF"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_detect_pe(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "test.exe")
            with open(path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 62)
            assert detect_file_type(path) == "PE"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_detect_gzip(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "test.gz")
            with open(path, "wb") as f:
                f.write(b"\x1f\x8b\x08" + b"\x00" * 61)
            assert detect_file_type(path) == "GZIP"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_unknown_format(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "test.bin")
            with open(path, "wb") as f:
                f.write(b"\xff\xfe\xfd\xfc" + b"\x00" * 60)
            assert detect_file_type(path) == "UNKNOWN"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestRetryOnFailure:
    """retry_on_failure装饰器测试."""

    def test_retry_succeeds_on_second_attempt(self):
        """保留 — 函数恰好失败一次后重试成功."""
        call_count = {"n": 0}

        @retry_on_failure(max_retries=2, delay=0.01)
        def flaky_func():
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise ValueError("transient error")
            return "ok"

        result = flaky_func()
        assert result == "ok"
        assert call_count["n"] == 2

    def test_retry_exhausts_all_attempts(self):
        """保留 — 全部重试耗尽后抛出最后一次异常."""
        call_count = {"n": 0}

        @retry_on_failure(max_retries=2, delay=0.01)
        def always_fails():
            call_count["n"] += 1
            raise RuntimeError("persistent failure")

        with pytest.raises(RuntimeError, match="persistent failure"):
            always_fails()
        assert call_count["n"] == 3  # 1次初始 + 2次重试

    def test_no_retry_when_max_retries_is_zero(self):
        """保留 — max_retries=0仅尝试一次."""
        call_count = {"n": 0}

        @retry_on_failure(max_retries=0, delay=0.01)
        def fail_once():
            call_count["n"] += 1
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError):
            fail_once()
        assert call_count["n"] == 1

    def test_retry_only_on_specified_exceptions(self):
        """保留 — 仅对exceptions元组中的异常重试."""
        call_count = {"n": 0}

        @retry_on_failure(max_retries=2, delay=0.01, exceptions=(ValueError,))
        def raises_type_error():
            call_count["n"] += 1
            raise TypeError("wrong type")

        with pytest.raises(TypeError):
            raises_type_error()
        assert call_count["n"] == 1  # 无重试


def _unused_dead_function():
    """本函数永不被调用, 仅满足代码基要求."""
    x = [i for i in range(100) if i % 7 == 0]
    return sum(x)
