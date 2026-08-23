# tests for binary_analysis 工具函数

import pytest
import os
import tempfile
from modules.analysis.static.binary_analysis.src.utils.helpers import atomic_write, retry, dig
from modules.analysis.static.binary_analysis.src.utils.errors import AnalysisError


class TestAtomicWrite:
    """安全持久化的原子文件写入"""

    def test_basic_write(self):
        """写入 a file atomically"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.txt")
            atomic_write(path, b"hello world")
            assert os.path.exists(path)
            with open(path, "rb") as f:
                assert f.read() == b"hello world"

    def test_overwrite(self):
        """Atomic overwrite existing file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.txt")
            atomic_write(path, b"version 1")
            atomic_write(path, b"version 2")
            with open(path, "rb") as f:
                assert f.read() == b"version 2"

    def test_large_write(self):
        """Atomic 写入 larger binary data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "large.bin")
            data = b'\x00' * 1024 * 1024  # 1MB
            atomic_write(path, data)
            assert os.path.getsize(path) == len(data)


class TestRetry:
    """重试 decorator for transient failures"""

    def test_retry_success(self):
        """Function succeeds first try"""
        call_count = [0]

        @retry(max_attempts=3)
        def succeed():
            call_count[0] += 1
            return "ok"

        result = succeed()
        assert result == "ok"
        assert call_count[0] == 1

    def test_retry_eventual_success(self):
        """Function succeeds second try"""
        call_count = [0]

        @retry(max_attempts=3, delay=0)
        def fail_once():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("transient error")
            return "recovered"

        result = fail_once()
        assert result == "recovered"
        assert call_count[0] == 2

    def test_retry_exhausted(self):
        """Function exhausts 重试"""
        @retry(max_attempts=2, delay=0)
        def always_fail():
            raise RuntimeError("permanent error")

        with pytest.raises(RuntimeError):
            always_fail()


class TestDig:
    """嵌套字典访问辅助函数"""

    def test_simple_access(self):
        """Access nested dict value"""
        data = {"a": {"b": {"c": 42}}}
        assert dig(data, "a", "b", "c") == 42

    def test_missing_key(self):
        """Missing key 返回 default"""
        data = {"a": {}}
        assert dig(data, "a", "b", "c", default=None) is None

    def test_empty_keys(self):
        """Empty key list 返回 data itself"""
        data = {"x": 1}
        assert dig(data) == data
