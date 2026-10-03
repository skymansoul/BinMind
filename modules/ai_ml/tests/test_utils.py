# tests/test_utils.py — retry, 日志, helpers
import sys
import os
import time
import logging
import pytest

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


class TestRetry:
    """指数退避重试机制"""

    def test_retry_decorator_success_first_attempt(self):
        """首次成功不重试"""
        from src.utils.retry import retry

        call_count = [0]

        @retry(max_attempts=3, backoff_base=0.01)
        def succeeds():
            call_count[0] += 1
            return "ok"

        result = succeeds()
        assert result == "ok"
        assert call_count[0] == 1

    def test_retry_decorator_retries_then_succeeds(self):
        """重试后成功"""
        from src.utils.retry import retry

        attempts = [0]

        @retry(max_attempts=3, backoff_base=0.01)
        def flaky():
            attempts[0] += 1
            if attempts[0] < 3:
                raise ConnectionError("transient")
            return "recovered"

        result = flaky()
        assert result == "recovered"
        assert attempts[0] == 3

    def test_retry_decorator_exhausted(self):
        """重试耗尽抛出RuntimeError"""
        from src.utils.retry import retry

        @retry(max_attempts=2, backoff_base=0.01)
        def always_fails():
            raise OSError("permanent")

        with pytest.raises(RuntimeError, match="failed after 2"):
            always_fails()

    def test_retry_call_success(self):
        """retry_call独立调用成功"""
        from src.utils.retry import retry_call

        result = retry_call(lambda x: x * 2, 21, max_attempts=3, backoff_base=0.01)
        assert result == 42

    def test_retry_call_failure(self):
        """retry_call失败抛出RuntimeError"""
        from src.utils.retry import retry_call

        def boom():
            raise TimeoutError("timed out")

        with pytest.raises(RuntimeError, match="retry_call failed"):
            retry_call(boom, max_attempts=2, backoff_base=0.01)


class TestLoggingSetup:
    """统一日志配置"""

    def test_setup_logging_no_file(self):
        """无文件处理器时不会崩溃"""
        from src.utils.logging_setup import setup_logging
        setup_logging(level="DEBUG", log_file=None, debug=True)
        logger = logging.getLogger("ai_ml")
        assert logger.level <= logging.DEBUG

    def test_get_logger_returns_child(self):
        """get_logger返回ai_ml子记录器"""
        from src.utils.logging_setup import get_logger
        lg = get_logger("test.sublog")
        assert lg.name == "ai_ml.test.sublog"

    def test_get_logger_empty_name(self):
        """空名称返回根记录器"""
        from src.utils.logging_setup import get_logger
        lg = get_logger("")
        assert lg.name == "ai_ml"


class TestHelpers:
    """通用工具函数"""

    def test_read_json_creates_temp_and_roundtrips(self, tmp_path):
        """JSON读写往返"""
        from src.utils.helpers import write_json, read_json
        p = str(tmp_path / "test.json")
        data = {"key": [1, 2, 3], "nested": {"a": True}}
        write_json(data, p)
        loaded = read_json(p)
        assert loaded == data

    def test_file_fingerprint_consistent(self, tmp_path):
        """文件指纹一致性"""
        from src.utils.helpers import file_fingerprint
        p = tmp_path / "fp_test.bin"
        p.write_bytes(b"hello world fingerprint test")
        fp1 = file_fingerprint(str(p))
        fp2 = file_fingerprint(str(p))
        assert fp1 == fp2
        assert len(fp1) > 0

    def test_chunked_iterator(self):
        """分块迭代器"""
        from src.utils.helpers import chunked_iterator
        data = list(range(10))
        chunks = list(chunked_iterator(data, chunk_size=3))
        assert len(chunks) == 4
        assert chunks[0] == [0, 1, 2]
        assert chunks[-1] == [9]

    def test_batch_generator(self):
        """批量生成器"""
        from src.utils.helpers import batch_generator
        items = [1, 2, 3, 4, 5, 6, 7]
        batches = list(batch_generator(items, batch_size=3))
        assert len(batches) == 3
        assert batches[0] == [1, 2, 3]
