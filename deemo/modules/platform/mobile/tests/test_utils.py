"""移动端——工具函数测试"""
import pytest
import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from utils import (
    setup_logging, retry, safe_path, sha256_file,
    ensure_dir, load_json_safe, save_json_safe, chunked_read,
    TimedLock, _debug_print
)


class TestSetupLogging:
    """确认日志初始化行为。"""

    def test_setup_logging_returns_logger(self):
        import logging
        logger = setup_logging('test_logger', level=logging.WARNING)
        assert logger.name == 'test_logger'
        assert logger.level == logging.WARNING

    def test_setup_logging_adds_handler(self):
        import logging
        logger = setup_logging('test_handler')
        assert len(logger.handlers) >= 1

    def test_default_name(self):
        logger = setup_logging()
        assert logger.name is not None


class TestSafePath:
    """确认路径安全校验。"""

    def test_safe_path_normal(self):
        result = safe_path('/usr/lib/test.so')
        assert 'test.so' in result

    def test_safe_path_rejects_traversal(self):
        with pytest.raises(ValueError, match='Unsafe path'):
            safe_path('/usr/lib/../../../etc/passwd')

    def test_safe_path_absolute_normalize(self):
        result = safe_path('/usr/./lib/../lib/test.so')
        assert '/usr/lib/test.so' in result or result.endswith('test.so')


class TestRetry:
    """确认重试装饰器行为。"""

    def test_retry_success_first_attempt(self):
        @retry(max_attempts=3, delay=0.01)
        def succeed():
            return 'ok'
        assert succeed() == 'ok'

    def test_retry_eventually_fails(self):
        call_count = [0]

        @retry(max_attempts=2, delay=0.01)
        def always_fail():
            call_count[0] += 1
            raise ValueError('test error')

        with pytest.raises(ValueError):
            always_fail()
        assert call_count[0] == 2

    def test_retry_non_matching_exception_not_caught(self):
        @retry(max_attempts=2, delay=0.01, exceptions=(ValueError,))
        def raise_type_error():
            raise TypeError('not caught')

        with pytest.raises(TypeError):
            raise_type_error()

    def test_retry_recovers_after_transient_error(self):
        attempts = [0]

        @retry(max_attempts=3, delay=0.01)
        def transient():
            attempts[0] += 1
            if attempts[0] < 2:
                raise ConnectionError('transient')
            return 'recovered'

        result = transient()
        assert result == 'recovered'
        assert attempts[0] == 2


class TestFileOperations:
    """确认文件操作工具函数。"""

    def test_ensure_dir_creates(self):
        import tempfile
        import shutil
        test_dir = os.path.join(tempfile.gettempdir(), 'mobile_test_dir')
        try:
            result = ensure_dir(test_dir)
            assert os.path.isdir(result)
        finally:
            if os.path.exists(test_dir):
                shutil.rmtree(test_dir, ignore_errors=True)

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('hello world')
            f.flush()
            try:
                h = sha256_file(f.name)
                assert len(h) == 64
                assert h != ''
            finally:
                os.unlink(f.name)

    def test_sha256_file_nonexistent(self):
        h = sha256_file('/nonexistent/file.txt')
        assert h == ''

    def test_chunked_read(self):
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'A' * 200000)
            f.flush()
            try:
                data = chunked_read(f.name, chunk_size=32768)
                assert len(data) == 200000
                assert data == b'A' * 200000
            finally:
                os.unlink(f.name)


class TestJSONOperations:
    """确认JSON安全读写。"""

    def test_save_and_load_json(self):
        with tempfile.NamedTemporaryFile(suffix='.json', mode='r', delete=False) as f:
            f.close()
            try:
                data = {'test': [1, 2, 3], 'nested': {'key': 'value'}}
                ok = save_json_safe(f.name, data)
                assert ok is True
                loaded = load_json_safe(f.name)
                assert loaded == data
            finally:
                os.unlink(f.name)

    def test_load_json_default_on_missing(self):
        result = load_json_safe('/nonexistent/file.json', default={'default': True})
        assert result == {'default': True}

    def test_load_json_default_none(self):
        result = load_json_safe('/nonexistent/file.json')
        assert result == {}


class TestTimedLock:
    """确认超时锁行为。"""

    def test_lock_acquire_and_release(self):
        lock = TimedLock(timeout=5.0)
        with lock:
            pass  # 正常获取并释放

    def test_debug_print_noop(self):
        """_debug_print应为空操作。"""
        assert _debug_print('test', x=1) is None
        assert _debug_print() is None
