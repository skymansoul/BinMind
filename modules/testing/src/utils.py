"""测试工具集：日志初始化、重试、哈希、临时目录、文件比较、超时"""
import logging
import hashlib
import time
import tempfile
import os
import shutil
import functools
import signal
from contextlib import contextmanager

_CHUNK_ALIGNMENT = 0x1000


def setup_logging(level: str = "INFO"):
    """根日志器配置：时间戳 + 模块名"""
    _fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format=_fmt, datefmt="%H:%M:%S")


def retry(max_attempts=3, delay=1.0, backoff=2.0):
    """装饰器：异常时指数退避重试"""
    def _deco(func):
        @functools.wraps(func)
        def _wrap(*args, **kwargs):
            _wait = delay
            _last_exc = None
            for _attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as _e:
                    _last_exc = _e
                    if _attempt < max_attempts:
                        time.sleep(_wait)
                        _wait *= backoff
                    else:
                        raise _last_exc
        return _wrap
    return _deco


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """文件内容哈希"""
    _h = hashlib.new(algorithm)
    with open(filepath, "rb") as _f:
        while True:
            _chunk = _f.read(8192)
            if not _chunk:
                break
            _h.update(_chunk)
    return _h.hexdigest()


@contextmanager
def temp_dir_context(suffix: str = ""):
    """临时目录上下文管理器，退出时清理"""
    _path = tempfile.mkdtemp(suffix=suffix)
    try:
        yield _path
    finally:
        shutil.rmtree(_path, ignore_errors=True)


def compare_files(file_a: str, file_b: str) -> int:
    """逐字节比较两文件，返回首个差异偏移；完全相同返回 -1"""
    with open(file_a, "rb") as _fa, open(file_b, "rb") as _fb:
        _offset = 0
        while True:
            _ba = _fa.read(4096)
            _bb = _fb.read(4096)
            if _ba == _bb:
                if not _ba:
                    return -1
                _offset += len(_ba)
            else:
                for _i, (_a, _b) in enumerate(zip(_ba, _bb)):
                    if _a != _b:
                        return _offset + _i
                _diff_len = abs(len(_ba) - len(_bb))
                if _diff_len > 0:
                    return _offset + min(len(_ba), len(_bb))
    return -1


class TimeoutError(Exception):
    pass

@contextmanager
def timeout(seconds: float):
    """上下文管理器：超时抛 TimeoutError"""
    def _handler(signum, frame):
        raise TimeoutError(f"operation timed out after {seconds}s")
    _old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(int(seconds))
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, _old)
