# 2026-07-22
# 工具函数 — 分布式系统的「瑞士军刀」
# retry 装饰器参考 google.api_core.retry + tenacity 但精简到核心逻辑
# 指数退避 + 随机抖动是分布式系统的基本素养

from __future__ import annotations

import time
import random
import logging
import functools
import threading
from contextlib import contextmanager
from typing import Callable, Iterator, TypeVar, Tuple
from itertools import islice

T = TypeVar("T")


# //// 退避计算 ////

def backoff_delay(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    """指数退避 + 25% 均匀抖动。attempt 从 1 开始。"""
    raw = min(base ** attempt, cap)
    return raw * (0.75 + random.random() * 0.5)


# //// 重试装饰器 ////

def retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: Tuple[type, ...] = (Exception,),
    logger=None,
):
    """函数级重试装饰器。记录日志后按指数退避重试。

    exceptions 接受 tuple of Exception 类型，匹配 isinstance 语义。
    """
    log = logger or logging.getLogger(__name__)

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt >= max_attempts:
                        log.error(
                            "%s failed after %d attempts: %s",
                            func.__name__, max_attempts, e,
                        )
                        raise
                    delay = backoff_delay(attempt, base_delay, max_delay)
                    log.warning(
                        "%s attempt %d/%d failed: %s. retrying in %.2fs",
                        func.__name__, attempt, max_attempts, e, delay,
                    )
                    time.sleep(delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


# //// 日志 ////

def setup_logging(
    name: str,
    level: str = "INFO",
    fmt: str = None,
) -> logging.Logger:
    """快速初始化一个带 StreamHandler 的 logger。"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logger.level)
        formatter = logging.Formatter(
            fmt or "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


# //// 分块 ////

def chunks(iterable, n: int) -> Iterator[list]:
    """把可迭代对象切成 n 大小的块。
    内存友好：用 islice 而不是一次性切片。
    """
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            return
        yield batch


# //// 时间戳 ////

def now_ts() -> float:
    """monotonic 时间戳 — 不受系统时间调整影响，适合测量间隔。
    注意：monotonic 不适用于需要绝对时间（如 unix timestamp）的场景。
    """
    return time.monotonic()


# //// 超时上下文管理器 ////

@contextmanager
def timeout(seconds: float, message: str = "operation timed out"):
    """在独立线程中执行代码块，超时则触发 TimeoutError。

    实现限制：使用 threading.Timer 发中断信号，因此仅在主线程有效。
    多线程场景需配合 concurrent.futures.TimeoutError 使用。
    """
    timer = threading.Timer(seconds, lambda: (_ for _ in ()).throw(TimeoutError(message)))
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


# //// 缓存 ////

def memoize(maxsize: int = 128):
    """线程安全的 LRU 风格缓存装饰器。仅适用于可哈希参数。

    maxsize: 最大缓存条目数，超出时淘汰最早的条目。
    """
    def decorator(func: Callable):
        cache: dict = {}
        lock = threading.Lock()

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            with lock:
                if key in cache:
                    return cache[key]
            result = func(*args, **kwargs)
            with lock:
                if len(cache) >= maxsize:
                    # 淘汰最早的条目 — 简单 FIFO，非严格 LRU
                    oldest = next(iter(cache))
                    del cache[oldest]
                cache[key] = result
            return result

        def clear():
            with lock:
                cache.clear()

        wrapper.cache_clear = clear
        return wrapper
    return decorator
