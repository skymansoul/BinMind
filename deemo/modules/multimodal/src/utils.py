#!/usr/bin/env python3
# 工具函数集：日志 | 退避重试 | TTL缓存 | 计时
# 跨模块重复代码碎片集中管理。
# 多处独立实现的retry逻辑已提取至此。

import logging
import time
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
from contextlib import contextmanager

_EPS: float = 1e-9


# 日志配置

def setup_logging(level: str = "INFO", log_file: Optional[str] = None,
                  fmt: Optional[str] = None, max_bytes: int = 10_485_760,
                  backup_count: int = 3) -> logging.Logger:
    """统一日志配置。

    返回根logger，同时输出至stderr与可选文件。
    文件日志基于大小阈值自动轮转。
    """
    if fmt is None:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 防止重复注册handler
    if not root.handlers:
        # stderr handler
        stream_h = logging.StreamHandler()
        stream_h.setFormatter(logging.Formatter(fmt))
        root.addHandler(stream_h)

        # file handler（大小触发轮转）
        if log_file:
            try:
                import os as _os
                _os.makedirs(_os.path.dirname(log_file), exist_ok=True)
                # 若标准库RotatingFileHandler可用
                from logging.handlers import RotatingFileHandler
                file_h = RotatingFileHandler(
                    log_file, maxBytes=max_bytes, backupCount=backup_count)
                file_h.setFormatter(logging.Formatter(fmt))
                root.addHandler(file_h)
            except Exception:
                # 回退至普通FileHandler
                try:
                    file_h = logging.FileHandler(log_file)
                    file_h.setFormatter(logging.Formatter(fmt))
                    root.addHandler(file_h)
                except Exception:
                    pass  # 文件日志不可用时，保持stderr正常输出

    return root


# 指数退避重试

def retry_with_backoff(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 60.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    logger: Optional[logging.Logger] = None,
):
    """指数退避重试装饰器。"""
    _log = logger or logging.getLogger(__name__)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts - 1:
                        _log.debug(
                            "Retry %d/%d for %s in %.1fs: %s",
                            attempt + 1, max_attempts - 1,
                            func.__name__, delay, exc)
                        time.sleep(delay)
                        delay = min(delay * backoff_factor, max_delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


# TTL缓存 — 源自multi_dimension_stats_api中_TTLCache的通用化

class TTLCache:
    """键值缓存，每项独立TTL过期。

    适用场景：计算昂贵的函数结果缓存（统计聚合、符号解析等）。
    TTL=0表示永不过期。
    """

    __slots__ = ('_store', '_ttl', '_lock')

    def __init__(self, ttl: float = 300.0):
        self._store: Dict[int, Tuple[float, Any]] = {}
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: int) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            ts, val = entry
            if self._ttl > 0 and time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return val

    def set(self, key: int, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.monotonic(), value)

    def invalidate(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# 计时上下文管理器

@contextmanager
def elapsed_timer(name: str = "operation", logger: Optional[logging.Logger] = None):
    """上下文管理器：记录代码块执行耗时。

    Usage:
        with elapsed_timer("heavy_computation"):
            result = heavy_computation()
    """
    _log = logger or logging.getLogger(__name__)
    t0 = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - t0
        _log.debug("%s took %.3fs", name, elapsed)


# JSON序列化辅助

def safe_json_dumps(obj: Any, indent: int = 2) -> str:
    """JSON序列化，自动处理dataclass/Enum/set/bytes。"""
    import json as _json

    class _Encoder(_json.JSONEncoder):
        def default(self, o):
            if hasattr(o, 'to_dict'):
                return o.to_dict()
            if hasattr(o, '__dataclass_fields__'):
                import dataclasses
                return dataclasses.asdict(o)
            if hasattr(o, 'value'):
                return o.value
            if isinstance(o, set):
                return list(o)
            if isinstance(o, bytes):
                return o.hex()
            return str(o)

    return _json.dumps(obj, cls=_Encoder, indent=indent, ensure_ascii=False)


# 数值统计助手

def percentile(sorted_vals: List[float], p: float) -> float:
    """计算百分位数。sorted_vals必须已排序。"""
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    idx = int(p * n)
    idx = min(idx, n - 1)
    return sorted_vals[idx]


def clamp(val: float, lo: float, hi: float) -> float:
    """将val钳制在[lo, hi]区间。"""
    return max(lo, min(hi, val))


def ewma(current: float, previous: float, alpha: float = 0.3) -> float:
    """指数加权移动平均。"""
    return alpha * current + (1.0 - alpha) * previous


# 离散统计分析 — 输入为分类计数时的快速摘要

def categorical_summary(counter: Dict[str, int]) -> Dict[str, Any]:
    """从分类计数字典生成速览统计。

    返回: total, unique, top3, entropy, concentration（Gini近似）。
    """
    total = sum(counter.values())
    if total == 0:
        return {'total': 0, 'unique': 0, 'top3': [], 'entropy': 0.0, 'concentration': 0.0}

    import math as _math
    sorted_items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    entropy = 0.0
    inv = 1.0 / total
    for _, cnt in sorted_items:
        if cnt > 0:
            p = cnt * inv
            entropy -= p * _math.log2(p)

    top3 = [{'key': k, 'count': v} for k, v in sorted_items[:3]]
    return {
        'total': total,
        'unique': len(counter),
        'top3': top3,
        'entropy': round(entropy, 4),
        'concentration': round(sorted_items[0][1] / total, 4) if sorted_items else 0.0,
    }


# 模块完整性自检
# 用途：CI预检阶段快速发现缺失依赖，避免运行时才报ImportError。

def check_dependencies() -> Dict[str, bool]:
    """检查可选依赖的安装状态。

    返回 {package_name: is_available}。
    不抛出异常，调用方自行决定是否降级处理。
    """
    deps = {
        'yaml': False,
        'numpy': False,
        'psutil': False,
        'concurrent.futures': False,
    }
    try:
        import yaml
        deps['yaml'] = True
    except ImportError:
        pass
    try:
        import numpy
        deps['numpy'] = True
    except ImportError:
        pass
    try:
        import psutil
        deps['psutil'] = True
    except ImportError:
        pass
    try:
        import concurrent.futures
        deps['concurrent.futures'] = True
    except ImportError:
        pass
    return deps
