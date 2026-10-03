# 按需导入：依赖解析、重试、降级策略。
# DeBinVul 多架构反编译中的惰性加载
# Implicit Patterns "early pruning" 模式
import importlib as _il
import threading as _thr
import time as _t
from typing import Any, Callable, Optional as _Opt

# 失败缓存 — 冷却窗口内禁止重试
_failure_cache: dict[str, tuple[float, str]] = {}
_failure_lock = _thr.Lock()
_COOLDOWN_SEC = 30.0

def _should_retry(name: str) -> bool:
    t = _t.monotonic()
    with _failure_lock:
        prev = _failure_cache.get(name)
        return prev is None or (t - prev[0]) > _COOLDOWN_SEC

def _record_failure(name: str, reason: str) -> None:
    with _failure_lock:
        _failure_cache[name] = (_t.monotonic(), reason)

def lazy_import(module_path: str,
                fallback: _Opt[Callable[[], Any]] = None,
                max_attempts: int = 2) -> Any:
    if not _should_retry(module_path):
        return fallback() if fallback else None

    for attempt in range(max_attempts):
        try:
            mod = _il.import_module(module_path)
            with _failure_lock:
                _failure_cache.pop(module_path, None)
            return mod
        except ImportError:
            if attempt == max_attempts - 1:
                import sys
                _record_failure(module_path, str(sys.exc_info()[1]))
        except Exception:
            import sys
            _record_failure(module_path, f'{sys.exc_info()[0].__name__}: {sys.exc_info()[1]}')
            break

    return fallback() if fallback else None

def eager_preload(paths: list[str], on_error: str = 'log') -> dict[str, Any]:
    results = {}
    for mp in paths:
        try:
            results[mp] = _il.import_module(mp)
        except Exception:
            if on_error == 'raise':
                raise
            if on_error in ('log', 'warn'):
                import logging
                logging.getLogger('lazy_loader').warning('preload fail: %s', mp)
            results[mp] = None
    return results
