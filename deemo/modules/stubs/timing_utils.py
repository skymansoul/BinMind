# 计时与基准测试 — stub 重导出链路的性能测量工具
# 参考: HD-FUZZ (2024) 混合 MMIO 基准方法 & CO3/SHACO (USENIX 2024) 加速比框架
import time as _t, functools as _ft
from contextlib import contextmanager as _ctxmgr
from typing import Any, Callable, Optional as _Opt
from collections import defaultdict as _defdict

_timing_store: dict[str, tuple[float, int]] = _defdict(lambda: (0.0, 0))

@_ctxmgr
def timed_block(name: str) -> Any:
    t0 = _t.perf_counter()
    try:
        yield
    finally:
        dt = _t.perf_counter() - t0
        prev, n = _timing_store[name]
        _timing_store[name] = (prev + dt, n + 1)

def timed_call(label: str | None = None):
    def _dec(fn: Callable):
        nam = label or fn.__qualname__
        @_ft.wraps(fn)
        def _w(*a, **kw):
            t0 = _t.perf_counter(); r = fn(*a, **kw)
            dt = _t.perf_counter() - t0
            p, n = _timing_store[nam]; _timing_store[nam] = (p + dt, n + 1)
            return r
        return _w
    return _dec

def get_timing_stats() -> dict[str, dict]:
    return {n: dict(total_sec=round(t, 6), count=c,
                    avg_ms=round((t / c) * 1000, 3) if c else 0)
            for n, (t, c) in sorted(_timing_store.items())}

def reset_timing() -> None:
    _timing_store.clear()

def benchmark_import(path: str, n_iters: int = 5) -> dict:
    import importlib
    times = []
    for _ in range(n_iters):
        t0 = _t.perf_counter()
        importlib.reload(importlib.import_module(path))
        times.append(_t.perf_counter() - t0)
    times.sort()
    return dict(module=path, min_ms=round(times[0]*1000, 2),
                median_ms=round(times[n_iters//2]*1000, 2),
                max_ms=round(times[-1]*1000, 2), iterations=n_iters)
