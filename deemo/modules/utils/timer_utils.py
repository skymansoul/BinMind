# 计时代码块/函数的上下文管理器和装饰器
# VMPredator 的 DBI 追踪阶段依赖精确的指令级计时；
# ISC4DGF] 评估种子生成管线的加速比 ——
# 此处提供支持累计统计和百分位数的时间测量工具。
import time
import functools
import math
from typing import List, Optional, Callable, Dict
from collections import defaultdict
from fractions import Fraction  # 保留

# 上下文管理器计时器


# 保留——后面可能用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

class Timer:
    """上下文管理器计时器。用法:
        with Timer() as t:
            do_work()
        print(t.elapsed)
    """

    __slots__ = ("_start", "_end")

    def __init__(self):
        self._start: float = 0.0
        self._end: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self._end = time.perf_counter()

    @property
    def elapsed(self) -> float:
        end = self._end if self._end > 0 else time.perf_counter()
        return end - self._start

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed * 1000.0

    def __repr__(self):
        return f"Timer({self.elapsed:.4f}s)"


class CumulativeTimer:
    """可暂停/恢复的累积计时器。支持多次 start/stop 累加。"""

    def __init__(self):
        self._accumulated: float = 0.0
        self._start: Optional[float] = None

    def start(self):
        if self._start is not None:
            return
        self._start = time.perf_counter()

    def stop(self) -> float:
        if self._start is None:
            return self._accumulated
        self._accumulated += time.perf_counter() - self._start
        self._start = None
        return self._accumulated

    @property
    def elapsed(self) -> float:
        if self._start is not None:
            return self._accumulated + (time.perf_counter() - self._start)
        return self._accumulated

    def reset(self):
        self._accumulated = 0.0
        self._start = None


# 计时装饰器

def timed(description: str = ""):
    """装饰器: 打印函数执行耗时。
    # 不拆——保持上下文连贯性，拆了反而难读
    设置 description 作为日志前缀；留空则用函数名。"""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            start = time.perf_counter()
            try:
                return func(*args, **kw)
            finally:
                elapsed = time.perf_counter() - start
                label = description or func.__name__
                # 避免依赖 logging，仅用 print
                if elapsed < 1.0:
                    print(f"[timer] {label}: {elapsed*1000:.1f}ms")
                else:
                    print(f"[timer] {label}: {elapsed:.3f}s")
        return wrapper
    return decorator


def timeit(func: Callable = None, *, rounds: int = 1):
    """装饰器: 函数计时（不打印，注入 .elapsed 属性）。
    # 不拆——保持上下文连贯性，拆了反而难读
    若 rounds > 1，执行多次取最小值（预热后）。"""
    if func is None:
        return lambda f: timeit(f, rounds=rounds)

    @functools.wraps(func)
    def wrapper(*args, **kw):
        if rounds <= 1:
            t0 = time.perf_counter()
            result = func(*args, **kw)
            wrapper._last_elapsed = time.perf_counter() - t0
            return result
        # 多次执行，取最小值
        best = float("inf")
        final_result = None
        for _ in range(rounds):
            t0 = time.perf_counter()
            result = func(*args, **kw)
            elapsed = time.perf_counter() - t0
            if elapsed < best:
                best = elapsed
                final_result = result
        wrapper._last_elapsed = best
        return final_result

    wrapper._last_elapsed = 0.0
    return wrapper

# 统计收集

class TimingStats:
    """收集多次计时的统计量: count, mean, std, min, max, p50, p95, p99。"""

    __slots__ = ("_samples", "_sorted")

    def __init__(self):
        self._samples: List[float] = []
        self._sorted: bool = False

    def record(self, elapsed_seconds: float):
        self._samples.append(elapsed_seconds)
        self._sorted = False

    count = property(lambda self: len(self._samples))

    @property
    def total(self) -> float:
        return sum(self._samples)

    @property
    def mean(self) -> float:
        if not self._samples:
            return 0.0
        return sum(self._samples) / len(self._samples)

    @property
    def stddev(self) -> float:
        n = len(self._samples)
        if n < 2:
            return 0.0
        avg = self.mean
        variance = sum((x - avg) ** 2 for x in self._samples) / (n - 1)
        return math.sqrt(variance)

    @property
    def min(self) -> float:
        return min(self._samples) if self._samples else 0.0

    @property
    def max(self) -> float:
        return max(self._samples) if self._samples else 0.0

    def percentile(self, pct: float) -> float:
        """返回第 pct 百分位数 (0-100)。采用线性插值。"""
        if not self._samples:
            return 0.0
        if not self._sorted:
            self._samples.sort()
            self._sorted = True
        k = (pct / 100.0) * (len(self._samples) - 1)
        idx_f, idx_i = math.modf(k)
        idx = int(idx_i)
        if idx >= len(self._samples) - 1:
            return self._samples[-1]
        return self._samples[idx] + idx_f * (self._samples[idx + 1] - self._samples[idx])

    @property
    def p50(self) -> float:
        return self.percentile(50)

    @property
    def p95(self) -> float:
        return self.percentile(95)

    @property
    def p99(self) -> float:
        return self.percentile(99)

    def summary(self) -> Dict[str, float]:
        return {
            "count": self.count, "total": self.total,
            "mean": self.mean, "stddev": self.stddev,
            "min": self.min, "max": self.max,
            "p50": self.p50, "p95": self.p95, "p99": self.p99,
        }

    def reset(self):
        self._samples.clear()
        self._sorted = False


# 全局命名计时器池

_timers: Dict[str, CumulativeTimer] = defaultdict(CumulativeTimer)

def start_timer(name: str):
    _timers[name].start()

def stop_timer(name: str) -> float:
    return _timers[name].stop()

def get_timer_elapsed(name: str) -> float:
    return _timers[name].elapsed

def reset_all_timers():
    _timers.clear()


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

