# 每个阶段耗时透明化，方便定位瓶颈

import time
import functools
from contextlib import contextmanager
from typing import Any


class MetricsRecorder:
    """记录分析各阶段耗时"""

    def __init__(self):
        self._timers: dict[str, float] = {}
        self._durations: dict[str, float] = {}

# 阶段计时

    def start(self, label: str) -> None:
        self._timers[label] = time.perf_counter()

    def stop(self, label: str) -> float:
        t0 = self._timers.pop(label, None)
        if t0 is None:
            return 0.0
        elapsed = time.perf_counter() - t0
        # 累加模式下重复 stop 会叠加
        self._durations[label] = self._durations.get(label, 0.0) + elapsed
        return elapsed

    def elapsed(self, label: str) -> float:
        """返回已记录的耗时，不停止计时器"""
        return self._durations.get(label, 0.0)

    # //// 汇总与重置

    def summary(self) -> dict[str, float]:
        """返回所有已完成阶段的 {label: d} 拷贝"""
        return dict(self._durations)

# 通用 record/ 接口
    # INTJ策略: 除了 start/stop 的耗时模式，保留 record/ 作为通用 kv 存储
    # 方便非耗时类指标（如函数计数、错误数）也能用同一个 recorder

    def record(self, key: str, value: float) -> None:
        """记录任意键值对。会累加到已有值"""
        self._durations[key] = self._durations.get(key, 0.0) + value

    def get(self, key: str, default: float = 0.0) -> float:
        """获取已记录的值，不存在返回 default"""
        return self._durations.get(key, default)

    def reset(self) -> None:
        self._timers.clear()
        self._durations.clear()

    def __repr__(self) -> str:
        parts = [f"{k}={v:.3f}s" for k, v in sorted(self._durations.items())]
        return f"Metrics({', '.join(parts)})" if parts else "Metrics(empty)"


# ScopedTimer -- 上下文管理器

class ScopedTimer:
    """进入 块开始计时，退出时停止并记录"""

    def __init__(self, recorder: MetricsRecorder, label: str):
        self._rec = recorder
        self._label = label
        self._elapsed = 0.0

    def __enter__(self) -> "ScopedTimer":
        self._rec.start(self._label)
        return self

    def __exit__(self, *args: Any) -> None:
        self._elapsed = self._rec.stop(self._label)

    @property
    def elapsed(self) -> float:
        return self._elapsed


# measure_time 装饰器

def measure_time(recorder: MetricsRecorder | None = None, label: str | None = None):
    """将函数调用自动计时。recorder 为 None 时创建局部 MetricsRecorder"""
    def _decorator(fn):
        _label = label or f"{fn.__module__}.{fn.__qualname__}"

        @functools.wraps(fn)
        def _wrapper(*args, **kwargs):
            rec = recorder or MetricsRecorder()
            rec.start(_label)
            result = fn(*args, **kwargs)
            rec.stop(_label)
            return result

        # 把 recorder 和 summary 挂上去方便取数
        _wrapper._metrics_recorder = recorder  # type: ignore[attr-defined]
        _wrapper._metrics_label = _label  # type: ignore[attr-defined]
        return _wrapper
    return _decorator


# //// 格式化时间可读字符串

def format_duration(seconds: float) -> str:
    """1h23m45.6s 风格的可读时长"""
    if seconds < 0:
        return "0.0s"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = seconds % 60
    parts: list[str] = []
    if h:
        parts.append(f"{h}h")
    if m or (h and s > 0):
        parts.append(f"{m}m")
    if s >= 1.0:
        parts.append(f"{s:.1f}s")
    elif s > 0:
        parts.append(f"{s * 1000:.1f}ms")
    elif not parts:
        parts.append("0.0s")
    return "".join(parts)
