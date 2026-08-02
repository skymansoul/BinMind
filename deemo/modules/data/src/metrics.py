# 轻量可观测性 — Counter/Gauge/Histogram/Summary/Rate/Delta，Prometheus text format 输出
# 参考 OpenTelemetry instrument/meter 概念，但去掉 SDK 重依赖
# Counter 用 threading.Lock 保原子性：Python int += 在 GIL 下也不原子，多线程会丢计数
#
# Delta: 差值追踪器 —— 存储上一次值和当前值，value() 返回差值。
# 适合追踪增量变化（如"本轮导入新增了多少条"）而无需外部维护状态。

import contextlib
import json
import threading
import time
from typing import Dict, List, Optional, Any


class Counter:
    def __init__(self, name: str, help_text: str = "", labels: Dict[str, str] = None):
        self.name = name
        self.help = help_text
        self.labels = labels or {}
        self._val = 0
        self._lock = threading.Lock()

    def inc(self, delta: int = 1):
        with self._lock:
            self._val += delta

    def value(self) -> int:
        return self._val

    def reset(self):
        with self._lock:
            self._val = 0


class Gauge:
    def __init__(self, name: str, help_text: str = "", labels: Dict[str, str] = None):
        self.name = name
        self.help = help_text
        self.labels = labels or {}
        self._val = 0.0
        self._lock = threading.Lock()

    def set(self, value: float):
        with self._lock:
            self._val = value

    def inc(self, delta: float = 1.0):
        with self._lock:
            self._val += delta

    def dec(self, delta: float = 1.0):
        with self._lock:
            self._val -= delta

    def value(self) -> float:
        return self._val


class Delta:
    """差值追踪器 — 存当前值和上一次值，返回增量。

    典型用法：跟踪数据库行数变化率。每轮调用 update(new_count)，
    value() 返回 new_count - previous_count。
    """

    def __init__(self, name: str, help_text: str = "", labels: Dict[str, str] = None):
        self.name = name
        self.help = help_text
        self.labels = labels or {}
        self._prev = 0.0
        self._curr = 0.0
        self._lock = threading.Lock()

    def update(self, value: float):
        with self._lock:
            self._prev = self._curr
            self._curr = value

    def value(self) -> float:
        with self._lock:
            return self._curr - self._prev

    @property
    def current(self) -> float:
        return self._curr

    @property
    def previous(self) -> float:
        return self._prev


class Histogram:
    """Prometheus 标准 histogram — le bucket 格式。"""

    def __init__(self, name: str, help_text: str = "",
                 buckets: List[float] = None, labels: Dict[str, str] = None):
        self.name = name
        self.help = help_text
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self.labels = labels or {}
        self._counts = [0] * (len(self.buckets) + 1)
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float):
        with self._lock:
            self._sum += value
            self._count += 1
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    self._counts[i] += 1
                    return
            self._counts[-1] += 1

    def value(self) -> Dict:
        return {"count": self._count, "sum": self._sum, "buckets": self._dump_buckets()}

    def _dump_buckets(self):
        cum = 0
        result = []
        for i, bound in enumerate(self.buckets):
            cum += self._counts[i]
            result.append((bound, cum))
        cum += self._counts[-1]
        result.append(("+Inf", cum))
        return result

    def timeit(self) -> "Timer":
        return Timer(self)


class Summary:
    """滑动窗口 Summary —— 存原始样本，按需算分位数。"""

    def __init__(self, name: str, help_text: str = "",
                 max_samples: int = 2000, labels: Dict[str, str] = None):
        self.name = name
        self.help = help_text
        self.labels = labels or {}
        self._samples: List[float] = []
        self._max = max_samples
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float):
        with self._lock:
            self._sum += value
            self._count += 1
            if len(self._samples) >= self._max:
                idx = int(_fast_random() * (len(self._samples) + 1))
                if idx < self._max:
                    self._samples[idx] = value
            else:
                self._samples.append(value)

    def quantile(self, q: float) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            s = sorted(self._samples)
            idx = int(len(s) * q)
            return s[min(idx, len(s) - 1)]

    def value(self) -> Dict:
        return {
            "count": self._count, "sum": self._sum,
            "p50": self.quantile(0.50), "p95": self.quantile(0.95),
            "p99": self.quantile(0.99),
        }

    def timeit(self) -> "Timer":
        return Timer(self)


class Rate:
    """滑动窗口速率计 —— 追踪最近 window_sec 内的事件频率。"""

    def __init__(self, name: str, help_text: str = "",
                 window_sec: float = 10.0, slots: int = 10,
                 labels: Dict[str, str] = None):
        self.name = name
        self.help = help_text
        self.labels = labels or {}
        self._window = window_sec
        self._slot_width = window_sec / slots
        self._slots = [0.0] * slots
        self._last_slot = int(time.monotonic() / self._slot_width)
        self._lock = threading.Lock()

    def mark(self, count: float = 1.0):
        with self._lock:
            now_slot = int(time.monotonic() / self._slot_width)
            self._advance(now_slot)
            self._slots[-1] += count

    def _advance(self, now_slot: int):
        diff = now_slot - self._last_slot
        if diff <= 0:
            return
        elif diff >= len(self._slots):
            self._slots = [0.0] * len(self._slots)
        else:
            self._slots = self._slots[diff:] + [0.0] * diff
        self._last_slot = now_slot

    def rate(self) -> float:
        with self._lock:
            now_slot = int(time.monotonic() / self._slot_width)
            self._advance(now_slot)
            return sum(self._slots) / self._window

    def value(self) -> float:
        return self.rate()


class Timer:
    """一行计时的上下文管理器。"""
    __slots__ = ("_target", "_start")

    def __init__(self, target):
        self._target = target
        self._start = 0.0

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *args):
        self._target.observe(time.monotonic() - self._start)
        return False


def _fast_random() -> float:
    _fast_random._state = (_fast_random._state * 1103515245 + 12345) & 0x7FFFFFFF
    return _fast_random._state / 0x7FFFFFFF


_fast_random._state = int(time.time() * 1e6) & 0x7FFFFFFF


class MetricsRegistry:
    """全局指标注册表 — 收集所有指标，支持多种输出格式。"""

    def __init__(self):
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._deltas: Dict[str, Delta] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._summaries: Dict[str, Summary] = {}
        self._rates: Dict[str, Rate] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, help_text: str = "", labels: Dict[str, str] = None) -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, help_text, labels)
            return self._counters[name]

    def gauge(self, name: str, help_text: str = "", labels: Dict[str, str] = None) -> Gauge:
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, help_text, labels)
            return self._gauges[name]

    def delta(self, name: str, help_text: str = "", labels: Dict[str, str] = None) -> Delta:
        with self._lock:
            if name not in self._deltas:
                self._deltas[name] = Delta(name, help_text, labels)
            return self._deltas[name]

    def histogram(self, name: str, help_text: str = "",
                  buckets: List[float] = None, labels: Dict[str, str] = None) -> Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, help_text, buckets, labels)
            return self._histograms[name]

    def summary(self, name: str, help_text: str = "",
                max_samples: int = 2000, labels: Dict[str, str] = None) -> Summary:
        with self._lock:
            if name not in self._summaries:
                self._summaries[name] = Summary(name, help_text, max_samples, labels)
            return self._summaries[name]

    def rate(self, name: str, help_text: str = "",
             window_sec: float = 10.0, labels: Dict[str, str] = None) -> Rate:
        with self._lock:
            if name not in self._rates:
                self._rates[name] = Rate(name, help_text, window_sec, labels=labels)
            return self._rates[name]

    def prometheus_text(self) -> str:
        lines = []
        for name, c in sorted(self._counters.items()):
            if c.help:
                lines.append(f"# HELP {name} {c.help}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name}{_label_str(c.labels)} {c.value()}")
        for name, g in sorted(self._gauges.items()):
            if g.help:
                lines.append(f"# HELP {name} {g.help}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{_label_str(g.labels)} {g.value()}")
        for name, d in sorted(self._deltas.items()):
            if d.help:
                lines.append(f"# HELP {name} {d.help}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{_label_str(d.labels)} {d.value()}")
        for name, h in sorted(self._histograms.items()):
            if h.help:
                lines.append(f"# HELP {name} {h.help}")
            lines.append(f"# TYPE {name} histogram")
            for bound, cum in h.value()["buckets"]:
                bl = dict(h.labels)
                bl["le"] = str(bound)
                lines.append(f"{name}_bucket{_label_str(bl)} {cum}")
            lines.append(f"{name}_sum{_label_str(h.labels)} {h.value()['sum']}")
            lines.append(f"{name}_count{_label_str(h.labels)} {h.value()['count']}")
        for name, s in sorted(self._summaries.items()):
            if s.help:
                lines.append(f"# HELP {name} {s.help}")
            lines.append(f"# TYPE {name} summary")
            v = s.value()
            for q in ["p50", "p95", "p99"]:
                ql = dict(s.labels)
                ql["quantile"] = q
                lines.append(f"{name}{_label_str(ql)} {v[q]}")
            lines.append(f"{name}_sum{_label_str(s.labels)} {v['sum']}")
            lines.append(f"{name}_count{_label_str(s.labels)} {v['count']}")
        for name, r in sorted(self._rates.items()):
            if r.help:
                lines.append(f"# HELP {name} {r.help}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{_label_str(r.labels)} {r.rate()}")
        return "\n".join(lines) + "\n"

    def to_json(self) -> dict:
        result = {"counters": {}, "gauges": {}, "deltas": {},
                  "histograms": {}, "summaries": {}, "rates": {}}
        for n, c in self._counters.items():
            result["counters"][n] = c.value()
        for n, g in self._gauges.items():
            result["gauges"][n] = g.value()
        for n, d in self._deltas.items():
            result["deltas"][n] = d.value()
        for n, h in self._histograms.items():
            result["histograms"][n] = h.value()
        for n, s in self._summaries.items():
            result["summaries"][n] = s.value()
        for n, r in self._rates.items():
            result["rates"][n] = r.rate()
        return result

    def reset_all(self):
        """清空所有已注册指标 —— 用于测试清理和进程重启。

        注意：这会删除所有指标对象，之后 get_registry().counter('x')
        会创建新的 Counter 实例（从零开始计数）。
        """
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._deltas.clear()
            self._histograms.clear()
            self._summaries.clear()
            self._rates.clear()

    def to_influxdb(self, measurement: str = "binmind_data") -> str:
        ts = int(time.time() * 1e9)
        fields = []
        for n, c in self._counters.items():
            fields.append(f"{n}={c.value()}i")
        for n, g in self._gauges.items():
            fields.append(f"{n}={g.value()}")
        return f"{measurement} {','.join(fields)} {ts}"


def _label_str(labels: Dict[str, str]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


_registry = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    return _registry
