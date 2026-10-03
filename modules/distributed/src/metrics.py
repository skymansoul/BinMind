# Prometheus 格式指标 — 不依赖 prometheus_client，自研精简实现
# 遵循 OpenMetrics 规范: HELP/TYPE 行 + metric line + 后缀
# Counter/Gauge/Histogram 覆盖常用场景，复杂指标通过 registry 扩展
#
# 扩展：Summary 类型 — 客户端分位数计算，适配 latency 统计

from __future__ import annotations

import threading
import math
from typing import Optional, Dict, List


# 指标基类

class Metric:
    __slots__ = ('name', 'help_text', 'type_str', '_labels')

    def __init__(self, name: str, help_text: str = "", labels: dict = None):
        self.name = name
        self.help_text = help_text
        self.type_str = "untyped"
        self._labels = labels or {}

    @property
    def labels(self) -> dict:
        return dict(self._labels)

    def _label_str(self) -> str:
        if not self._labels:
            return ""
        parts = [f'{k}="{v}"' for k, v in sorted(self._labels.items())]
        return "{" + ", ".join(parts) + "}"


# 累加计数器

class Counter(Metric):
    """只增不减的单调计数器"""

    __slots__ = ('_value', '_lock')

    def __init__(self, name: str, help_text: str = "", labels: dict = None):
        super().__init__(name, help_text, labels)
        self.type_str = "counter"
        self._value: float = 0.0
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    @property
    def value(self) -> float:
        with self._lock:
            return self._value


# 瞬时值仪表盘

class Gauge(Metric):
    """可增可减的瞬时值度量"""

    __slots__ = ('_value', '_lock')

    def __init__(self, name: str, help_text: str = "", labels: dict = None):
        super().__init__(name, help_text, labels)
        self.type_str = "gauge"
        self._value: float = 0.0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value -= amount

    @property
    def value(self) -> float:
        with self._lock:
            return self._value


# 直方图

class Histogram(Metric):
    """预定义桶的直方图 — 输出 _bucket/_sum/_count 序列"""

    __slots__ = ('_buckets', '_count', '_sum', '_lock')

    _DEFAULT_BUCKETS = (
        0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5,
        0.75, 1.0, 2.5, 5.0, 7.5, 10.0, float("inf"),
    )

    def __init__(self, name: str, help_text: str = "", labels: dict = None,
                 buckets: tuple = None):
        super().__init__(name, help_text, labels)
        self.type_str = "histogram"
        bucket_list = list(buckets) if buckets else list(self._DEFAULT_BUCKETS)
        self._buckets: Dict[float, int] = {b: 0 for b in sorted(set(bucket_list))}
        self._count: int = 0
        self._sum: float = 0.0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._count += 1
            self._sum += value
            for boundary in self._buckets:
                if value <= boundary:
                    self._buckets[boundary] += 1

    @property
    def buckets(self) -> List[float]:
        return sorted(self._buckets.keys())

    def quantile(self, q: float) -> float:
        """基于桶边界的线性插值估算分位数。q ∈ [0, 1]"""
        if q < 0 or q > 1:
            raise ValueError("quantile must be between 0 and 1")
        with self._lock:
            if self._count == 0:
                return 0.0
            target = int(math.ceil(q * self._count))
            cum = 0
            for b in sorted(self._buckets.keys()):
                cum += self._buckets[b]
                if cum >= target:
                    return b
            return sorted(self._buckets.keys())[-1]


# 客户端分位数摘要

class Summary(Metric):
    """客户端分位数摘要 — 存储原始值列表，抓取时计算分位数。

    量化精度随样本数增长。内存 O(samples)，不适合无限累积，
    建议配合 max_age 定期重置。
    """

    __slots__ = ('_values', '_count', '_sum', '_lock')

    def __init__(self, name: str, help_text: str = "", labels: dict = None,
                 quantiles: tuple = (0.5, 0.9, 0.99)):
        super().__init__(name, help_text, labels)
        self.type_str = "summary"
        self._values: List[float] = []
        self._quantiles = quantiles
        self._count: int = 0
        self._sum: float = 0.0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._values.append(value)
            self._count += 1
            self._sum += value

    def quantiles(self) -> Dict[float, float]:
        """计算全部预定义分位数并返回。"""
        with self._lock:
            if not self._values:
                return {q: 0.0 for q in self._quantiles}
            sorted_vals = sorted(self._values)
            result = {}
            for q in self._quantiles:
                idx = int(math.ceil(q * len(sorted_vals))) - 1
                idx = max(0, min(idx, len(sorted_vals) - 1))
                result[q] = sorted_vals[idx]
            return result

    @property
    def count(self) -> int:
        return self._count

    @property
    def sum(self) -> float:
        return self._sum


# 全局注册表

class Registry:
    """指标注册表 — 线程安全的全局指标容器"""

    def __init__(self):
        self._metrics: Dict[str, Metric] = {}
        self._lock = threading.Lock()

    def register(self, metric: Metric) -> None:
        with self._lock:
            self._metrics[metric.name] = metric

    def unregister(self, name: str) -> bool:
        with self._lock:
            return self._metrics.pop(name, None) is not None

    def get(self, name: str) -> Optional[Metric]:
        return self._metrics.get(name)

    def collect(self) -> List[Metric]:
        with self._lock:
            return list(self._metrics.values())


# 全局默认注册表单例
_default_registry = Registry()


# Prometheus 文本序列化

def _prometheus_text(registry: Registry = None) -> str:
    """生成 Prometheus exposition 格式文本。

    标准格式:
    # HELP <name> <help>
    # TYPE <name> <type>
    <name>{labels} <value>
    """
    reg = registry or _default_registry
    lines: List[str] = []
    seen: set = set()

    for metric in reg.collect():
        if metric.name in seen:
            continue
        seen.add(metric.name)
        label = metric._label_str()

        # HELP / TYPE 头部
        lines.append(f"# HELP {metric.name} {metric.help_text or metric.name}")
        lines.append(f"# TYPE {metric.name} {metric.type_str}")

        if isinstance(metric, Histogram):
            # 逐桶输出
            for boundary in sorted(metric._buckets.keys()):
                b_label = f'le="{_format_boundary(boundary)}"'
                if not label:
                    full = "{" + b_label + "}"
                else:
                    full = label[:-1] + f', {b_label}' + "}"
                lines.append(
                    f"{metric.name}_bucket{full} {metric._buckets[boundary]}"
                )
            # _sum, _count 后缀行
            lines.append(f"{metric.name}_sum{label} {metric._sum}")
            lines.append(f"{metric.name}_count{label} {metric._count}")
        elif isinstance(metric, Summary):
            for q, val in metric.quantiles().items():
                q_label = f'quantile="{_format_boundary(q)}"'
                if not label:
                    full = "{" + q_label + "}"
                else:
                    full = label[:-1] + f', {q_label}' + "}"
                lines.append(f"{metric.name}{full} {val}")
            lines.append(f"{metric.name}_sum{label} {metric._sum}")
            lines.append(f"{metric.name}_count{label} {metric._count}")
        else:
            val = metric.value
            if isinstance(val, float) and val == val and val != float("inf"):
                s_val = f"{val:g}"
            else:
                s_val = str(val)
            lines.append(f"{metric.name}{label} {s_val}")

    return "\n".join(lines) + "\n"


def _format_boundary(b: float) -> str:
    if b == float("inf"):
        return "+Inf"
    return f"{b:g}"
