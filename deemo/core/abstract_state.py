"""
抽象状态数据类 — 单个程序点的抽象状态。

包含区间映射、堆抽象域、join/widen/clone 操作。
"""


from dataclasses import dataclass, field
from typing import Dict

from core.heap_abstract_domain import HeapAbstractDomain, Interval


@dataclass
class AbstractState:
    """单个程序点的抽象状态。包含 intervals 变量区间映射、heap 堆抽象域、reachable 可达标记。"""
    intervals: Dict[str, Interval] = field(default_factory=dict)
    heap: HeapAbstractDomain = field(default_factory=HeapAbstractDomain)
    reachable: bool = True

    def clone(self) -> "AbstractState":
        return AbstractState(
            intervals={k: Interval(v.low, v.high) for k, v in self.intervals.items()},
            heap=self.heap.clone(),
            reachable=self.reachable,
        )

    def join(self, other: "AbstractState") -> "AbstractState":
        """合并两个状态。"""
        joined = AbstractState()
        all_vars = set(self.intervals.keys()) | set(other.intervals.keys())
        for v in all_vars:
            a = self.intervals.get(v)
            b = other.intervals.get(v)
            if a and b:
                joined.intervals[v] = a.join(b)
            elif a:
                joined.intervals[v] = Interval(a.low, a.high)
            else:
                joined.intervals[v] = Interval(b.low, b.high)  # type: ignore
        joined.heap = self.heap.join(other.heap)
        joined.reachable = self.reachable or other.reachable
        return joined

    def widen(self, other: "AbstractState") -> "AbstractState":
        """Widening —— 用于循环头。"""
        widened = AbstractState()
        all_vars = set(self.intervals.keys()) | set(other.intervals.keys())
        for v in all_vars:
            a = self.intervals.get(v, Interval(None, None))
            b = other.intervals.get(v, Interval(None, None))
            widened.intervals[v] = a.widen(b)
        widened.heap = self.heap.join(other.heap)  # heap 不 widen (对象集合稳定)
        widened.reachable = True
        return widened
