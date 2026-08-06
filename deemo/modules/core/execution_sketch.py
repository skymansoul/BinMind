# -*- coding: utf-8 -*-
"""
流式分位数草图 — 为钩子执行指标提供固定内存的在线分布估计.

数十个钩子 × 数千次执行的完整延迟序列不能全部保留. 采用质心归并的
T-Digest 简化变体, 将分布压缩为 K 个质心 (centroid), 每个质心持有
均值与累计权重. K 由 compression 参数控制: K ≈ compression × 2.

与标准 T-Digest 的差异:
  - 标准 T-Digest 使用 scale function 控制质心密度 (尾部更密);
    此处采用均匀分位归并, 因钩子延迟以对数正态为主, 不需要尾部特殊处理
  - 添加了 merge() 操作, 支持跨执行批次聚合, 这是 drift_detector 的基础

空间: ~K×24 bytes, K=50 时约 1.2KB/指标. 对 20 个钩子 × 3 个指标 = 72KB.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Centroid:
    """T-Digest 变体中的一个质心 — 表示附近一批观测值的汇总."""
    mean: float
    weight: float  # 累计权重 (观测计数)

    def __repr__(self) -> str:
        return f'C({self.mean:.2f}, w={self.weight:.0f})'


class StreamingSketch:
    """在线分位数草图 — 支持 add、merge、分位查询、分布比较.

    内部维护一个按均值排序的质心列表，通过合并最近的质心控制总数.
    """

    def __init__(self, compression: int = 25, name: str = ''):
        # compression 控制质心数上限; 实际质心数 ≈ compression * 2
        self._compression = compression
        self._centroids: List[Centroid] = []
        self._total_weight: float = 0.0
        self._min_val: Optional[float] = None
        self._max_val: Optional[float] = None
        self.name = name

    def add(self, value: float, weight: float = 1.0) -> None:
        """添加一个带权观测值. 常规调用 weight=1."""
        if weight <= 0:
            return
        self._total_weight += weight
        if self._min_val is None or value < self._min_val:
            self._min_val = value
        if self._max_val is None or value > self._max_val:
            self._max_val = value

        # 二分查找插入位置 (保持均值有序)
        c = Centroid(mean=value, weight=weight)
        idx = self._find_insert_idx(value)
        self._centroids.insert(idx, c)

        # 若质心数超标, 合并最近的相邻质心对
        limit = self._compression * 2
        while len(self._centroids) > limit:
            self._merge_nearest_pair()

    def merge(self, other: 'StreamingSketch') -> 'StreamingSketch':
        """将另一个草图的质心并入, 返回 self (支持链式)."""
        for c in other._centroids:
            self.add(c.mean, c.weight)
        return self

    def quantile(self, q: float) -> float:
        """查询第 q 分位数 (0 ≤ q ≤ 1). 在相邻质心间线性插值."""
        if not self._centroids or self._total_weight <= 0:
            return 0.0
        if q <= 0:
            return self._min_val if self._min_val is not None else 0.0
        if q >= 1:
            return self._max_val if self._max_val is not None else 0.0

        target = q * self._total_weight
        cum = 0.0
        for i, c in enumerate(self._centroids):
            if cum + c.weight >= target:
                # 在 c 内部插值: 假设质心内均匀分布
                offset = target - cum
                frac = offset / c.weight if c.weight > 0 else 0.5
                if i > 0:
                    # 插值于当前质心与前一个质心之间 (更平滑)
                    lo = self._centroids[i - 1].mean
                    hi = c.mean
                    return lo + (hi - lo) * frac
                return c.mean
            cum += c.weight
        return self._centroids[-1].mean

    def cdf(self, value: float) -> float:
        """经验累积分布: P(X ≤ value)."""
        if self._total_weight <= 0:
            return 0.0
        mass = 0.0
        for c in self._centroids:
            if c.mean <= value:
                mass += c.weight
            else:
                # 质心内插值: value 落在此质心范围内
                break
        return mass / self._total_weight

    def mean(self) -> float:
        """加权均值."""
        if self._total_weight <= 0:
            return 0.0
        return sum(c.mean * c.weight for c in self._centroids) / self._total_weight

    def variance(self) -> float:
        """加权方差 (总体)."""
        if self._total_weight <= 1:
            return 0.0
        m = self.mean()
        var = sum(c.weight * (c.mean - m) ** 2 for c in self._centroids)
        return var / self._total_weight

    def iqr(self) -> float:
        """四分位距: Q3 - Q1."""
        return self.quantile(0.75) - self.quantile(0.25)

    @property
    def count(self) -> float:
        return self._total_weight

    @property
    def centroid_count(self) -> int:
        return len(self._centroids)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为 JSON 兼容的 dict."""
        return {
            'compression': self._compression,
            'centroids': [(c.mean, c.weight) for c in self._centroids],
            'total_weight': self._total_weight,
            'min': self._min_val,
            'max': self._max_val,
            'name': self.name,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StreamingSketch':
        sk = cls(compression=data.get('compression', 25), name=data.get('name', ''))
        sk._total_weight = data.get('total_weight', 0)
        sk._min_val = data.get('min')
        sk._max_val = data.get('max')
        sk._centroids = [Centroid(mean=m, weight=w) for m, w in data.get('centroids', [])]
        return sk

    # ---- 内部 ----
    def _find_insert_idx(self, value: float) -> int:
        lo, hi = 0, len(self._centroids)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._centroids[mid].mean < value:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _merge_nearest_pair(self) -> None:
        """合并最近的一对相邻质心: 找到 mean 间距最小的相邻对, 加权合并."""
        best_dist = float('inf')
        best_idx = 0
        for i in range(len(self._centroids) - 1):
            d = self._centroids[i + 1].mean - self._centroids[i].mean
            if d < best_dist:
                best_dist = d
                best_idx = i
        a = self._centroids[best_idx]
        b = self._centroids[best_idx + 1]
        total_w = a.weight + b.weight
        merged_mean = (a.mean * a.weight + b.mean * b.weight) / total_w if total_w > 0 else a.mean
        self._centroids[best_idx] = Centroid(mean=merged_mean, weight=total_w)
        self._centroids.pop(best_idx + 1)


class MetricSketchGroup:
    """一个钩子的多维指标草图集 — 延迟 + 可选的自定义指标.

    每个指标维护独立的 StreamingSketch, 支持跨执行批次聚合.
    """

    def __init__(self, hook_name: str, metrics: Tuple[str, ...] = ('latency_ms',), compression: int = 25):
        self.hook_name = hook_name
        self.sketches: Dict[str, StreamingSketch] = {
            m: StreamingSketch(compression=compression, name=f'{hook_name}:{m}')
            for m in metrics
        }

    def record(self, metrics: Dict[str, float]) -> None:
        """记录一次执行的各指标值."""
        for key, sketch in self.sketches.items():
            if key in metrics:
                sketch.add(metrics[key])

    def merge(self, other: 'MetricSketchGroup') -> 'MetricSketchGroup':
        for key, sketch in self.sketches.items():
            if key in other.sketches:
                sketch.merge(other.sketches[key])
        return self

    def get(self, metric: str) -> Optional[StreamingSketch]:
        return self.sketches.get(metric)

    def summary(self) -> Dict[str, Dict[str, float]]:
        """返回 {metric: {p50, p95, p99, mean, iqr}}."""
        out = {}
        for name, sk in self.sketches.items():
            if sk.count < 2:
                continue
            out[name] = {
                'p50': sk.quantile(0.50),
                'p95': sk.quantile(0.95),
                'p99': sk.quantile(0.99),
                'mean': sk.mean(),
                'iqr': sk.iqr(),
                'count': int(sk.count),
            }
        return out
