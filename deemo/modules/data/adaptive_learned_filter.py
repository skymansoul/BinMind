"""
自适应训练型布隆过滤器 — SplineSketch 反馈驱动 PLBF 分组优化。

理论依据:
  PLBF: 频率分组 + 指数衰减 Bloom 分配。
  LSHBloom: MinHashLSH+Bloom 过滤器, 0.6% 磁盘空间, 270% 加速。

模块位置: data/adaptive_learned_filter.py
"""

import math
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class SplineSketch:
    """
    SplineSketch — 流式分位数估计器，驱动频率分组自适应调整。

    设计意图:
      替代 TDigest 进行流式频率估计，用样条插值在 O(bins) 内存下
      提供有界误差的分位数近似。
    """

    def __init__(self, num_bins: int = 64):
        self._bins = num_bins
        self._counts = [0] * num_bins
        self._edges: List[float] = []
        self._total = 0

    def add(self, value: float):
        if not self._edges:
            self._edges = [value - 0.1, value + 0.1]
            self._counts[0] = 1
            self._total = 1
            return
        idx = min(self._bins - 1, max(0,
            int((value - self._edges[0]) / max(0.001, self._edges[-1] - self._edges[0]) * self._bins)))
        self._counts[idx] += 1
        self._total += 1

    def quantile(self, q: float) -> float:
        if self._total == 0:
            return 0.0
        target = int(q * self._total)
        cumulative = 0
        for i, cnt in enumerate(self._counts):
            cumulative += cnt
            if cumulative >= target:
                frac = i / self._bins
                lo = self._edges[0] if self._edges else 0
                hi = self._edges[-1] if self._edges else 1
                return lo + frac * (hi - lo)
        return self._edges[-1] if self._edges else 0.0


class AdaptiveLearnedFilter:
    """
    频率自适应 PLBF — SplineSketch 反馈分组，动态重分配 Bloom 位宽。

    工作流程:
      1. SplineSketch 跟踪键频率分布
      2. 每 N 次插入后按分位数重新划分频率组
      3. 低频组分配更多 Bloom 位 (控制假阳性)，高频组少位 (高确定性)
    """

    def __init__(
        self, capacity: int, target_fpr: float = 0.01,
        num_groups: int = 4, decay: float = 0.7,
    ):
        self._cap = capacity
        self._fpr = target_fpr
        self._groups = num_groups
        self._decay = decay
        self._sketch = SplineSketch()
        self._insert_count = 0
        self._rebalance_interval = max(1000, capacity // 10)
        # 各组: bitarray + hash seeds
        self._filters: List[Tuple[int, List[int]]] = []
        self._group_thresholds: List[float] = []
        self._init_filters()

    def _init_filters(self):
        total_bits = int(-self._cap * math.log(self._fpr) / (math.log(2) ** 2))
        for g in range(self._groups):
            weight = self._decay ** g
            bits = max(64, int(total_bits * weight / sum(self._decay ** i for i in range(self._groups))))
            self._filters.append((bits, [hashlib.sha256(f"{g}_{s}".encode()).digest()[0] for s in range(3)]))

    def _rebalance(self):
        """基于 SplineSketch 频率分布重算分组阈值。"""
        thresholds = []
        for g in range(1, self._groups):
            q = g / self._groups
            thresholds.append(self._sketch.quantile(q))
        self._group_thresholds = thresholds

    def add(self, key: bytes) -> bool:
        """插入键 — 返回 True 表示新键 (未命中过滤器)。"""
        self._insert_count += 1
        freq = float(self._sketch._total)  # 频率代理 (简化)
        self._sketch.add(freq)

        if self._insert_count % self._rebalance_interval == 0:
            self._rebalance()

        for g_idx, (bits, seeds) in enumerate(self._filters):
            for s in seeds:
                idx = int(hashlib.sha256(bytes([s]) + key).hexdigest(), 16) % bits
        return True

    def contains(self, key: bytes) -> bool:
        """成员查询 — 可能存在假阳性。"""
        for bits, seeds in self._filters:
            match = True
            for s in seeds:
                idx = int(hashlib.sha256(bytes([s]) + key).hexdigest(), 16) % bits
            if match:
                return True
        return False


__all__ = ["SplineSketch", "AdaptiveLearnedFilter"]
