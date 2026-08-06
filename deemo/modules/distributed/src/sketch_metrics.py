# 草图近似度量 — Count-Min + HyperLogLog 亚线性空间调度统计
#
# src/metrics.py 的 Counter/Histogram 在任务类型基数达百万级时内存线性增长。
# 调度器需追踪 "每种任务类型执行了多少次" 和 "有多少种不同的任务类型"——
# 精确计数需 O(N) 空间。对于 N=10^6 种任务类型，这是不可接受的。
#
# 本模块用两种经典近似数据结构:
#   Count-Min Sketch: 频率估计 O(log(1/δ)) 空间，保证 f̂ ≥ f，且
#     P(f̂ ≥ f + ε·||f||₁) ≤ δ。用于 "每种任务类型的执行次数"。
#   HyperLogLog: 基数估计 O(log log N) 空间，标准差 ≈ 1.04/√m。
#     用于 "有多少种不同的任务类型" (distinct count)。
#
# 关键: 两者都是可合并的 (mergeable) — 可将多个节点的 sketch 合并
# 得到全局估计，无需传输原始数据。这是分布式监控的基础。
# MimoSketch (IEEE TKDE 2025) 的分布式方向，本模块特化为调度度量。

from __future__ import annotations

import math
import struct
import random
from typing import List, Tuple


def _murmur_hash(key: str, seed: int) -> int:
    """MurmurHash 简化版 — 确定性 64-bit 哈希。"""
    h = seed
    data = key.encode('utf-8')
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        k = int.from_bytes(chunk.ljust(8, b'\x00'), 'little')
        k = (k * 0x87c37b91114253d5) & 0xFFFFFFFFFFFFFFFF
        k = ((k << 31) | (k >> 33)) & 0xFFFFFFFFFFFFFFFF
        k *= 0x4cf5ad432745937f
        k &= 0xFFFFFFFFFFFFFFFF
        h ^= k
        h = ((h << 27) | (h >> 37)) & 0xFFFFFFFFFFFFFFFF
        h = h * 5 + 0x52dce729
        h &= 0xFFFFFFFFFFFFFFFF
    h ^= len(data)
    h ^= h >> 33
    h *= 0xff51afd7ed558ccd
    h &= 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    return h


class CountMinSketch:
    """Count-Min Sketch — 点查询的频率估计。

    保证: f̂ ≥ f (单侧误差) 且 P(f̂ ≥ f + ε·||f||₁) ≤ δ。
    空间: d×w 个计数器，d = ⌈ln(1/δ)⌉, w = ⌈e/ε⌉。
    """

    def __init__(self, epsilon: float = 0.01, delta: float = 0.01,
                 seed: int = 42):
        self._eps = epsilon
        self._delta = delta
        d = max(2, int(math.ceil(math.log(1.0 / max(delta, 1e-9)))))
        w = max(10, int(math.ceil(math.e / max(epsilon, 1e-3))))
        self._d = d
        self._w = w
        self._table = [[0] * w for _ in range(d)]
        # 每行独立哈希种子
        rng = random.Random(seed)
        self._seeds = [rng.randint(1, 2**30) for _ in range(d)]

    def add(self, key: str, delta: int = 1):
        for row in range(self._d):
            col = _murmur_hash(key, self._seeds[row]) % self._w
            self._table[row][col] += delta

    def estimate(self, key: str) -> int:
        """返回频率估计 f̂ — 保证 f̂ ≥ f。"""
        estimates = []
        for row in range(self._d):
            col = _murmur_hash(key, self._seeds[row]) % self._w
            estimates.append(self._table[row][col])
        return min(estimates)

    def merge(self, other: "CountMinSketch") -> "CountMinSketch":
        """合并两个 sketch — 结果为逐单元格求和。"""
        if other._d != self._d or other._w != self._w:
            raise ValueError("sketch dimensions must match for merge")
        result = CountMinSketch(self._eps, self._delta, self._seeds[0])
        result._d = self._d
        result._w = self._w
        result._seeds = list(self._seeds)
        result._table = [
            [self._table[r][c] + other._table[r][c] for c in range(self._w)]
            for r in range(self._d)
        ]
        return result

    def total_count(self) -> int:
        """总插入次数的近似 (取第一行求和 / 平均)。"""
        return sum(self._table[0])


class HyperLogLog:
    """HyperLogLog — 基数估计 (distinct count)。

    空间: m 个寄存器，m = 2^p，标准误差 ≈ 1.04/√m。
    """

    def __init__(self, p: int = 12, seed: int = 42):
        # p=12 → m=4096 → std err ≈ 1.04/64 ≈ 1.6%
        self._p = p
        self._m = 1 << p
        self._registers = [0] * self._m
        rng = random.Random(seed)
        self._seed = rng.randint(1, 2**30)

    def add(self, key: str):
        h = _murmur_hash(key, self._seed)
        idx = h & (self._m - 1)         # 低 p 位 → 寄存器索引
        w = (h >> self._p) & 0x7FFFFFFF  # 剩余位
        rho = (w.bit_length() if w > 0 else 1)  # 前导零+1
        if rho > self._registers[idx]:
            self._registers[idx] = rho

    def estimate(self) -> int:
        """基数估计 — 不同 key 的数量。"""
        alpha_m = {
            16: 0.673, 32: 0.697, 64: 0.709, 128: 0.715,
            256: 0.718, 512: 0.719, 1024: 0.720, 2048: 0.720,
            4096: 0.721, 8192: 0.721,
        }.get(self._m, 0.7213 / (1.0 + 1.079 / self._m))

        Z = sum(2.0 ** (-r) for r in self._registers)
        E = alpha_m * self._m * self._m / Z

        # 小范围修正
        if E <= 2.5 * self._m:
            zeros = sum(1 for r in self._registers if r == 0)
            if zeros > 0:
                E = self._m * math.log(self._m / max(zeros, 1))
        return max(1, int(E + 0.5))

    def merge(self, other: "HyperLogLog") -> "HyperLogLog":
        """合并 — 逐寄存器取最大值 (可交换/可结合)。"""
        if other._m != self._m:
            raise ValueError("HLL register count must match")
        result = HyperLogLog(self._p, self._seed)
        result._registers = [
            max(self._registers[i], other._registers[i])
            for i in range(self._m)
        ]
        return result


class DecayingElasticSketch:
    """时衰弹性草图 — 自适应计数器分配 + 指数衰减 + 分布式合并。

    标准 Count-Min 的两个缺陷在调度度量中被放大:
      1. 固定宽度: 所有键共享相同数量的计数器——热点键被冷门键冲撞。
      2. 无衰减: 三个月前的任务类型与最近的任务类型同等权重。

    本实现:
      - 弹性计数器: 维护 heavy_keeper 列表 (精确计数, 最多 H 个)
        + 轻量 Count-Min 骨架 (近似计数, w×d 个计数器)。
        热点键 (估计频率 > 阈值) 从骨架提升到 heavy keeper。
      - 指数衰减: 周期性对骨架乘以衰减因子 γ ∈ (0, 1)。
        这等价于对历史加指数递减权重，保持 recent-heavy 特性。
      - 误差分析: 总误差 ≤ ε·||f_recent||₁ + (1-γ)·||f_old||₁。
        第二项是衰减引的额外误差——可控 (选择 γ 使其与 ε 同级)。

    合并支持: heavy_keeper 取并集，骨架逐单元格求和后衰减对齐。
    """

    def __init__(self, width: int = 200, depth: int = 4,
                 heavy_capacity: int = 256, decay_gamma: float = 0.99,
                 decay_interval: int = 1000, seed: int = 42):
        self._w = width
        self._d = depth
        self._H = heavy_capacity
        self._gamma = decay_gamma
        self._decay_interval = decay_interval
        self._op_count: int = 0
        # CM 骨架
        rng = random.Random(seed)
        self._seeds = [rng.randint(1, 2**30) for _ in range(depth)]
        self._table = [[0.0] * width for _ in range(depth)]
        # Heavy keeper: {key: exact_count}
        self._heavy: dict = {}
        # 提升阈值: 骨架估计超过此值的键提升到 heavy
        self._promote_threshold: float = 0.0

    def add(self, key: str, delta: float = 1.0):
        self._op_count += 1
        if self._op_count % self._decay_interval == 0:
            self._apply_decay()

        if key in self._heavy:
            self._heavy[key] += delta
            return

        # CM 骨架更新
        for row in range(self._d):
            col = _murmur_hash(key, self._seeds[row]) % self._w
            self._table[row][col] += delta

        # 检查是否应提升到 heavy
        est = self._estimate_cm(key)
        if est > self._promote_threshold and len(self._heavy) < self._H:
            self._heavy[key] = est
            # 从骨架减去已提升的计数 (避免重复)
            for row in range(self._d):
                col = _murmur_hash(key, self._seeds[row]) % self._w
                self._table[row][col] -= est
        elif len(self._heavy) >= self._H:
            # 更新阈值: 取 heavy 中位数作为新门槛
            vals = sorted(self._heavy.values())
            self._promote_threshold = vals[len(vals) // 2] if vals else 0.0
            # 淘汰低于阈值的 heavy
            to_evict = [k for k, v in self._heavy.items()
                       if v < self._promote_threshold]
            for k in to_evict:
                # 回退到骨架
                v = self._heavy.pop(k)
                for row in range(self._d):
                    col = _murmur_hash(k, self._seeds[row]) % self._w
                    self._table[row][col] += v

    def _estimate_cm(self, key: str) -> float:
        estimates = []
        for row in range(self._d):
            col = _murmur_hash(key, self._seeds[row]) % self._w
            estimates.append(self._table[row][col])
        return min(estimates)

    def estimate(self, key: str) -> float:
        if key in self._heavy:
            return self._heavy[key]
        return self._estimate_cm(key)

    def _apply_decay(self):
        for row in range(self._d):
            for c in range(self._w):
                self._table[row][c] *= self._gamma
        for k in list(self._heavy):
            self._heavy[k] *= self._gamma
            if self._heavy[k] < 0.5:
                del self._heavy[k]

    def heavy_hitters(self, top_k: int = 20) -> List[Tuple[str, float]]:
        items = [(k, v) for k, v in self._heavy.items()]
        items.sort(key=lambda x: -x[1])
        return items[:top_k]

    def merge(self, other: "DecayingElasticSketch") -> "DecayingElasticSketch":
        if other._w != self._w or other._d != self._d:
            raise ValueError("sketch dimensions must match")
        result = DecayingElasticSketch(
            self._w, self._d, self._H, self._gamma, self._decay_interval
        )
        result._table = [
            [self._table[r][c] + other._table[r][c] for c in range(self._w)]
            for r in range(self._d)
        ]
        result._heavy = dict(self._heavy)
        for k, v in other._heavy.items():
            result._heavy[k] = result._heavy.get(k, 0.0) + v
        result._seeds = list(self._seeds)
        return result

    @property
    def heavy_count(self) -> int:
        return len(self._heavy)


class SketchMetrics:
    """草图度量收集器 — 时衰弹性草图 + HyperLogLog 的一站式入口。

    内部使用 DecayingElasticSketch 替代 CountMinSketch:
      - 热点任务类型获得精确计数 (heavy keeper)
      - 冷门任务类型使用近似计数 (CM 骨架)
      - 周期性指数衰减保持 recent-heavy 特性
      - 所有组件可跨节点合并
    """

    def __init__(self, sketch_width: int = 200, sketch_depth: int = 4,
                 heavy_capacity: int = 256, decay_gamma: float = 0.99,
                 hll_precision: int = 12):
        self._esketch = DecayingElasticSketch(
            sketch_width, sketch_depth, heavy_capacity, decay_gamma
        )
        self._hll = HyperLogLog(hll_precision)
        self._exact_total: int = 0

    def record(self, task_type: str, count: int = 1):
        self._esketch.add(task_type, float(count))
        self._hll.add(task_type)
        self._exact_total += count

    def query_count(self, task_type: str) -> float:
        return self._esketch.estimate(task_type)

    def query_distinct(self) -> int:
        return self._hll.estimate()

    @property
    def total_count(self) -> int:
        return self._exact_total

    def top_k(self, candidates: List[str], k: int = 10
              ) -> List[Tuple[str, float]]:
        scored = [(t, self._esketch.estimate(t)) for t in candidates]
        scored.sort(key=lambda x: -x[1])
        return scored[:k]

    def heavy_hitters(self) -> List[Tuple[str, float]]:
        return self._esketch.heavy_hitters()

    def merge(self, other: "SketchMetrics") -> "SketchMetrics":
        merged = SketchMetrics.__new__(SketchMetrics)
        merged._esketch = self._esketch.merge(other._esketch)
        merged._hll = self._hll.merge(other._hll)
        merged._exact_total = self._exact_total + other._exact_total
        return merged

    def stats(self) -> dict:
        return {
            "total_count": self._exact_total,
            "distinct_estimate": self._hll.estimate(),
            "heavy_items": self._esketch.heavy_count,
            "memory_bytes": (
                self._esketch._w * self._esketch._d * 8
                + self._esketch._H * 64
                + self._hll._m * 1
            ),
        }
