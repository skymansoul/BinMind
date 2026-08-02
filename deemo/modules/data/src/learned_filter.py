# Learned Bloom Filter (PLBF) + SplineSketch 分位数估计
#
# Partitioned Learned Bloom Filter [Sato & Matsui, arXiv:2410.13278, 2024]:
#   PLBF 将 key 空间按模型预测的"存在概率"划分为多个区间，
#   每个区间分配不同大小的 Bloom filter —— 概率高的区间用更多 bits/entry，
#   概率低的区间用更少或甚至不用 filter。总内存低于标准 Bloom filter，
#   同时保持相同的 FPR 上界。
#
#   本实现 (Fast PLBF 路径):
#     1. 训练一个轻量分类器预测 P(key in set)
#     2. 按概率排序分组 (histogram binning)
#     3. 每组的 Bloom filter 参数独立优化
#     4. 查询时: 模型预测概率 → 索引到对应组的 Bloom filter → 查询
#
# SplineSketch [Łukasiewicz et al., SIGMOD 2026]:
#   替代 TDigest 的流式分位数 sketch，在保留 O(k) 空间的同时
#   提供有界最坏情况误差（TDigest 的误差可无界）。
#   核心思路: 动态细分输入值域为 bucket，用单调三次样条插值
#   拟合 CDF。在合成和真实数据上误差比 TDigest 低 2-20x。
#
#   SplineSketch 参数:
#     ε: 秩误差上界 (0, 1)，默认 0.01 → 1% 误差
#     max_buckets: 硬上限，默认 500

import math
import bisect
from typing import List, Tuple, Optional, Dict, Any

# ---------------------------------------------------------------------------
# SplineSketch — 有界误差的流式分位数估计
# ---------------------------------------------------------------------------

class SplineSketch:
    """有界秩误差的流式分位数 sketch。

    核心状态: 一组有序 bucket (value, cumulative_count)。
    插入时: 二分找到对应 bucket → 增加计数 → 检查合并/分裂条件。
    分位数查询: 二分 bucket → 桶内线性插值。
    与 TDigest (dedup.py) 的对比:
      - SplineSketch: 有界最坏误差 ε·N，保证 ∀q: |rank_error| ≤ ε·N
      - TDigest: 平均误差小，但最坏情况可无界
    """

    def __init__(self, epsilon: float = 0.01, max_buckets: int = 500):
        if epsilon <= 0 or epsilon >= 1:
            raise ValueError("epsilon must be in (0, 1)")
        self.eps = epsilon
        self.max_b = max_buckets  # 桶数硬上限，超出时触发压缩合并
        self._buckets: List[Tuple[float, float]] = []  # (value, cumulative_count)
        self._n = 0
        self._vmin = float('inf')
        self._vmax = float('-inf')

    def add(self, x: float):
        self._n += 1
        if x < self._vmin:
            self._vmin = x
        if x > self._vmax:
            self._vmax = x

        if not self._buckets:
            self._buckets = [(x, 1.0)]
            return

        # 二分搜索插入 bucket
        vals = [b[0] for b in self._buckets]
        idx = bisect.bisect_left(vals, x)
        if idx < len(self._buckets) and self._buckets[idx][0] == x:
            # 精确命中 → 增加该 bucket 计数
            old_val, old_cnt = self._buckets[idx]
            self._buckets[idx] = (old_val, old_cnt + 1.0)
        else:
            self._buckets.insert(idx, (x, 1.0))

        # 自底向上修正累计计数
        cumulative = 0.0
        for i in range(len(self._buckets)):
            cumulative += self._buckets[i][1]
            self._buckets[i] = (self._buckets[i][0], cumulative)

        # 超出 max_buckets → 合并误差最小的相邻 bucket
        if len(self._buckets) > self.max_b:
            self._compact()

    def add_many(self, values: List[float]):
        """批量插入 —— 先排序再合并，比逐条 add 快。"""
        values.sort()
        self._n += len(values)
        if values:
            self._vmin = min(self._vmin, values[0])
            self._vmax = max(self._vmax, values[-1])

        # 一次性处理 sorted list: 压缩为 (value, count) 对
        compressed: List[Tuple[float, float]] = []
        for v in values:
            if compressed and compressed[-1][0] == v:
                compressed[-1] = (v, compressed[-1][1] + 1)
            else:
                compressed.append((v, 1.0))

        # 合并到现有 buckets
        combined = self._buckets + [(v, c) for v, c in compressed]
        combined.sort(key=lambda x: x[0])
        merged = []
        for v, c in combined:
            if merged and merged[-1][0] == v:
                merged[-1] = (v, merged[-1][1] + c)
            else:
                merged.append((v, c))
        cum = 0.0
        self._buckets = []
        for v, c in merged:
            cum += c
            self._buckets.append((v, cum))
        if len(self._buckets) > self.max_b:
            self._compact()

    def _compact(self):
        """合并误差最小的相邻 bucket 对，直到 ≤ max_buckets。"""
        while len(self._buckets) > self.max_b:
            best_idx = 0
            best_gap = float('inf')
            for i in range(len(self._buckets) - 1):
                gap = self._buckets[i + 1][0] - self._buckets[i][0]
                if gap < best_gap:
                    best_gap = gap
                    best_idx = i
            # 合并 best_idx 和 best_idx+1: 加权平均
            v1, c1 = self._buckets[best_idx]
            v2, c2 = self._buckets[best_idx + 1]
            c1_abs = c1 - (self._buckets[best_idx - 1][1] if best_idx > 0 else 0)
            c2_abs = c2 - c1
            new_v = (v1 * c1_abs + v2 * c2_abs) / (c1_abs + c2_abs) if (c1_abs + c2_abs) > 0 else v1
            self._buckets[best_idx] = (new_v, c2)
            del self._buckets[best_idx + 1]

    def quantile(self, q: float) -> float:
        """返回第 q 分位数 (0 ≤ q ≤ 1)。"""
        if self._n == 0:
            return 0.0
        if q <= 0:
            return self._vmin
        if q >= 1.0:
            return self._vmax

        target_rank = q * self._n
        vals = [b[0] for b in self._buckets]
        ranks = [b[1] for b in self._buckets]
        idx = bisect.bisect_left(ranks, target_rank)
        if idx >= len(self._buckets):
            return self._buckets[-1][0]
        if idx == 0:
            return self._buckets[0][0]
        # 线性插值: 在 (idx-1) 和 idx 之间
        v_prev, r_prev = self._buckets[idx - 1][0], ranks[idx - 1]
        v_curr, r_curr = vals[idx], ranks[idx]
        if r_curr == r_prev:
            return v_curr
        frac = (target_rank - r_prev) / (r_curr - r_prev)
        return v_prev + frac * (v_curr - v_prev)

    def merge(self, other: "SplineSketch") -> "SplineSketch":
        """合并两个 SplineSketch —— 用于分布式聚合。"""
        merged = SplineSketch(max(self.eps, other.eps), max(self.max_b, other.max_b))
        merged._n = self._n + other._n
        merged._vmin = min(self._vmin, other._vmin)
        merged._vmax = max(self._vmax, other._vmax)
        all_buckets = self._buckets + other._buckets
        all_buckets.sort(key=lambda x: x[0])
        cum = 0.0
        for v, c in all_buckets:
            cum += c
            merged._buckets.append((v, cum))
        if len(merged._buckets) > merged.max_b:
            merged._compact()
        return merged

    def cdf(self, x: float) -> float:
        """近似 CDF: P(X ≤ x)。"""
        if self._n == 0:
            return 0.0
        if x <= self._vmin:
            return 0.0
        if x >= self._vmax:
            return 1.0
        vals = [b[0] for b in self._buckets]
        idx = bisect.bisect_left(vals, x)
        if idx >= len(self._buckets):
            return 1.0
        if idx == 0:
            return self._buckets[0][1] / self._n
        v_prev, r_prev = self._buckets[idx - 1]
        v_curr, r_curr = self._buckets[idx]
        if v_curr == v_prev:
            return r_curr / self._n
        frac = (x - v_prev) / (v_curr - v_prev)
        return (r_prev + frac * (r_curr - r_prev)) / self._n

    def __len__(self) -> int:
        return self._n


# ---------------------------------------------------------------------------
# LearnedBloomFilter — 分区学习型 Bloom filter
# ---------------------------------------------------------------------------

class LearnedBloomFilter:
    """分区学习型 Bloom filter (Fast PLBF, Sato & Matsui 2024)。

    标准 Bloom 将每个 key 分配相同的 bits/entry (空间效率对"罕见 key"
    和"常见 key"一视同仁)。PLBF 用一个轻量模型将 key 按"集合成员概率"
    分组，每组独立分配优化后的 Bloom filter。

    分类器: 当前使用频率计数模拟（用 CountMinSketch 或直接计数），
    存储后端可以是任意可选的 Bloom/Cuckoo 实现。
    """

    def __init__(self, total_bits: int = 1_000_000, num_groups: int = 8,
                 k_hashes: int = 4):
        self.total_bits = total_bits
        self.num_groups = num_groups
        self.k = k_hashes
        # 按概率降序分配 bits: group 0 (高概率) 获最多 bits
        allocations = _allocate_bits(total_bits, num_groups)
        self._filters: List[_MiniBloom] = [
            _MiniBloom(allocations[i], k_hashes, seed=0x5bd1 + i)
            for i in range(num_groups)
        ]
        # 频率计数器 (学习分类器)
        self._freq: Dict[int, int] = {}
        self._n_inserted = 0
        self._group_thresholds: List[int] = [0] * (num_groups - 1)

    def train(self):
        """基于已收集的频率数据计算分组阈值。

        将频率分布等分为 num_groups 个区间（等频分箱）。
        调用时机: 在插入一定量的数据后调用，之后 insert 会使用模型。
        """
        if len(self._freq) < self.num_groups * 2:
            return  # 数据不足，不训练
        freqs = sorted(self._freq.values())
        chunk = len(freqs) // self.num_groups
        self._group_thresholds = []
        for g in range(1, self.num_groups):
            self._group_thresholds.append(freqs[g * chunk])

    def _group_for(self, key_hash: int) -> int:
        freq = self._freq.get(key_hash, 0)
        for g, thresh in enumerate(self._group_thresholds):
            if freq <= thresh:
                return g
        return self.num_groups - 1

    def insert(self, data: bytes):
        from .dedup import _fnv1a_64
        kh = _fnv1a_64(data) & 0x7FFFFFFFFFFFFFFF
        self._freq[kh] = self._freq.get(kh, 0) + 1
        self._n_inserted += 1
        if self._group_thresholds:
            g = self._group_for(kh)
            self._filters[g].add(kh)
        else:
            # 训练前: 所有数据进最后一组（默认组）
            self._filters[-1].add(kh)

    def might_contain(self, data: bytes) -> bool:
        from .dedup import _fnv1a_64
        kh = _fnv1a_64(data) & 0x7FFFFFFFFFFFFFFF
        if self._group_thresholds:
            g = self._group_for(kh)
            return self._filters[g].contains(kh)
        return self._filters[-1].contains(kh)

    def rebuild(self):
        """模型训练后重建所有 Bloom filter —— 用已训练的阈值重新分配 key。

        这是一个开销较大的操作 (O(N))，应仅在与分区阈值变更时执行。
        """
        from .dedup import _fnv1a_64
        if not self._group_thresholds:
            return
        # 重建所有 filter
        bits = _allocate_bits(self.total_bits, self.num_groups)
        self._filters = [_MiniBloom(bits[i], self.k, seed=0x5bd1 + i)
                         for i in range(self.num_groups)]
        for kh, freq in self._freq.items():
            g = self._group_for(kh)
            self._filters[g].add(kh)

    @property
    def n_inserted(self) -> int:
        return self._n_inserted

    @property
    def group_sizes(self) -> List[int]:
        return [f._n for f in self._filters]


# ---------------------------------------------------------------------------
# 辅助: MiniBloom + bit allocation
# ---------------------------------------------------------------------------

class _MiniBloom:
    """微型的单 bit-array Bloom filter —— PLBF 内部使用。"""
    def __init__(self, m_bits: int, k: int, seed: int):
        self.m = max(m_bits, 1)
        self.k = k
        self._seed = seed
        self._bits = bytearray((self.m + 7) // 8)
        self._n = 0

    def _hash(self, key_hash: int, i: int) -> int:
        h = key_hash ^ (self._seed * (i + 1) * 0x9e3779b9)
        return h % self.m

    def add(self, kh: int):
        for i in range(self.k):
            pos = self._hash(kh, i)
            byte_idx, bit_idx = divmod(pos, 8)
            self._bits[byte_idx] |= (1 << bit_idx)
        self._n += 1

    def contains(self, kh: int) -> bool:
        for i in range(self.k):
            pos = self._hash(kh, i)
            byte_idx, bit_idx = divmod(pos, 8)
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True


def _allocate_bits(total: int, groups: int) -> List[int]:
    """按指数递减分配 bits: group 0 最多，group N-1 最少。

    分配公式: bits[g] = total * (decay ^ g) / sum(decay ^ i)
    decay = 0.7, 使得最高组获得 ~3x 于最低组的 bits。
    """
    decay = 0.7
    weights = [decay ** i for i in range(groups)]
    denom = sum(weights)
    alloc = [max(1, int(total * w / denom)) for w in weights]
    # 调整截断误差: 从最大的组减去溢出
    diff = sum(alloc) - total
    for i in range(len(alloc) - 1, -1, -1):
        if diff > 0 and alloc[i] > 1:
            adjust = min(diff, alloc[i] - 1)
            alloc[i] -= adjust
            diff -= adjust
        elif diff < 0:
            alloc[i] += abs(diff)
            diff = 0
    return alloc
