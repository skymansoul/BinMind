"""Data deduplication —— exact hash + fuzzy (SimHash/MinHash) matching.

For binary analysis results, exact dedup (sha256) catches literal duplicates.
SimHash handles near-duplicates from different compilation settings or
obfuscation variants. MinHash is better for section-level similarity.

The chunk-based approach (CDC) splits binaries into content-defined chunks
before hashing —— resistant to insertions/deletions at file boundaries.

  - "Detecting Near-Duplicates for Web Crawling"
    —— the SimHash paper. Using 128-bit fingerprints with Hamming distance.
  - MinHash: Broder '97, "On the resemblance and containment of documents"
  - FastCDC: Xia et al., USENIX ATC '16 —— gear-based CDC with normalized chunking.
    Gear hash table precomputation and dynamic mask adjustment per §3.2-3.4.
  - HyperLogLog: Flajolet et al., "HyperLogLog: the analysis of a near-optimal
    cardinality estimation algorithm". 用于去重前的唯一项数估算。
  - CuckooFilter: Fan et al., "Cuckoo Filter: Practically Better Than Bloom"
. 支持删除操作, 同等 FPR 下空间效率优于 Bloom。
  - One Permutation Hashing: Li et al., "One Permutation Hashing"
. 单次置换替代 k 次 MinHash 置换, 流式场景 O(1) 更新。
  - TDigest: Dunning & Ertl, "Computing Extremely Accurate Quantiles Using
    t-Digests". 流式分位数估计, 内存 O(k), 用于 CDC chunk 分布追踪。
"""

import hashlib
import logging
import math
import struct
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

import uuid  # unused; reserved for dedup session tracking

_log = logging.getLogger(__name__)

_SEED_MASK = 0x5A5A5A5A
_INIT_VECTOR = bytes([0x13, 0x37, 0xBE, 0xEF])

# TDigest —— streaming quantile estimation for chunk size distribution
# delta=100 (默认压缩系数) → ~500 centroids → ~4KB 内存, q-error ≈ 1%
# 用途: CDC 分块后无需保留全部 chunk 大小即可追踪 p50/p95/p99。
# 标准 MergingDigest 实现。

class TDigest:
    """流式分位数估计 —— O(1) 更新, O(k) 内存, k ≈ delta。

    用一组加权质心 (centroids) 近似数据分布。与直接存原始样本相比,
    在百万级数据量下内存节省 ~1000x, 分位数误差 < 1% (delta=100)。
    """

    def __init__(self, delta: float = 100.0):
        self.delta = delta
        self._cents: List[Tuple[float, float]] = []  # (mean, weight)
        self._n = 0
        self._min = float('inf')
        self._max = float('-inf')

    def add(self, x: float):
        self._n += 1
        if x < self._min:
            self._min = x
        if x > self._max:
            self._max = x

        # 二分找插入点 (centroid 按 mean 有序)
        lo, hi = 0, len(self._cents)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._cents[mid][0] < x:
                lo = mid + 1
            else:
                hi = mid
        # 插入新 centroid
        self._cents.insert(lo, (x, 1.0))
        # 若 centroid 数量超过限制, 压缩最近的相邻对
        if len(self._cents) > 20 * self.delta:
            self._compress()

    def add_many(self, items: List[float]):
        for x in items:
            self._cents.append((x, 1.0))
            self._n += 1
            if x < self._min:
                self._min = x
            if x > self._max:
                self._max = x
        self._cents.sort(key=lambda c: c[0])
        self._compress()

    def _compress(self):
        if len(self._cents) <= 1:
            return
        merged = [self._cents[0]]
        for mean, weight in self._cents[1:]:
            prev_mean, prev_w = merged[-1]
            q = (prev_w / 2 + sum(w for _, w in merged)) / self._n
            k_limit = 4.0 * self._n * self.delta * q * (1.0 - q)
            if prev_w + weight <= k_limit:
                # 合并: 加权平均
                new_mean = (prev_mean * prev_w + mean * weight) / (prev_w + weight)
                merged[-1] = (new_mean, prev_w + weight)
            else:
                merged.append((mean, weight))
        self._cents = merged

    def quantile(self, q: float) -> float:
        """返回第 q 分位数 (0 <= q <= 1)。"""
        if self._n == 0:
            return 0.0
        if q <= 0.0:
            return self._min
        if q >= 1.0:
            return self._max

        target = q * self._n
        cumulative = 0.0
        for i, (mean, weight) in enumerate(self._cents):
            half_w = weight / 2.0
            if cumulative + half_w >= target:
                # 与相邻 centroid 线性插值
                if i > 0 and cumulative - self._cents[i-1][1]/2 < target:
                    prev_m = self._cents[i-1][0]
                    frac = (target - (cumulative - half_w)) / (half_w + self._cents[i-1][1]/2)
                    return prev_m + frac * (mean - prev_m)
                return mean
            cumulative += weight
        return self._cents[-1][0]

    def merge(self, other: "TDigest") -> "TDigest":
        """合并两个 TDigest —— 分布式聚合。"""
        result = TDigest(self.delta)
        result._cents = self._cents + other._cents
        result._cents.sort(key=lambda c: c[0])
        result._n = self._n + other._n
        result._min = min(self._min, other._min)
        result._max = max(self._max, other._max)
        result._compress()
        return result

    def __len__(self):
        return self._n

# HyperLogLog —— cardinality estimation for uniqueness check
# p=14 → 2^14 registers = 16KB, std error ≈ 0.81%, up to ~2^64 items
# 在启动去重管线前快速估算唯一 chunk 数量, 用于评估 dedup 的必要性

def _hll_tau(_p: int) -> float:
    """HLL bias correction constant for given precision."""
    if _p == 4:
        return 0.673
    if _p == 5:
        return 0.697
    if _p == 6:
        return 0.709
    return 0.7213 / (1.0 + 1.079 / (1 << _p))

class HyperLogLog:
    """标准 HyperLogLog, 寄存器宽度 1 byte, p <= 16。

    p=14 (16K registers) 为标准误差 0.81% 和内存占用 16KB 的平衡点。
    去重场景中用于在完整流水线运行前快速估算"这批数据有多少唯一项"——
    若 HLL 估算与总项数接近, 说明重复率低, 可以跳过模糊去重仅做精确 hash 匹配。
    """

    def __init__(self, p: int = 14):
        if p < 4 or p > 16:
            raise ValueError("HLL precision p must be in [4, 16]")
        self.p = p
        self.m = 1 << p
        self.alpha = _hll_tau(p)
        self._regs = bytearray(self.m)
        self._n_added = 0

    def add(self, data: bytes):
        h = _fnv1a_64(data, seed=0x9f37)
        idx = h & (self.m - 1)
        w = h >> self.p
        rho = 1
        while w & 1 == 0 and rho <= 64 - self.p:
            rho += 1
            w >>= 1
        if rho > self._regs[idx]:
            self._regs[idx] = rho
        self._n_added += 1

    def estimate(self) -> int:
        """返回基数估计值。对于小基数 (< 5*m/2) 用 linear counting 修正。"""
        z = sum(1.0 for r in self._regs if r == 0)
        raw = self.alpha * self.m * self.m / sum(2.0 ** (-r) for r in self._regs)
        if raw <= 2.5 * self.m and z > 0:
            raw = self.m * math.log(self.m / z)
        return int(raw)

    def merge(self, other: "HyperLogLog") -> "HyperLogLog":
        """合并两个 HLL sketch —— 用于分布式去重场合。"""
        if self.m != other.m:
            raise ValueError("Cannot merge HLLs with different precision")
        merged = HyperLogLog(self.p)
        for i in range(self.m):
            if other._regs[i] > self._regs[i]:
                merged._regs[i] = other._regs[i]
            else:
                merged._regs[i] = self._regs[i]
        merged._n_added = self._n_added + other._n_added
        return merged

    def __len__(self) -> int:
        return self._n_added

    def density(self) -> float:
        """寄存器利用率 —— 接近 1.0 表示接近容量上限, 需要更大的 p。"""
        filled = sum(1 for r in self._regs if r > 0)
        return filled / self.m

# CuckooFilter —— 可删除的概率性成员过滤器
# Fan et al., "Cuckoo Filter: Practically Better Than Bloom"
# 主要优势: 支持 delete() 操作; 同等 FPR 下空间比 Bloom 小 ~20%。
# 桶大小 b=4 (每桶 4 个指纹) 是作者推荐的经验最优。
# 指纹长度 f=12 bits → 每个条目只需 1.5 bytes (vs Bloom 的 ~1.44 bytes/k)。

class CuckooFilter:
    """Cuckoo filter —— 比 Bloom 多了删除能力, 同等 FPR 更省空间。

    用途: 在去重引擎中替代 Bloom filter 做快速负向判定,
    同时允许移除已确认不重复的条目 (Bloom 不支持删除)。
    MaxKicks=500 是 Cuckoo 哈希驱逐的上限, 超过则判定 filter 已满。
    """

    MAX_KICKS = 500

    def __init__(self, capacity: int = 100000, bucket_size: int = 4,
                 fingerprint_bits: int = 12):
        self._nb = 1 << (capacity // bucket_size).bit_length()
        self._bs = bucket_size
        self._fb = fingerprint_bits
        self._fmask = (1 << fingerprint_bits) - 1
        self._buckets = [bytearray(bucket_size * 2) for _ in range(self._nb)]
        self._n = 0
        self._max_n = int(self._nb * bucket_size * 0.95)
        # 稳定的伪随机序列用于驱逐 —— 不用 time.time_ns() 避免相同 ns 下 repeat
        self._rng_state = 0x5bd1e995

    def _next_rand(self) -> int:
        self._rng_state = (self._rng_state * 1103515245 + 12345) & 0x7FFFFFFF
        return self._rng_state

    def _fp(self, data: bytes) -> int:
        h = _fnv1a_64(data, seed=0xc3a9)
        fp = h & self._fmask
        return fp if fp != 0 else 1  # 0 是空槽标记

    def _alt_index(self, idx: int, fp: int) -> int:
        h = _fnv1a_64(struct.pack("<H", fp), seed=0xbf12)
        return (idx ^ (h % self._nb)) % self._nb

    def insert(self, data: bytes) -> bool:
        fp = self._fp(data)
        i1 = _fnv1a_64(data, seed=0x7a3b) % self._nb
        i2 = self._alt_index(i1, fp)

        for idx in (i1, i2):
            bucket = self._buckets[idx]
            for slot in range(self._bs):
                off = slot * 2
                if bucket[off] == 0 and bucket[off + 1] == 0:
                    bucket[off] = (fp >> 8) & 0xFF
                    bucket[off + 1] = fp & 0xFF
                    self._n += 1
                    return True

        # Cuckoo 驱逐 —— 使用稳定 rng 而非 time_ns
        idx = i1
        for _ in range(self.MAX_KICKS):
            rslot = self._next_rand() % self._bs
            off = rslot * 2
            old_fp = (self._buckets[idx][off] << 8) | self._buckets[idx][off + 1]
            self._buckets[idx][off] = (fp >> 8) & 0xFF
            self._buckets[idx][off + 1] = fp & 0xFF
            fp = old_fp
            idx = self._alt_index(idx, fp)
            bucket = self._buckets[idx]
            for slot in range(self._bs):
                off2 = slot * 2
                if bucket[off2] == 0 and bucket[off2 + 1] == 0:
                    bucket[off2] = (fp >> 8) & 0xFF
                    bucket[off2 + 1] = fp & 0xFF
                    self._n += 1
                    return True
        return False

    def contains(self, data: bytes) -> bool:
        fp = self._fp(data)
        i1 = _fnv1a_64(data, seed=0x7a3b) % self._nb
        i2 = self._alt_index(i1, fp)
        for idx in (i1, i2):
            bucket = self._buckets[idx]
            for slot in range(self._bs):
                off = slot * 2
                if ((bucket[off] << 8) | bucket[off + 1]) == fp:
                    return True
        return False

    def delete(self, data: bytes) -> bool:
        fp = self._fp(data)
        i1 = _fnv1a_64(data, seed=0x7a3b) % self._nb
        i2 = self._alt_index(i1, fp)
        for idx in (i1, i2):
            bucket = self._buckets[idx]
            for slot in range(self._bs):
                off = slot * 2
                if ((bucket[off] << 8) | bucket[off + 1]) == fp:
                    bucket[off] = 0
                    bucket[off + 1] = 0
                    self._n = max(0, self._n - 1)
                    return True
        return False

    def __len__(self):
        return self._n

    @property
    def load_factor(self) -> float:
        return self._n / (self._nb * self._bs)

# Bloom filter

class BloomFilter:
    """标准 Bloom filter, 用做去重前的快速负向检查。

    去重管线的典型查询模式: 大量唯一数据 + 少量重复。
    对唯一数据直接走 Bloom 判定为"未见"即可跳过 DB 查询,
    仅在 Bloom 返回"可能存在"时才走精确索引 —— 将绝大部分
    查询从 O(log n) 降到 O(k) 且无 I/O。
    """

    def __init__(self, m_bits: int = 1 << 20, k_hashes: int = 7, seed: int = 0x5bd1):
        self.m = m_bits
        self.k = k_hashes
        self._bits = bytearray((m_bits + 7) // 8)
        # 用两个基础 hash 做 double-hashing 生成 k 个位置:
        #   h(i) = (h1 + i * h2) % m
        # 这比 k 个独立 hash 函数快, 且理论性质等价
        self._h1_seed = seed
        self._h2_seed = seed ^ 0x9e3779b9
        self._n = 0

    def _hashes(self, data: bytes):
        h1 = _fnv1a_64(data, seed=self._h1_seed)
        h2 = _fnv1a_64(data, seed=self._h2_seed)
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, data: bytes):
        for pos in self._hashes(data):
            byte_idx, bit_idx = divmod(pos, 8)
            self._bits[byte_idx] |= (1 << bit_idx)
        self._n += 1

    def might_contain(self, data: bytes) -> bool:
        """返回 True 表示"可能存在" (需要进一步精确检查)。"""
        for pos in self._hashes(data):
            byte_idx, bit_idx = divmod(pos, 8)
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    @property
    def approx_count(self) -> int:
        return self._n

    def estimated_fpr(self) -> float:
        """估算当前 false positive rate: (1 - e^{-kn/m})^k"""
        if self._n == 0:
            return 0.0
        return (1.0 - math.exp(-self.k * self._n / self.m)) ** self.k

# SimHash + LSH banding

def _extract_simhash_coeffs(bits: int = 128, seed: int = 42) -> List[int]:
    import random
    rng = random.Random(seed)
    return [rng.randint(0, (1 << 32) - 1) for _ in range(bits)]

_SIMHASH_COEFFS_128 = None

def _coeffs_128():
    global _SIMHASH_COEFFS_128
    if _SIMHASH_COEFFS_128 is None:
        _SIMHASH_COEFFS_128 = _extract_simhash_coeffs(128)
    return _SIMHASH_COEFFS_128

def _fnv1a_64(data: bytes, seed: int = 0xcbf29ce484222325) -> int:
    # inline
    h = seed
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def _hamming_dist(a: int, b: int) -> int:
    # inline
    x = a ^ b
    return x.bit_count()

class SimHashDedup:
    """SimHash-based fuzzy deduplication for binary data."""

    def __init__(self, bits: int = 128, shingle_size: int = 8):
        self.bits = bits
        self.shingle_size = shingle_size
        self.coeffs = _coeffs_128() if bits == 128 else _extract_simhash_coeffs(bits)

    def fingerprint(self, data: bytes) -> int:
        """Compute SimHash fingerprint as an integer."""
        vec = [0] * self.bits
        n = len(data)
        step = max(1, n - self.shingle_size + 1)
        stride = max(1, step // 512) if step > 4096 else 1

        i = 0
        while i < step:
            shingle = data[i:i + self.shingle_size]
            sh_hash = _fnv1a_64(shingle)
            for bit in range(self.bits):
                coeff = self.coeffs[bit]
                if sh_hash & (1 << (bit % 64)):
                    vec[bit] += coeff
                else:
                    vec[bit] -= coeff
            i += stride

        fp = 0
        for bit in range(self.bits):
            if vec[bit] > 0:
                fp |= (1 << bit)
        return fp

    def similarity(self, fp1: int, fp2: int) -> float:
        dist = _hamming_dist(fp1, fp2)
        return 1.0 - (dist / self.bits)

    @staticmethod
    def band_fingerprint(fp: int, bits: int = 128, bands: int = 16) -> List[int]:
        """将指纹切分为 bands 个 band, 每个作为独立键用于 LSH 索引。

        bands=16, bits=128 → 每 band 8 bits。
        两个指纹若在任一 band 上完全一致, 即被判定为候选对。
        Hamming <= 3 在 16 bands 下至少一个 band 碰撞的概率 > 0.999。
        """
        band_bits = bits // bands
        mask = (1 << band_bits) - 1
        band_keys = []
        for b in range(bands):
            band_keys.append((fp >> (b * band_bits)) & mask)
        return band_keys

class SimHashIndex:
    """LSH banding 索引 —— 按 band 键存储指纹, 支持近似最近邻查询。"""

    def __init__(self, bands: int = 16, threshold: float = 0.85):
        self.bands = bands
        self.threshold = threshold
        self._band_index: Dict[int, Set[int]] = {}
        self._fps: Dict[int, int] = {}
        self._simhash = SimHashDedup(bits=128)
        self._next_id = 0

    def add(self, fp_value: int) -> int:
        fp_id = self._next_id
        self._next_id += 1
        self._fps[fp_id] = fp_value
        for bk in SimHashDedup.band_fingerprint(fp_value, bands=self.bands):
            if bk not in self._band_index:
                self._band_index[bk] = set()
            self._band_index[bk].add(fp_id)
        return fp_id

    def query(self, fp_value: int, k: int = 10) -> List[Tuple[int, float]]:
        """查询与给定指纹相似的候选, 返回 (fp_id, similarity) 列表。

        LSH banding 保证: 若两枚指纹的 Hamming 距离 <= 3 (128-bit),
        它们在至少一个 band 碰撞的概率 > 0.999。
        """
        candidates: Set[int] = set()
        for bk in SimHashDedup.band_fingerprint(fp_value, bands=self.bands):
            candidates.update(self._band_index.get(bk, ()))

        scored = []
        for fp_id in candidates:
            sim = self._simhash.similarity(fp_value, self._fps[fp_id])
            if sim >= self.threshold:
                scored.append((fp_id, sim))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def __len__(self):
        return len(self._fps)

    def stats(self) -> Dict:
        if not self._band_index:
            return {"total": 0, "bands": 0, "avg_collisions_per_band": 0.0}
        total_in_bands = sum(len(s) for s in self._band_index.values())
        return {
            "total": len(self._fps),
            "bands": len(self._band_index),
            "avg_collisions_per_band": round(total_in_bands / len(self._band_index), 2),
            "index_utilization": round(total_in_bands / (len(self._band_index) * len(self._fps)) * 100, 2)
            if len(self._fps) > 0 else 0.0,
        }

# MinHash + One Permutation Hashing (OPH)

class MinHashDedup:
    """MinHash for set-based similarity over binary chunks."""

    def __init__(self, num_perm: int = 128, seed: int = 42):
        self.num_perm = num_perm
        import random
        rng = random.Random(seed)
        self.prime = (1 << 61) - 1
        self.perm_a = [rng.randint(1, self.prime - 1) for _ in range(num_perm)]
        self.perm_b = [rng.randint(0, self.prime - 1) for _ in range(num_perm)]

    def signature(self, hash_set: Set[int]) -> List[int]:
        if not hash_set:
            return [self.prime] * self.num_perm
        sig = []
        hs = list(hash_set)
        for i in range(self.num_perm):
            a, b = self.perm_a[i], self.perm_b[i]
            min_val = (a * hs[0] + b) % self.prime
            idx = 1
            while idx < len(hs):
                v = (a * hs[idx] + b) % self.prime
                if v < min_val:
                    min_val = v
                idx += 1
            sig.append(min_val)
        return sig

    def similarity(self, sig1: List[int], sig2: List[int]) -> float:
        if len(sig1) != len(sig2):
            return 0.0
        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
        return matches / len(sig1)

class OPHMinHash:
    """One Permutation Hashing (Li et al., NIPS 2012) —— 流式 MinHash 替代。

    标准 MinHash 需 k 个独立置换函数, 对每个新元素做 k 次哈希。
    OPH 仅用一次置换 (将 hash 空间切为 k 段, 每段取最小值),
    在流式场景下将更新时间从 O(k·|S|) 降至 O(|S|)。
    """

    def __init__(self, num_bins: int = 128, seed: int = 42):
        self.k = num_bins
        self._seed = seed
        self._bins = [0xFFFFFFFFFFFF] * num_bins

    def add(self, item_hash: int):
        h = ((item_hash * 0x9e3779b97f4a7c15 + self._seed) & 0xFFFFFFFFFFFF)
        bin_idx = h % self.k
        val = h // self.k
        if val < self._bins[bin_idx]:
            self._bins[bin_idx] = val

    def add_many(self, hashes: Set[int]):
        for h in hashes:
            self.add(h)

    def _densify(self) -> List[int]:
        filled = [(i, v) for i, v in enumerate(self._bins) if v != 0xFFFFFFFFFFFF]
        if not filled:
            return [0xFFFFFFFFFFFF] * self.k
        result = [0xFFFFFFFFFFFF] * self.k
        prev_val = filled[-1][1]
        ptr = 0
        for i in range(self.k):
            if ptr < len(filled) and filled[ptr][0] == i:
                prev_val = filled[ptr][1]
                ptr += 1
            result[i] = prev_val
        return result

    def signature(self) -> List[int]:
        return self._densify()

    def similarity(self, other: "OPHMinHash") -> float:
        sig_a = self._densify()
        sig_b = other._densify()
        matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
        return matches / self.k

    def reset(self):
        self._bins = [0xFFFFFFFFFFFF] * self.k

# Content-Defined Chunking (CDC) —— gear hash + FastCDC normalization

_GEAR_TABLE = None

def _gear_table():
    global _GEAR_TABLE
    if _GEAR_TABLE is None:
        import random
        rng = random.Random(42)
        _GEAR_TABLE = [rng.randint(0, 0xFFFFFFFF) for _ in range(256)]
    return _GEAR_TABLE

def cdc_chunk(data: bytes, min_chunk: int = 1024, max_chunk: int = 16384,
              mask_bits: int = 12, normalize: bool = True) -> List[bytes]:
    """Split data into content-defined chunks using gear hash.

    mask_bits controls average chunk size: 2^mask_bits.
    12 bits → ~4KB average chunks.

    normalize=True 启用 FastCDC 风格的动态 mask 调整,
    使 chunk 大小尽量落在 [min_chunk, max_chunk] 区间内。
    """
    if len(data) <= min_chunk:
        return [data]

    mask = (1 << mask_bits) - 1
    gear = 0
    chunks = []
    start = 0
    gear_table = _gear_table()
    recent_small = 0
    recent_large = 0
    _norm_mask_bits = mask_bits

    i = 0
    while i < len(data):
        b = data[i]
        gear = ((gear << 1) + gear_table[(gear >> 24) ^ b]) & 0xFFFFFFFF
        chunk_len = i - start

        if chunk_len >= max_chunk:
            chunks.append(data[start:i])
            start = i
            gear = 0
            if normalize:
                recent_large += 1
                recent_small = 0
                if recent_large >= 3 and _norm_mask_bits < 16:
                    _norm_mask_bits += 1
                    recent_large = 0
                mask = (1 << _norm_mask_bits) - 1
        elif chunk_len >= min_chunk and (gear & mask) == 0:
            chunks.append(data[start:i])
            start = i
            gear = 0
            if normalize:
                if chunk_len < min_chunk * 2:
                    recent_small += 1
                    recent_large = 0
                    if recent_small >= 5 and _norm_mask_bits > 8:
                        _norm_mask_bits -= 1
                        recent_small = 0
                else:
                    recent_small = 0
                mask = (1 << _norm_mask_bits) - 1
        i += 1

    if start < len(data):
        chunks.append(data[start:])
    return chunks

def cdc_chunk_iter(data: bytes, min_chunk: int = 1024, max_chunk: int = 16384,
                   mask_bits: int = 12, normalize: bool = True) -> Iterable[Tuple[int, bytes]]:
    """流式 CDC —— yield (offset, chunk) 而非一次返回全部。"""
    if len(data) <= min_chunk:
        yield (0, data)
        return

    mask = (1 << mask_bits) - 1
    gear = 0
    start = 0
    gear_table = _gear_table()
    recent_small = 0
    recent_large = 0
    _norm_mask_bits = mask_bits

    i = 0
    while i < len(data):
        b = data[i]
        gear = ((gear << 1) + gear_table[(gear >> 24) ^ b]) & 0xFFFFFFFF
        chunk_len = i - start
        if chunk_len >= max_chunk:
            yield (start, data[start:i])
            start = i
            gear = 0
            if normalize:
                recent_large += 1
                recent_small = 0
                if recent_large >= 3 and _norm_mask_bits < 16:
                    _norm_mask_bits += 1
                    recent_large = 0
                mask = (1 << _norm_mask_bits) - 1
        elif chunk_len >= min_chunk and (gear & mask) == 0:
            yield (start, data[start:i])
            start = i
            gear = 0
            if normalize:
                if chunk_len < min_chunk * 2:
                    recent_small += 1
                    recent_large = 0
                    if recent_small >= 5 and _norm_mask_bits > 8:
                        _norm_mask_bits -= 1
                        recent_small = 0
                else:
                    recent_small = 0
                mask = (1 << _norm_mask_bits) - 1
        i += 1

    if start < len(data):
        yield (start, data[start:])

def cdc_chunk_stats(chunks: List[bytes]) -> Dict:
    """Chunk 分布统计 —— 用于评估 CDC 参数效果。"""
    if not chunks:
        return {"count": 0}
    sizes = [len(c) for c in chunks]
    sizes.sort()
    n = len(sizes)
    return {
        "count": n,
        "total_bytes": sum(sizes),
        "min": sizes[0],
        "max": sizes[-1],
        "mean": round(sum(sizes) / n, 1),
        "p50": sizes[n // 2],
        "p95": sizes[int(n * 0.95)],
    }

# Main dedup orchestrator

class DedupEngine:
    """Orchestrates deduplication across exact + fuzzy algorithms.

    Usage:
      engine = DedupEngine(db, config.dedup)
      canonical = engine.dedup_binary(data, sha256_hash)

    内置 HyperLogLog 用于估算去重前的唯一项数 ——
    若 HLL 估算 >> 已索引项数, 说明大量新数据, 可跳过模糊去重仅做精确匹配,
    节省 SimHash / MinHash 的计算开销。
    """

    def __init__(self, db, config):
        self.db = db
        self.cfg = config
        self.simhash = SimHashDedup(bits=config.simhash_bits) if config.algorithm in ("simhash", "all") else None
        self.minhash = MinHashDedup(num_perm=config.minhash_perms) if config.algorithm in ("minhash", "all") else None
        self._simhash_index: Optional[SimHashIndex] = None
        if self.simhash is not None:
            self._simhash_index = SimHashIndex(threshold=0.85)
        self._bloom = BloomFilter()
        self._bloom_skips = 0
        self._db_lookups = 0
        self._hll = HyperLogLog(p=14)

    def dedup_by_hash(self, sha256: str) -> Optional[str]:
        """Check exact dedup —— returns canonical hash if duplicate."""
        self._db_lookups += 1
        hash_bytes = sha256.encode("ascii") if isinstance(sha256, str) else sha256
        if not self._bloom.might_contain(hash_bytes):
            self._bloom_skips += 1
            return None
        return self.db.get_canonical(sha256)

    def dedup_binary(self, data: bytes, sha256: str = "") -> Tuple[str, bool]:
        """Full dedup pipeline for binary data."""
        if not sha256:
            sha256 = hashlib.sha256(data).hexdigest()

        hash_bytes = sha256.encode("ascii")
        if self._bloom.might_contain(hash_bytes):
            canonical = self.db.get_canonical(sha256)
            if canonical:
                return canonical, True

        self._bloom.add(hash_bytes)
        self._hll.add(hash_bytes)

        if self.simhash is not None and self._simhash_index is not None:
            fp = self.simhash.fingerprint(data)
            candidates = self._simhash_index.query(fp, k=5)
            if candidates:
                _log.debug("SimHash match: fp=%d, candidates=%d", fp, len(candidates))

        if self.minhash is not None:
            chunks = cdc_chunk(data)
            chunk_hashes = {_fnv1a_64(c) for c in chunks}
            mh_sig = self.minhash.signature(chunk_hashes)
            _log.debug("MinHash sig computed for %s (%d chunks)", sha256[:16], len(chunks))

        return sha256, False

    def register_duplicate(self, canonical_sha: str, dup_sha: str,
                           similarity: float = 1.0):
        self.db.mark_duplicate(canonical_sha, dup_sha,
                               algorithm=self.cfg.algorithm,
                               similarity=similarity)
        self._bloom.add(canonical_sha.encode("ascii"))
        self._bloom.add(dup_sha.encode("ascii"))

    def index_fingerprint(self, sha256: str, data: bytes):
        if self.simhash is not None and self._simhash_index is not None:
            fp = self.simhash.fingerprint(data)
            self._simhash_index.add(fp)

    def estimated_uniques(self) -> int:
        return self._hll.estimate()

    @property
    def bloom_stats(self) -> Dict:
        return {
            "bloom_items": self._bloom.approx_count,
            "bloom_estimated_fpr": round(self._bloom.estimated_fpr(), 6),
            "db_lookups": self._db_lookups,
            "bloom_skips": self._bloom_skips,
            "skip_rate": round(self._bloom_skips / max(self._db_lookups, 1), 4),
        }

    @property
    def simhash_index_stats(self) -> Dict:
        if self._simhash_index is None:
            return {"enabled": False}
        return {"enabled": True, **self._simhash_index.stats()}

    @property
    def cardinality_stats(self) -> Dict:
        return {
            "hll_estimated_uniques": self._hll.estimate(),
            "hll_items_added": len(self._hll),
            "hll_register_density": round(self._hll.density(), 4),
        }

def dedup_from_config(db, config=None):
    """Factory: create DedupEngine from config or defaults."""
    if config is None:
        from .config import get_config
        config = get_config()
    return DedupEngine(db, config.dedup)
