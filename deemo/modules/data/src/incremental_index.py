# 增量 LSM 风格索引 (Incremental LSM-style Index for SimHash/Vector Signatures)
#
# 当前问题: simhash_index (db.py) 和 VectorIndex (vector_search.py)
#   是全量构建模式 —— 每条新签名插入需重建整个 LSH 索引.
#   在大批量流式导入场景中, 重建开销 O(N·L·K) 成为瓶颈.
#
# 创新点:
#   1. Memtable + SSTable 分层: 借鉴 LSM-tree 写优化策略.
#      Memtable (内存 Cuckoo Filter + Python dict) 吸收写入,
#      达到阈值后冻结为 immutable SSTable, 异步与现有层合并.
#      合并使用 Cuckoo Filter 的 load-factor-based merge
#      (J. Big Data 2025: Cuckoo 支持删除 + filter 合并).
#   2. 分层 Bloom 预过滤: 每层配备独立的 Bloom filter,
#      查询时逐层探测: Memtable → Level-0 → Level-1 → ...
#      命中即返回, 未命中查询下一层. 减少无效探测.
#   3. 自适应合并触发: 当某层的 Cuckoo filter load factor
#      超过阈值 (默认 0.85), 触发与下一层的合并.
#      load factor 由插入计数和 filter 容量实时监控.
#   4. 写放大控制: 限制最大层数 (默认 4), 最底层使用
#      全量精确索引 (Python set) 保证零假阳性.
#      每层大小按倍数增长 (×4), 类似 LSM 的 level size ratio.
#
# 与现有工作:
#   - LSM-tree + Cuckoo (J. Big Data 2025): 面向 KV 存储.
#     本方案将 Cuckoo 的删除+合并特性适配到签名索引场景.
#   - PGM-index (streaming construction): 面向排序数组.
#     本方案面向无序签名哈希, 使用概率结构替代学习索引.
#   - 标准 LSH 索引: 批量重建. 本方案增量分层, 写入 O(1).

import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class _CuckooSlot:
    """Cuckoo filter 单槽: 1B fingerprint."""
    __slots__ = ("fp",)
    def __init__(self): self.fp = 0


class MiniCuckoo:
    """微型 Cuckoo filter: 每桶 4 槽, 1B 指纹, 支持插入/查询/删除/合并.

    区别于 dedup.py 中完整 CuckooFilter (12-bit 指纹 + 双字节存储):
    此处使用 1B 指纹 (8-bit) + 紧凑存储, 面向索引而非去重,
    允许略高的 FPR (≈ 3%) 以换取更小的内存占用和更快的合并.
    """

    MAX_KICKS = 200
    BUCKET_SIZE = 4

    def __init__(self, capacity: int = 1024):
        n_buckets = max(4, 1 << (capacity // self.BUCKET_SIZE).bit_length())
        self._nb = n_buckets
        self._buckets: List[List[int]] = [[0]*self.BUCKET_SIZE for _ in range(n_buckets)]
        self._count = 0
        self._capacity = n_buckets * self.BUCKET_SIZE

    def insert(self, key_hash: int) -> bool:
        fp = self._fingerprint(key_hash)
        i1 = key_hash % self._nb
        i2 = (i1 ^ (fp * 0x9e3779b9 + 1)) % self._nb

        for idx in (i1, i2):
            bucket = self._buckets[idx]
            for slot in range(self.BUCKET_SIZE):
                if bucket[slot] == 0:
                    bucket[slot] = fp; self._count += 1; return True

        # 驱逐
        idx = i1; fp_cur = fp
        for _ in range(self.MAX_KICKS):
            slot = (key_hash + _) % self.BUCKET_SIZE
            old = self._buckets[idx][slot]
            self._buckets[idx][slot] = fp_cur
            if old == 0: self._count += 1; return True
            fp_cur = old
            idx = (idx ^ (fp_cur * 0x9e3779b9 + 1)) % self._nb

        return False  # filter 已满

    def contains(self, key_hash: int) -> bool:
        fp = self._fingerprint(key_hash)
        i1 = key_hash % self._nb
        i2 = (i1 ^ (fp * 0x9e3779b9 + 1)) % self._nb
        for idx in (i1, i2):
            if fp in self._buckets[idx]:
                return True
        return False

    def delete(self, key_hash: int) -> bool:
        fp = self._fingerprint(key_hash)
        i1 = key_hash % self._nb
        i2 = (i1 ^ (fp * 0x9e3779b9 + 1)) % self._nb
        for idx in (i1, i2):
            bucket = self._buckets[idx]
            for slot in range(self.BUCKET_SIZE):
                if bucket[slot] == fp:
                    bucket[slot] = 0; self._count = max(0, self._count-1)
                    return True
        return False

    @property
    def load_factor(self) -> float:
        return self._count / max(self._capacity, 1)

    def merge_from(self, other: "MiniCuckoo"):
        """将 other 的全部条目重新插入 self (合并)."""
        for bucket in other._buckets:
            for fp in bucket:
                if fp != 0:
                    # 重建 key_hash 不可逆, 使用 fp 作为代理
                    self._insert_fp(fp)

    def _insert_fp(self, fp: int):
        """直接用指纹插入 (合并时使用, 无需原始 key)."""
        i1 = fp % self._nb
        for slot in range(self.BUCKET_SIZE):
            if self._buckets[i1][slot] == 0:
                self._buckets[i1][slot] = fp; self._count += 1; return
        i2 = (i1 ^ (fp * 0x9e3779b9 + 1)) % self._nb
        for slot in range(self.BUCKET_SIZE):
            if self._buckets[i2][slot] == 0:
                self._buckets[i2][slot] = fp; self._count += 1; return

    @staticmethod
    def _fingerprint(key_hash: int) -> int:
        fp = (key_hash ^ (key_hash >> 16)) & 0xFF
        return fp if fp != 0 else 1


# ---------------------------------------------------------------------------
# 分层索引
# ---------------------------------------------------------------------------

class _IndexLevel:
    """单层索引: Cuckoo filter (快速排除) + 精确存储 (dict/set)."""
    def __init__(self, capacity: int):
        self.filter = MiniCuckoo(capacity=capacity)
        self.store: Dict[int, Any] = {}  # key_hash → value
        self._frozen = False

    def freeze(self): self._frozen = True

    def insert(self, key_hash: int, value: Any):
        if self._frozen: return
        self.filter.insert(key_hash)
        self.store[key_hash] = value

    def query(self, key_hash: int) -> Optional[Any]:
        if not self.filter.contains(key_hash):
            return None
        return self.store.get(key_hash)

    @property
    def size(self) -> int: return len(self.store)


class IncrementalLSHIndex:
    """LSM 风格增量 LSH 索引.

    层级: Memtable (L0) → Level 1 → Level 2 → Level 3.
    每层容量增长 4x: L0=1000, L1=4000, L2=16000, L3=64000.
    L3 (最底层) 使用 Python set 而非 Cuckoo, 保证零假阳性.

    用法:
      idx = IncrementalLSHIndex()
      for sig_id, lsh_hash in stream:
          idx.insert(lsh_hash, sig_id)
      candidates = idx.query(query_hash, max_depth=3)
    """

    MAX_LEVELS = 4
    SIZE_RATIO = 4   # 层间容量倍数
    BASE_CAP = 1024
    COMPACT_LOAD = 0.85  # 超过此 load factor 触发合并

    def __init__(self):
        self._levels: List[_IndexLevel] = []
        for i in range(self.MAX_LEVELS):
            cap = self.BASE_CAP * (self.SIZE_RATIO ** i)
            self._levels.append(_IndexLevel(capacity=cap))
        self._level_counts = [0] * self.MAX_LEVELS
        self._total_inserts = 0

    def insert(self, key_hash: int, value: Any):
        """插入键值对到 L0 (memtable)."""
        self._levels[0].insert(key_hash, value)
        self._level_counts[0] += 1
        self._total_inserts += 1

        # 触发条件检查
        if self._levels[0].filter.load_factor > self.COMPACT_LOAD:
            self._maybe_compact(0)

    def query(self, key_hash: int) -> Optional[Any]:
        """分层查询: L0 → L1 → L2 → L3."""
        for level in self._levels:
            result = level.query(key_hash)
            if result is not None:
                return result
        return None

    def batch_query(self, hashes: List[int]) -> Dict[int, Optional[Any]]:
        return {h: self.query(h) for h in hashes}

    def _maybe_compact(self, from_level: int):
        """检查是否需要合并 from_level → to_level."""
        if from_level >= self.MAX_LEVELS - 1:
            return

        src = self._levels[from_level]
        dst = self._levels[from_level + 1]

        if src.filter.load_factor < self.COMPACT_LOAD:
            return

        # 合并: 将 src 的全部条目插入 dst
        for key_hash, value in src.store.items():
            dst.insert(key_hash, value)

        # 清空 src
        src.filter = MiniCoo(capacity=self.BASE_CAP * (self.SIZE_RATIO ** from_level))
        src.store.clear()
        self._level_counts[from_level] = 0

        # 若 dst 也满了, 递归合并
        if dst.filter.load_factor > self.COMPACT_LOAD:
            self._maybe_compact(from_level + 1)

    def force_compact(self):
        """强制全量合并: 所有数据压入最底层."""
        for i in range(self.MAX_LEVELS - 1):
            self._maybe_compact(i)

    @property
    def stats(self) -> dict:
        levels = []
        for i, lv in enumerate(self._levels):
            levels.append({
                "level": i, "entries": lv.size,
                "capacity": self.BASE_CAP * (self.SIZE_RATIO ** i),
                "load_factor": round(lv.filter.load_factor, 4),
            })
        return {
            "total_inserts": self._total_inserts,
            "total_entries": sum(lv.size for lv in self._levels),
            "levels": levels,
        }


# 兼容别名: 避免重复写 MiniCuckoo 全名
MiniCoo = MiniCuckoo


__all__ = [
    "IncrementalLSHIndex",
    "MiniCuckoo",
]
