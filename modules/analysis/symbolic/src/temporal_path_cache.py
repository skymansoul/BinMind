#
# 时态路径缓存 - SimHash 分桶 + 时间衰减 + 自适应桶分裂
#
# 符号执行中路径缓存的特殊性：不同于通用 KV 缓存，路径的"有用性"随
# 探索进程递减。早期探索阶段缓存了大量浅层路径的 SimHash 签名--
# 这些浅层路径在后期几乎不可能被再次匹配到（因为后期路径普遍更深、
# 约束更复杂）。如果不加衰减，缓存被早期噪声主导
#
# 设计：
#   (a) SimHash 的前 16 bits 作为桶索引--2^16=65536 个桶，冲突概率低
#   (b) 每个桶内的路径按插入时间排序，查询时用指数衰减权重修正相似度
#       新路径 weight=1.0，半衰期后 weight≈0.5
#   (c) 桶内路径数超过阈值时自适应分裂--沿 SimHash 的第 17-20 bits
#       进一步划分子桶，但这仅在实际查询热度的桶上触发（惰性）
#
# 与 PathDiversityTracker 的 ANNIndex 的关系：
# ANNIndex 用于"给定路径，找 k 个最近邻"--这是 top-k 搜索
#   本模块用于"给定路径，判断是否与缓存中任一路径高度相似"--
# 这是 membership 查询。两者互补，不替代

import hashlib
import math
import time
import threading
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field


@dataclass
class CachedPath:
    """缓存中的单条路径条目

    simhash: 64-bit SimHash 签名（由 PathDiversityTracker 计算后传入）
    inserted_at: 插入时间戳（epoch seconds）
    depth: 路径深度--用于辅助判断"浅层噪声"
    constraint_count: 约束数量--用于辅助相似度阈值自适应
    """
    path_id: str
    simhash: int
    inserted_at: float
    depth: int = 0
    constraint_count: int = 0


class TemporalPathCache:
    """SimHash 分桶的时态路径缓存

    桶索引 = simhash 的前 16 bits。桶内路径按时间衰减加权
    查询返回与给定 SimHash 在桶内最相似的 k 条路径
    相似度 = (1 - 汉明距离/64) × exp(-λ × age)。λ = ln(2)/halflife
    """

    # 桶索引的位数--16 bits → 65536 桶
    BUCKET_BITS = 16
    BUCKET_MASK = (1 << BUCKET_BITS) - 1

    def __init__(self, halflife_seconds: float = 120.0, max_per_bucket: int = 50):
        """
        halflife_seconds: 路径权重衰减半衰期（秒），默认 120
        max_per_bucket: 触发桶分裂的路径数阈值
        """
        self._halflife = halflife_seconds
        self._decay_lambda = math.log(2) / halflife_seconds
        self._max_per_bucket = max_per_bucket
        self._buckets: Dict[int, List[CachedPath]] = {}
        self._sub_buckets: Dict[int, Dict[int, List[CachedPath]]] = {}
        self._total_paths: int = 0
        self._lock = threading.Lock()

    def _bucket_key(self, simhash: int) -> int:
        return simhash & self.BUCKET_MASK

    def _sub_key(self, simhash: int) -> int:
        # 子桶用第 17-20 bits（4 bits → 16 个子桶）
        return (simhash >> self.BUCKET_BITS) & 0xF

    def insert(self, path_id: str, simhash: int,
               depth: int = 0, constraint_count: int = 0):
        """插入一条路径到缓存。桶满时自动触发惰性子桶分裂"""
        entry = CachedPath(
            path_id=path_id, simhash=simhash,
            inserted_at=time.time(), depth=depth,
            constraint_count=constraint_count,
        )
        with self._lock:
            bucket = self._bucket_key(simhash)
            if bucket not in self._buckets:
                self._buckets[bucket] = []
            self._buckets[bucket].append(entry)
            self._total_paths += 1

            # 桶满 → 惰性分裂
            if len(self._buckets[bucket]) > self._max_per_bucket:
                self._split_bucket(bucket)

    def _split_bucket(self, bucket: int):
        """将桶内路径按子桶重新分配

        仅在查询触发时对已满的桶执行--非全局重哈希
        子桶结构建立后，主桶的 list 保留但后续查询优先走子桶
        """
        if bucket in self._sub_buckets:
            return  # 已分裂
        sub: Dict[int, List[CachedPath]] = {}
        for entry in self._buckets.get(bucket, []):
            sk = self._sub_key(entry.simhash)
            sub.setdefault(sk, []).append(entry)
        self._sub_buckets[bucket] = sub

    def query(self, simhash: int, k: int = 5,
              min_similarity: float = 0.7) -> List[Tuple[str, float]]:
        """在桶 + 子桶中搜索与给定 SimHash 最相似的 k 条路径

        相似度 = 原始 SimHash 余弦相似度 × 时间衰减因子
        返回 [(path_id, weighted_similari),.]，按加权相似度降序
        """
        bucket = self._bucket_key(simhash)
        now = time.time()

        with self._lock:
            candidates: List[Tuple[CachedPath, float]] = []

            # 子桶优先（粒度更细）
            sub = self._sub_buckets.get(bucket, {})
            if sub:
                sk = self._sub_key(simhash)
                for entry in sub.get(sk, []):
                    sim = self._compute_similarity(simhash, entry, now)
                    if sim >= min_similarity:
                        candidates.append((entry, sim))
            else:
                for entry in self._buckets.get(bucket, []):
                    sim = self._compute_similarity(simhash, entry, now)
                    if sim >= min_similarity:
                        candidates.append((entry, sim))

        candidates.sort(key=lambda x: -x[1])
        return [(e.path_id, round(s, 4)) for e, s in candidates[:k]]

    def _compute_similarity(self, query_simhash: int, entry: CachedPath,
                            now: float) -> float:
        """原始 SimHash 相似度 × 时间衰减"""
        # 原始相似度 = 1 - 汉明距离/64
        xor = query_simhash ^ entry.simhash
        hamming = xor.bit_count()
        raw_sim = 1.0 - hamming / 64.0

        # 时间衰减因子 = exp(-λ × age)
        age = now - entry.inserted_at
        decay = math.exp(-self._decay_lambda * max(0.0, age))

        return raw_sim * decay

    def evict_expired(self, max_age_seconds: float = 600.0) -> int:
        """批量逐出超过最大年龄的路径条目

        返回逐出数量。调用方可周期性调用（如在符号执行检查点）
        """
        now = time.time()
        evicted = 0
        with self._lock:
            for bucket in list(self._buckets.keys()):
                old_len = len(self._buckets[bucket])
                self._buckets[bucket] = [
                    e for e in self._buckets[bucket]
                    if now - e.inserted_at < max_age_seconds
                ]
                evicted += old_len - len(self._buckets[bucket])
                if not self._buckets[bucket]:
                    del self._buckets[bucket]
                    self._sub_buckets.pop(bucket, None)
            self._total_paths -= evicted
        return evicted

    def stats(self) -> Dict:
        """返回缓存状态：总路径数、桶数、已分裂桶数、最大桶深度"""
        with self._lock:
            bucket_sizes = [len(v) for v in self._buckets.values()]
            return {
                'total_paths': self._total_paths,
                'total_buckets': len(self._buckets),
                'split_buckets': len(self._sub_buckets),
                'max_bucket_depth': max(bucket_sizes) if bucket_sizes else 0,
                'avg_bucket_depth': (sum(bucket_sizes) / len(bucket_sizes)
                                     if bucket_sizes else 0),
            }
