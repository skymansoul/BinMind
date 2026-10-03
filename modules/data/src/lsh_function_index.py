# 多表 SimHash LSH + 动态质心查询修改
"""
SimHash LSH 二进制函数搜索索引 - 多表哈希 + 动态查询修改.

本模块构建 SimHash 的多表 LSH 索引将查询降至 O(L*K):
  L = 哈希表数量 (默认 8)
  K = 每表检索的候选数 (默认 10)
  总查询: O(80) 次汉明距离计算, 与 N 无关

LSH 原理:
  随机超平面投影 -> 汉明距离保持余弦相似度.
  SimHash(x) = sign(W @ x) 其中 W 的每一行是随机超平面的法向量.
  汉明距离(simhash(a), simhash(b)) ∝ arccos(cosine_similarity(a,b)).

多表 LSH 参数选择:
  单表召回率 = P(h(q)=h(nn)) ≈ 1 - (1-p^k)^L
  p = 1 - arccos(sim)/pi (两个相似点碰撞的概率)
  k = 每表哈希位数, L = 表数
  调整 k 和 L 以平衡召回率与查询速度.

动态查询修改:
  原始查询 q -> centroid(kNN(q)) -> 更高碰撞概率.
  centroid 在几何上更接近多个近邻的平均位置,
  用第一轮检索到的候选向量的几何质心替代原始查询做第二轮检索.

创建: 2025-04-17  初始版本, 多表 LSH + centroid 动态查询
修改: 2025-04-17  移除未验证的外部引用, 替换为算法原理自述
"""

from __future__ import annotations

import math
import random
import struct
from collections import defaultdict
from typing import Optional


# SimHash 投影矩阵
# 每个表使用独立的随机投影矩阵, 保证表间独立性。

class SimHashTable:
    """单张 SimHash LSH 表——k 位哈希 + 桶存储。"""

    __slots__ = ('_projections', '_buckets', '_k', '_dim')

    def __init__(self, k_bits: int = 16, dim: int = 64, seed: int = 0):
        self._k = k_bits
        self._dim = dim
        rng = random.Random(seed)
        # 随机超平面法向量: (k, dim) 矩阵
        self._projections = [
            [rng.gauss(0, 1) for _ in range(dim)]
            for _ in range(k_bits)
        ]
        self._buckets: dict[int, list[tuple[int, list[float]]]] = defaultdict(list)

    def hash_vector(self, vec: list[float]) -> int:
        """计算 k-bit SimHash——每个超平面投影后取 sign 位。"""
        if not self._projections:
            return 0
        h = 0
        for i, proj in enumerate(self._projections):
            dot = sum(p * v for p, v in zip(proj, vec))
            if dot > 0:
                h |= (1 << i)
        return h

    def insert(self, func_id: int, embedding: list[float]) -> None:
        h = self.hash_vector(embedding)
        self._buckets[h].append((func_id, embedding))

    def query(self, query_vec: list[float],
              max_candidates: int = 10) -> list[tuple[int, float]]:
        """查询: 返回桶内候选 + 汉明距离排序。"""
        h = self.hash_vector(query_vec)
        candidates = self._buckets.get(h, [])
        if not candidates:
            return []

        scored = []
        for func_id, emb in candidates:
            dist = _hamming_distance_simhash(h, self.hash_vector(emb))
            scored.append((func_id, dist))
        scored.sort(key=lambda x: x[1])
        return [(fid, 1.0 - d / self._k) for fid, d in scored[:max_candidates]]


# 多表 LSH 索引

class LSHFunctionIndex:
    """多表 SimHash LSH 二进制函数相似搜索索引。

    用法:
        index = LSHFunctionIndex(n_tables=8, k_bits=16, dim=64)
        index.insert(func_id=1, embedding=[0.1, 0.2, ...])
        results = index.search(query_embedding, top_k=5)
    """

    __slots__ = ('_tables', '_n_tables', '_k_bits', '_dim',
                 '_func_count', '_query_count')

    def __init__(self, n_tables: int = 8, k_bits: int = 16, dim: int = 64):
        self._tables = [
            SimHashTable(k_bits=k_bits, dim=dim, seed=i * 137 + 42)
            for i in range(n_tables)
        ]
        self._n_tables = n_tables
        self._k_bits = k_bits
        self._dim = dim
        self._func_count = 0
        self._query_count = 0

    def insert(self, func_id: int, embedding: list[float]) -> None:
        # 补齐/截断到 dim
        vec = _pad_or_trunc(embedding, self._dim)
        for table in self._tables:
            table.insert(func_id, vec)
        self._func_count += 1

    def search(self, query_vec: list[float],
               top_k: int = 5,
               dynamic_query: bool = True) -> list[tuple[int, float]]:
        """多表 LSH 搜索——各表候选合并 + 去重 + 按相似度排序。

        dynamic_query=True: 对查询向量做 centroid 修改——
        用已检索到的候选向量的几何质心替代原始查询,
        提高与 kNN 的碰撞概率."""
        self._query_count += 1
        q = _pad_or_trunc(query_vec, self._dim)

        # 第一轮: 用原始查询
        candidates: dict[int, float] = {}
        for table in self._tables:
            for fid, sim in table.query(q, max_candidates=top_k * 2):
                if fid not in candidates or sim > candidates[fid]:
                    candidates[fid] = sim

        # 动态查询修改: centroid of top candidates
        if dynamic_query and len(candidates) >= 3:
            q_modified = self._compute_centroid(q, list(candidates.keys())[:5])
            for table in self._tables:
                for fid, sim in table.query(q_modified, max_candidates=top_k):
                    if fid not in candidates or sim > candidates[fid]:
                        candidates[fid] = sim

        scored = [(fid, sim) for fid, sim in candidates.items()]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def _compute_centroid(self, query: list[float],
                          candidate_ids: list[int]) -> list[float]:
        """计算查询向量与候选嵌入的几何质心——用于动态查询修改。"""
        # 从第一张表中获取候选嵌入 (所有表共享相同嵌入)
        centroid = list(query)
        count = 1
        for fid in candidate_ids:
            for fid2, emb in self._tables[0]._buckets.get(
                self._tables[0].hash_vector(query), []):
                if fid2 == fid:
                    for d in range(self._dim):
                        centroid[d] += emb[d]
                    count += 1
                    break
        if count > 1:
            centroid = [v / count for v in centroid]
        return centroid

    def batch_insert(self, embeddings: dict[int, list[float]]) -> None:
        for fid, emb in embeddings.items():
            self.insert(fid, emb)

    def stats(self) -> dict:
        total_buckets = sum(len(t._buckets) for t in self._tables)
        return {
            'n_tables': self._n_tables,
            'k_bits': self._k_bits,
            'dim': self._dim,
            'functions_indexed': self._func_count,
            'total_buckets': total_buckets,
            'queries_served': self._query_count,
        }


# 汉明距离 + 辅助

def _hamming_distance_simhash(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def _pad_or_trunc(vec: list[float], target_dim: int) -> list[float]:
    if len(vec) == target_dim:
        return list(vec)
    if len(vec) < target_dim:
        return list(vec) + [0.0] * (target_dim - len(vec))
    return vec[:target_dim]


# 嵌入构建适配器
# 从二进制函数的特征向量构建 SimHash 兼容的 64 维嵌入。
# 特征: 指令直方图 (前 32 维) + CFG 统计 (后 32 维)。

def build_function_embedding(ins_histogram: dict[str, int],
                             cfg_stats: dict,
                             target_dim: int = 64) -> list[float]:
    """从指令直方图和 CFG 统计构建归一化嵌入向量。"""
    # 指令直方图 → 前 32 维 (top opcodes)
    top_ops = sorted(ins_histogram.items(), key=lambda x: x[1], reverse=True)[:32]
    total_ins = max(1, sum(ins_histogram.values()))
    vec = [0.0] * target_dim
    for i, (op, count) in enumerate(top_ops):
        if i < 32:
            vec[i] = count / total_ins

    # CFG 统计 → 后 32 维
    cfg_features = [
        cfg_stats.get('block_count', 0) / 100.0,
        cfg_stats.get('edge_count', 0) / 500.0,
        cfg_stats.get('loop_count', 0) / 20.0,
        cfg_stats.get('call_count', 0) / 50.0,
        cfg_stats.get('avg_block_size', 0) / 50.0,
    ]
    for i, v in enumerate(cfg_features):
        idx = 32 + (i * 3) % 32
        if idx < target_dim:
            vec[idx] = min(1.0, max(-1.0, v))

    # 用 SHA-256 将剩余维度填充为确定性伪随机值
    seed = str(sorted(ins_histogram.keys())[:10]).encode()
    h = __import__('hashlib').sha256(seed).digest()
    for i in range(target_dim):
        if vec[i] == 0.0:
            vec[i] = (h[i % len(h)] / 255.0) * 0.1  # 小量抖动

    return vec


__all__ = [
    'LSHFunctionIndex', 'SimHashTable',
    'build_function_embedding', '_hamming_distance_simhash',
]
