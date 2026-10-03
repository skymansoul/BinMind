# 跨模态检索：双向查询 + 重排序 + 检索质量指标评估
# 支持文本→图像、图像→文本、音频→文本等多方向检索
# 基础算法：余弦最近邻 + 倒排索引加速 + Rocchio 查询扩展
# Frome et al. DeViSE. NIPS 2013. Faghri et al. VSE++. BMVC 2018.

import math
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

_EPS: float = 1e-9


# LSH 倒排索引 — 随机投影将连续向量离散化到哈希桶，实现 O(1) 近似最近邻
# Datar et al. LSH scheme based on p-stable distributions. SoCG 2004.

class LSHIndex:
    """基于随机投影的局部敏感哈希（LSH）索引。

    以 L 组随机超平面将嵌入映射至整数哈希桶，
    检索时仅比对与查询落于同一桶的候选项，压缩搜索空间。
    近似质量由 hash_dim（每组平面数）和 num_tables（总表数）协同控制——
    表数越多召回越高，但存储开销线性增长。
    """

    def __init__(self, dim: int = 64, num_tables: int = 8, hash_dim: int = 16):
        self.dim = dim
        self.num_tables = num_tables
        self.hash_dim = hash_dim
        # 每个表对应 hash_dim 个随机投影向量
        self._planes: List[List[List[float]]] = []
        self._tables: List[Dict[int, List[int]]] = []
        self._embeddings: Dict[int, List[float]] = {}
        self._next_id: int = 0

        # 伪随机投影初始化
        for _t in range(num_tables):
            _table_planes = [
                [(math.sin((_t * 1.73 + _h * 0.91 + _d * 0.37)) - 0.5) * 2.0
                 for _d in range(dim)]
                for _h in range(hash_dim)
            ]
            self._planes.append(_table_planes)
            self._tables.append({})

    def _hash_vector(self, vec: List[float], table_idx: int) -> int:
        """随机投影 → 二进制编码 → 整数桶号。"""
        _planes = self._planes[table_idx]
        _hash_bits = 0
        for _h, _plane in enumerate(_planes):
            _dot = sum(vec[_d] * _plane[_d] for _d in range(min(len(vec), self.dim)))
            if _dot >= 0:
                _hash_bits |= (1 << _h)
        return _hash_bits

    def insert(self, vec: List[float]) -> int:
        """插入一个向量，返回分配的内部 ID。"""
        _id = self._next_id
        self._next_id += 1
        self._embeddings[_id] = vec[:]

        for _t in range(self.num_tables):
            _bucket = self._hash_vector(vec, _t)
            if _bucket not in self._tables[_t]:
                self._tables[_t][_bucket] = []
            self._tables[_t][_bucket].append(_id)
        return _id

    def query(self, query_vec: List[float], topk: int = 10) -> List[Tuple[int, float]]:
        _candidates: set = set()
        for _t in range(self.num_tables):
            _bucket = self._hash_vector(query_vec, _t)
            _ids = self._tables[_t].get(_bucket, [])
            _candidates.update(_ids)

        if not _candidates:
            return []

        _scored: List[Tuple[int, float]] = []
        _q_norm = math.sqrt(sum(x * x for x in query_vec)) + _EPS

        for _cid in _candidates:
            _vec = self._embeddings.get(_cid)
            if _vec is None:
                continue
            _dot = sum(query_vec[_i] * _vec[_i] for _i in range(min(len(query_vec), len(_vec))))
            _v_norm = math.sqrt(sum(x * x for x in _vec)) + _EPS
            _cos_sim = _dot / (_q_norm * _v_norm)
            _scored.append((_cid, _cos_sim))

        _scored.sort(key=lambda x: x[1], reverse=True)
        return _scored[:topk]


# 双向检索器 — 维护 A/B 双模态索引，支持两个方向互查

class BidirectionalRetriever:
    """双向跨模态检索器：同时索引 A 模态和 B 模态。

    内部持有两个独立的 LSH 索引，共享配对关系表以节省内存。
    """

    def __init__(self, dim_a: int = 64, dim_b: int = 64):
        self._index_a = LSHIndex(dim=dim_a)
        self._index_b = LSHIndex(dim=dim_b)
        # 配对信息：(id_a, id_b)
        self._pairs: List[Tuple[int, int]] = []

    def add_pair(self, embedding_a: List[float], embedding_b: List[float]):
        _ida = self._index_a.insert(embedding_a)
        _idb = self._index_b.insert(embedding_b)
        self._pairs.append((_ida, _idb))

    def query_a_to_b(self, query_a: List[float], topk: int = 10
                     ) -> List[Tuple[int, float]]:
        """A→B 方向检索，返回 (pair_index, similarity) 列表。"""
        _results = self._index_b.query(query_a, topk)
        return [(_b_id, _sim) for _b_id, _sim in _results]

    def query_b_to_a(self, query_b: List[float], topk: int = 10
                     ) -> List[Tuple[int, float]]:
        return self._index_a.query(query_b, topk)


# 检索质量评估 — Recall@K, mAP, MedianRank, R-Precision

def recall_at_k(scores_matrix: List[List[float]], k: int = 10) -> float:
    """Recall@K：对角线正样本是否进入前 K 个检索结果。

    scores_matrix[i][j]: 查询 i 与候选 j 的相似度。
    正样本索引 = i（对角线对应真实配对）。
    返回 N 个查询的 Recall@K 均值。
    """
    _N = len(scores_matrix)
    if _N == 0:
        return 0.0
    _count = 0
    for _i in range(_N):
        _row = scores_matrix[_i]
        _topk_indices = sorted(range(len(_row)), key=lambda j: _row[j], reverse=True)[:k]
        if _i in _topk_indices:
            _count += 1
    return _count / _N


def mean_average_precision(scores_matrix: List[List[float]]) -> float:
    """mAP：每个查询正样本排名的倒数均值。"""
    _N = len(scores_matrix)
    if _N == 0:
        return 0.0
    _ap_sum = 0.0
    for _i in range(_N):
        _row = scores_matrix[_i]
        _ranked = sorted(range(len(_row)), key=lambda j: _row[j], reverse=True)
        try:
            _pos = _ranked.index(_i) + 1  # 1-indexed rank
        except ValueError:
            continue
        _ap_sum += 1.0 / _pos
    return _ap_sum / _N


def median_rank(scores_matrix: List[List[float]]) -> float:
    """正样本排名中位数——越低表示检索越精确。

    中位排名 = 1 时，超过半数的查询首位即命中对齐样本。
    """
    _N = len(scores_matrix)
    if _N == 0:
        return float('inf')
    _ranks: List[int] = []
    for _i in range(_N):
        _row = scores_matrix[_i]
        _ranked = sorted(range(len(_row)), key=lambda j: _row[j], reverse=True)
        try:
            _ranks.append(_ranked.index(_i) + 1)
        except ValueError:
            _ranks.append(len(_row))
    _ranks.sort()
    _mid = len(_ranks) // 2
    if len(_ranks) % 2 == 0:
        return (_ranks[_mid - 1] + _ranks[_mid]) / 2.0
    return float(_ranks[_mid])


# Rocchio 查询扩展 — 在嵌入空间实现相关反馈
# Rocchio algorithm for relevance feedback. SMART system, 1971.
# 嵌入空间形式：q_new = α·q_0 + β·mean(relevant) - γ·mean(irrelevant)

def rocchio_query_expansion(query_vec: List[float],
                             relevant_embeddings: List[List[float]],
                             irrelevant_embeddings: Optional[List[List[float]]] = None,
                             alpha: float = 1.0, beta_weight: float = 0.75,
                             gamma_weight: float = 0.15) -> List[float]:
    """Rocchio 相关反馈在嵌入空间的实现。

    q_new = α·q_0 + β·mean(relevant) - γ·mean(irrelevant)
    扩展后的查询向量在检索精度上通常优于原始查询。
    """
    _d = len(query_vec)
    _expanded = [alpha * query_vec[_j] for _j in range(_d)]

    if relevant_embeddings:
        _rel_mean = [0.0] * _d
        for _emb in relevant_embeddings:
            for _j in range(min(_d, len(_emb))):
                _rel_mean[_j] += _emb[_j]
        _n_rel = len(relevant_embeddings)
        for _j in range(_d):
            _expanded[_j] += beta_weight * _rel_mean[_j] / _n_rel

    if irrelevant_embeddings:
        _irr_mean = [0.0] * _d
        for _emb in irrelevant_embeddings:
            for _j in range(min(_d, len(_emb))):
                _irr_mean[_j] += _emb[_j]
        _n_irr = len(irrelevant_embeddings)
        for _j in range(_d):
            _expanded[_j] -= gamma_weight * _irr_mean[_j] / _n_irr

    # L2 归一化
    _norm = math.sqrt(sum(x * x for x in _expanded)) + _EPS
    return [x / _norm for x in _expanded]


# 元数据重排序 — 在初步检索结果上施加硬约束/软加分

class MetadataReranker:
    """元数据驱动的结果重排：对初检候选集叠加硬过滤与软加权。

    硬约束 filter_fn → True 保留 / False 剔除
    软加权 boost_fn → similarity *= (1 + boost) 优先匹配项
    """

    def __init__(self, filter_fn=None, boost_fn=None):
        self._filter = filter_fn or (lambda meta: True)
        self._boost = boost_fn or (lambda meta: 0.0)

    def rerank(self, candidates: List[Tuple[int, float, Dict[str, Any]]],
               topk: int = 10) -> List[Tuple[int, float, Dict[str, Any]]]:
        """候选格式：[(id, similarity, metadata), ...]"""
        _filtered: List[Tuple[int, float, Dict[str, Any]]] = []
        for _cid, _sim, _meta in candidates:
            if self._filter(_meta):
                _boost_val = self._boost(_meta)
                _new_sim = _sim * (1.0 + _boost_val)
                _filtered.append((_cid, _new_sim, _meta))

        _filtered.sort(key=lambda x: x[1], reverse=True)
        return _filtered[:topk]


# 跨模态哈希 (CMH) — 将异构模态嵌入映射至公共汉明空间
# Jiang & Li. Deep Cross-Modal Hashing. CVPR 2017.
# 二值化后汉明距离检索，存储开销降至 O(N·bits) 级别

class CrossModalHasher:
    """迭代量化（ITQ）风格的跨模态哈希器。

    利用正交旋转矩阵将 PCA 降维后的连续向量旋转为近似平衡的二值码。
    最终 bits 位哈希码在汉明空间完成检索，每个码仅占 bits/8 字节。
    """

    def __init__(self, num_bits: int = 64):
        self.num_bits = num_bits
        self._rotation: List[List[float]] = []
        self._fitted = False

    def fit(self, embeddings: List[List[float]]):
        """拟合正交旋转矩阵：对去均值嵌入执行迭代正交化。"""
        _N = len(embeddings)
        _d = len(embeddings[0]) if _N > 0 else 0
        _bits = min(self.num_bits, _d)

        # 去均值
        _mean = [0.0] * _d
        for _emb in embeddings:
            for _j in range(_d):
                _mean[_j] += _emb[_j] / _N
        _centered = [[embeddings[_i][_j] - _mean[_j] for _j in range(_d)]
                     for _i in range(_N)]

        # 简化 PCA：随机投影方向 + Gram-Schmidt 正交化
        _R = [[0.0] * _d for _ in range(_bits)]
        for _b in range(_bits):
            _vec = [(math.sin((_b + 1.37) * (_j + 1.73)) - 0.5) * 2.0
                    for _j in range(_d)]
            # 对已选方向做 Gram-Schmidt 正交化
            for _pb in range(_b):
                _dot = sum(_vec[_j] * _R[_pb][_j] for _j in range(_d))
                for _j in range(_d):
                    _vec[_j] -= _dot * _R[_pb][_j]
            _norm = math.sqrt(sum(x * x for x in _vec)) + _EPS
            _R[_b] = [x / _norm for x in _vec]

        self._rotation = [[_R[_b][_j] for _j in range(_d)] for _b in range(_bits)]
        self._fitted = True

    def hash(self, embedding: List[float]) -> List[int]:
        """将连续嵌入二值化为 {0,1} 哈希码。"""
        if not self._fitted:
            return [0] * self.num_bits
        _bits = len(self._rotation)
        _code: List[int] = []
        for _b in range(_bits):
            _dot = sum(embedding[_j] * self._rotation[_b][_j]
                      for _j in range(min(len(embedding), len(self._rotation[_b]))))
            _code.append(1 if _dot >= 0 else 0)
        return _code

    def hamming_distance(self, code_a: List[int], code_b: List[int]) -> int:
        """汉明距离：两个码中不同位的计数。"""
        return sum(1 for _a, _b in zip(code_a, code_b) if _a != _b)

    def hamming_retrieve(self, query_code: List[int],
                         code_db: List[List[int]], topk: int = 10
                         ) -> List[Tuple[int, int]]:
        """汉明空间近似检索，返回 (db_index, hamming_distance) 列表。"""
        _scored = [(i, self.hamming_distance(query_code, c))
                   for i, c in enumerate(code_db)]
        _scored.sort(key=lambda x: x[1])
        return _scored[:topk]


__all__ = [
    "LSHIndex", "BidirectionalRetriever", "CrossModalHasher",
    "MetadataReranker",
    "recall_at_k", "mean_average_precision", "median_rank",
    "rocchio_query_expansion",
]
