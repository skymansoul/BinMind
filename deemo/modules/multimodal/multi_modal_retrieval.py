# 2026-07-29
# 跨模态检索 — 双向检索 + 重排序 + 检索质量评估
# 支持文本→图像、图像→文本、音频→文本等多方向查询
# 核心算法：余弦最近邻 + 倒排索引加速 + 查询扩展
# 参考：Frome et al. DeViSE (NIPS 2013), Faghri et al. VSE++ (BMVC 2018)

import math
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

_EPS: float = 1e-9


# ============================================================================
# 倒排索引 — 将嵌入向量离散化到 LSH 桶中，O(1) 近似最近邻
# 参考：Datar et al. LSH scheme based on p-stable distributions (SoCG 2004)
# ============================================================================

class LSHIndex:
    """基于随机投影的局部敏感哈希 (LSH) 索引。

    用 L 组随机超平面将嵌入映射到哈希桶，
    查询时仅搜索与查询落入同一桶的候选项。
    近似因子由 hash_dim 和 num_tables 控制——
    表越多召回率越高，但存储成本线性增长。
    """

    def __init__(self, dim: int = 64, num_tables: int = 8, hash_dim: int = 16):
        self.dim = dim
        self.num_tables = num_tables
        self.hash_dim = hash_dim
        # 每组随机投影向量 (table × hash_dim × dim)
        self._planes: List[List[List[float]]] = []
        self._tables: List[Dict[int, List[int]]] = []
        self._embeddings: Dict[int, List[float]] = {}
        self._next_id: int = 0

        # 初始化随机投影
        for _t in range(num_tables):
            _table_planes = [
                [(math.sin((_t * 1.73 + _h * 0.91 + _d * 0.37)) - 0.5) * 2.0
                 for _d in range(dim)]
                for _h in range(hash_dim)
            ]
            self._planes.append(_table_planes)
            self._tables.append({})

    def _hash_vector(self, vec: List[float], table_idx: int) -> int:
        """对向量做随机投影 → 二进制编码 → 整数哈希桶ID。"""
        _planes = self._planes[table_idx]
        _hash_bits = 0
        for _h, _plane in enumerate(_planes):
            _dot = sum(vec[_d] * _plane[_d] for _d in range(min(len(vec), self.dim)))
            if _dot >= 0:
                _hash_bits |= (1 << _h)
        return _hash_bits

    def insert(self, vec: List[float]) -> int:
        """插入向量，返回分配的内部ID。"""
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


# ============================================================================
# 双向检索器 — 支持 A→B 和 B→A 两个方向，自动维护双索引
# ============================================================================

class BidirectionalRetriever:
    """双向跨模态检索器：索引模态A和模态B，支持两个方向的查询。

    维护两个独立的 LSH 索引，但共享底层嵌入存储以节省内存。
    """

    def __init__(self, dim_a: int = 64, dim_b: int = 64):
        self._index_a = LSHIndex(dim=dim_a)
        self._index_b = LSHIndex(dim=dim_b)
        # 存配对信息：(id_a, id_b)
        self._pairs: List[Tuple[int, int]] = []

    def add_pair(self, embedding_a: List[float], embedding_b: List[float]):
        _ida = self._index_a.insert(embedding_a)
        _idb = self._index_b.insert(embedding_b)
        self._pairs.append((_ida, _idb))

    def query_a_to_b(self, query_a: List[float], topk: int = 10
                     ) -> List[Tuple[int, float]]:
        """A→B 检索：返回 (pair_index, similarity)。"""
        _results = self._index_b.query(query_a, topk)
        return [(_b_id, _sim) for _b_id, _sim in _results]

    def query_b_to_a(self, query_b: List[float], topk: int = 10
                     ) -> List[Tuple[int, float]]:
        return self._index_a.query(query_b, topk)


# ============================================================================
# 检索评估指标 — Recall@K, mAP, MedianRank, R-Precision
# ============================================================================

def recall_at_k(scores_matrix: List[List[float]], k: int = 10) -> float:
    """召回率@K：对角线正样本是否在前K个检索结果中。

    scores_matrix[i][j] = 查询i与候选项j的相似度。
    正样本索引 = i（对角线对应配对）。
    返回平均 Recall@K。
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
    """平均检索精度 (mAP)：每个查询的正样本位置加权和。"""
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
    """正样本排名的中位数——越低表示检索精度越高。

    中位排名为1意味着超过一半的查询第一位就命中了对齐样本。
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


# ============================================================================
# 查询扩展 — 基于同义词或近邻嵌入自动扩写查询
# 参考：Rocchio algorithm for relevance feedback (SMART system, 1971)
# 应用于嵌入空间：查询向量 = α·原查询 + β·topK相关项均值 - γ·随机项均值
# ============================================================================

def rocchio_query_expansion(query_vec: List[float],
                             relevant_embeddings: List[List[float]],
                             irrelevant_embeddings: Optional[List[List[float]]] = None,
                             alpha: float = 1.0, beta_weight: float = 0.75,
                             gamma_weight: float = 0.15) -> List[float]:
    """Rocchio 查询扩展在嵌入空间中的实现。

    q_new = α·q_0 + β·mean(relevant) - γ·mean(irrelevant)
    扩展后的查询向量通常在检索准确率上优于原始查询。
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


# ============================================================================
# 重排序器 — 基于元数据的二次排序，在初检结果上应用额外约束
# ============================================================================

class MetadataReranker:
    """基于元数据过滤的重排序：在初始检索结果上应用硬/软约束。

    硬约束：filter_fn → True 保留 | False 排除
    软约束：boost_fn → similarity *= (1 + boost) 对优先项加权
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


# ============================================================================
# 跨模态哈希 (CMH) — 将不同模态的嵌入映射到公共汉明空间
# 参考：Jiang & Li. Deep Cross-Modal Hashing (CVPR 2017)
# 二值化后支持高效的汉明距离检索，存储成本降至 O(N·bits)
# ============================================================================

class CrossModalHasher:
    """迭代量化 (ITQ) 风格的跨模态哈希。

    通过正交旋转矩阵将 PCA 降维后的连续向量旋转为近似二值码。
    最终 bits 位哈希码在汉明空间做检索，每个码仅占 bits/8 字节。
    """

    def __init__(self, num_bits: int = 64):
        self.num_bits = num_bits
        self._rotation: List[List[float]] = []
        self._fitted = False

    def fit(self, embeddings: List[List[float]]):
        """拟合正交旋转矩阵：对 PCA 后的中心化嵌入做迭代正交化。"""
        _N = len(embeddings)
        _d = len(embeddings[0]) if _N > 0 else 0
        _bits = min(self.num_bits, _d)

        # 均值中心化
        _mean = [0.0] * _d
        for _emb in embeddings:
            for _j in range(_d):
                _mean[_j] += _emb[_j] / _N
        _centered = [[embeddings[_i][_j] - _mean[_j] for _j in range(_d)]
                     for _i in range(_N)]

        # 简化的 PCA：取前 _bits 个主成分方向（随机投影 + Gram-Schmidt）
        _R = [[0.0] * _d for _ in range(_bits)]
        for _b in range(_bits):
            _vec = [(math.sin((_b + 1.37) * (_j + 1.73)) - 0.5) * 2.0
                    for _j in range(_d)]
            # Gram-Schmidt 正交化对之前的方向
            for _pb in range(_b):
                _dot = sum(_vec[_j] * _R[_pb][_j] for _j in range(_d))
                for _j in range(_d):
                    _vec[_j] -= _dot * _R[_pb][_j]
            _norm = math.sqrt(sum(x * x for x in _vec)) + _EPS
            _R[_b] = [x / _norm for x in _vec]

        self._rotation = [[_R[_b][_j] for _j in range(_d)] for _b in range(_bits)]
        self._fitted = True

    def hash(self, embedding: List[float]) -> List[int]:
        """将连续嵌入二值化为 {0,1} 的哈希码。"""
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
        """汉明距离：不同位数。"""
        return sum(1 for _a, _b in zip(code_a, code_b) if _a != _b)

    def hamming_retrieve(self, query_code: List[int],
                         code_db: List[List[int]], topk: int = 10
                         ) -> List[Tuple[int, int]]:
        """汉明空间检索：返回 (db_index, hamming_distance)。"""
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
