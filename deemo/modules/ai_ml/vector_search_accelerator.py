"""
Vector Search Accelerator - High-performance vector similarity search.

Provides accelerated vector search with FAISS integration and
dimensionality reduction for binary function similarity.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

_logger = logging.getLogger(__name__)


@dataclass
class FeatureVector:
    """A feature vector with associated metadata."""
    vec_id: str
    label: str
    features: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vec_id': self.vec_id,
            'label': self.label,
            'dimensions': len(self.features),
            'metadata': self.metadata,
        }

    @property
    def vector(self) -> np.ndarray:
        return np.array(self.features, dtype=np.float32)

    def __len__(self) -> int:
        return len(self.features)


class VectorSearchAccelerator:
    """Accelerated vector similarity search with multiple backends."""

    def __init__(
        self,
        dimensions: int = 128,
        use_faiss: bool = True,
    ) -> None:
        self.dimensions = dimensions
        self._vectors: Dict[str, FeatureVector] = {}
        self._index: Any = None
        self._use_faiss = False
        self._id_list: List[str] = []
        # 缓存相似度矩阵以避免重复计算 — 任何变更操作都会使缓存失效
        self._matrix_cache: Optional[Dict[str, Dict[str, float]]] = None

        if use_faiss:
            try:
                import faiss
                self._index = faiss.IndexFlatL2(dimensions)
                self._use_faiss = True
                _logger.info(f"FAISS IndexFlatL2 initialized with dim={dimensions}")
            except ImportError:
                _logger.info("FAISS not available, using numpy/cosine fallback")

    def _invalidate_cache(self) -> None:
        """使相似度矩阵缓存失效 — 向量集发生变更时必须调用。"""
        self._matrix_cache = None

    def add_vector(
        self,
        vec_id: str,
        label: str,
        features: List[float],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a vector to the index.

        Args:
            vec_id: Unique vector identifier.
            label: Vector label/category.
            features: Feature vector values.
            metadata: Optional metadata dictionary.
        """
        padded = self._pad_features(features)
        fv = FeatureVector(
            vec_id=vec_id,
            label=label,
            features=padded,
            metadata=metadata or {},
        )
        self._vectors[vec_id] = fv
        self._id_list.append(vec_id)

        if self._use_faiss and self._index is not None:
            arr = np.array([padded], dtype=np.float32)
            self._index.add(arr)

        self._invalidate_cache()

    def add_vectors_batch(
        self,
        entries: List[Dict[str, Any]],
        progress_callback: Optional[callable] = None,
    ) -> int:
        """批量向量插入 — 利用 FAISS 原生批量 add 大幅降低构建开销。

        逐个调用 add_vector 在大量数据时效率低下，因为每次 add 都会
        触发 FAISS 内部的单条插入逻辑。本方法先将所有向量缓存到内存，
        最后一次性写入 FAISS 索引，减少 Python↔C 交互次数。

        Args:
            entries: 字典列表，每项需包含 'vec_id', 'label', 'features' 字段，
                    可选 'metadata' 字段。
            progress_callback: 可选回调，签名为 callback(current, total)。

        Returns:
            成功添加的向量数量。

        Raises:
            ValueError: 如果某条目缺少必填字段。
        """
        total = len(entries)
        padded_list: List[List[float]] = []
        ids_added: List[str] = []

        for idx, entry in enumerate(entries):
            if 'vec_id' not in entry or 'label' not in entry or 'features' not in entry:
                raise ValueError(
                    f"Entry at index {idx} missing required fields: "
                    f"vec_id/label/features"
                )

            padded = self._pad_features(entry['features'])
            self._vectors[entry['vec_id']] = FeatureVector(
                vec_id=entry['vec_id'],
                label=entry['label'],
                features=padded,
                metadata=entry.get('metadata', {}),
            )
            self._id_list.append(entry['vec_id'])
            padded_list.append(padded)
            ids_added.append(entry['vec_id'])

            if progress_callback:
                progress_callback(idx + 1, total)

        # FAISS 批量写入 — 一次性将 numpy 数组压入索引
        if self._use_faiss and self._index is not None and padded_list:
            try:
                data = np.array(padded_list, dtype=np.float32)
                self._index.add(data)
                _logger.debug(
                    f"FAISS batch add: {len(padded_list)} vectors, "
                    f"shape={data.shape}"
                )
            except Exception as e:
                _logger.warning(f"FAISS batch add failed, rebuilding: {e}")
                self.build_index(use_faiss=self._use_faiss)

        self._invalidate_cache()
        return len(ids_added)

    def _pad_features(self, features: List[float]) -> List[float]:
        """Pad or truncate features to match configured dimensions."""
        if len(features) >= self.dimensions:
            return features[:self.dimensions]
        return features + [0.0] * (self.dimensions - len(features))

    @staticmethod
    def cosine_similarity(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if not a or not b:
            return 0.0
        vec_a = np.array(a, dtype=np.float32)
        vec_b = np.array(b, dtype=np.float32)
        dot = float(np.dot(vec_a, vec_b))
        norm_a = float(np.linalg.norm(vec_a))
        norm_b = float(np.linalg.norm(vec_b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    @staticmethod
    def euclidean_distance(a: List[float], b: List[float]) -> float:
        """Compute Euclidean distance between two vectors."""
        if not a or not b:
            return float('inf')
        vec_a = np.array(a, dtype=np.float32)
        vec_b = np.array(b, dtype=np.float32)
        return float(np.linalg.norm(vec_a - vec_b))

    def search(
        self,
        query: List[float],
        top_k: int = 10,
    ) -> List[Tuple[FeatureVector, float]]:
        """Search for nearest neighbors.

        Args:
            query: Query feature vector.
            top_k: Number of results to return.

        Returns:
            List of (FeatureVector, similarity_score) tuples.
        """
        q = self._pad_features(query)

        if self._use_faiss and self._index is not None:
            try:
                q_arr = np.array([q], dtype=np.float32)
                distances, indices = self._index.search(
                    q_arr, min(top_k, len(self._vectors))
                )
                results: List[Tuple[FeatureVector, float]] = []
                for i in range(len(indices[0])):
                    idx = indices[0][i]
                    if 0 <= idx < len(self._id_list):
                        vec_id = self._id_list[idx]
                        vec = self._vectors.get(vec_id)
                        if vec:
                            sim = 1.0 / (1.0 + float(distances[0][i]))
                            results.append((vec, sim))
                return results
            except Exception as e:
                _logger.warning(f"FAISS search failed: {e}")

        # Brute-force cosine similarity 回退
        scores: List[Tuple[FeatureVector, float]] = []
        for vec_id, vec in self._vectors.items():
            sim = self.cosine_similarity(q, vec.features)
            scores.append((vec, sim))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def search_by_label(
        self,
        query: List[float],
        label_filter: str,
        top_k: int = 10,
    ) -> List[Tuple[FeatureVector, float]]:
        """Search with label filtering.

        Args:
            query: Query vector.
            label_filter: Only return vectors with this label.
            top_k: Number of results.

        Returns:
            Filtered search results.
        """
        q = self._pad_features(query)
        scores: List[Tuple[FeatureVector, float]] = []
        for vec_id, vec in self._vectors.items():
            if vec.label == label_filter:
                sim = self.cosine_similarity(q, vec.features)
                scores.append((vec, sim))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def build_index(self, use_faiss: bool = True) -> None:
        """Build or rebuild the search index.

        Args:
            use_faiss: Attempt to use FAISS.
        """
        if use_faiss and not self._use_faiss:
            try:
                import faiss
                # from collections import OrderedDict # 保留--未使用，修复缩进
                self._index = faiss.IndexFlatL2(self.dimensions)
                if self._vectors:
                    data = np.array(
                        [v.features for v in self._vectors.values()],
                        dtype=np.float32,
                    )
                    self._index.add(data)
                self._use_faiss = True
                _logger.info(f"FAISS index built with {len(self._vectors)} vectors")
            except ImportError:
                _logger.warning("FAISS unavailable; using brute-force fallback")
                self._index = {'type': 'brute_force', 'size': len(self._vectors)}
                self._use_faiss = False
        elif not use_faiss:
            self._index = {'type': 'brute_force', 'size': len(self._vectors)}

    def remove_vector(self, vec_id: str) -> bool:
        """Remove a vector by ID.

        Args:
            vec_id: Vector identifier to remove.

        Returns:
            True if removed.
        """
        if vec_id in self._vectors:
            del self._vectors[vec_id]
            self._id_list.remove(vec_id)
            self.build_index(use_faiss=self._use_faiss)
            self._invalidate_cache()
            return True
        return False

    def get_vector(self, vec_id: str) -> Optional[FeatureVector]:
        """Get a vector by ID.

        Args:
            vec_id: Vector identifier.

        Returns:
            FeatureVector or None.
        """
        return self._vectors.get(vec_id)

    def analyze(
        self,
        vectors: Optional[List[Dict[str, Any]]] = None,
        query: Optional[List[float]] = None,
        top_k: int = 10,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Analyze vectors and optionally search.

        Args:
            vectors: Vectors to index.
            query: Optional query vector.
            top_k: Result count.
            **kwargs: Additional options.

        Returns:
            Analysis results dict.
        """
        if vectors:
            for v in vectors:
                self.add_vector(
                    vec_id=v.get('id', v.get('label', 'unknown')),
                    label=v.get('label', 'unknown'),
                    features=v.get('features', []),
                    metadata=v.get('metadata'),
                )
        self.build_index()

        result: Dict[str, Any] = {
            'success': True,
            'total_vectors': len(self._vectors),
            'dimensions': self.dimensions,
            'index_type': 'faiss' if self._use_faiss else 'brute_force',
        }

        if query:
            results = self.search(query, top_k)
            result['query_results'] = [
                {
                    'label': vec.label,
                    'vec_id': vec.vec_id,
                    'similarity': round(sim, 4),
                    'metadata': vec.metadata,
                }
                for vec, sim in results
            ]

        return result

    def compute_similarity_matrix(
        self,
        force_recompute: bool = False,
    ) -> Dict[str, Dict[str, float]]:
        """计算完整对称的成对余弦相似度矩阵。

        与旧版不同，返回的字典是完整对称矩阵：每个 vec_id 映射到一个
        包含所有其他 vec_id 的相似度字典。"""
        if not force_recompute and self._matrix_cache is not None:
            return self._matrix_cache

        vec_ids = list(self._vectors.keys())
        n = len(vec_ids)

        # 预分配对称矩阵 — 避免重复构造内部字典
        matrix: Dict[str, Dict[str, float]] = {}
        for vid in vec_ids:
            matrix[vid] = {}
            matrix[vid][vid] = 1.0  # 自相似度

        if n < 2:
            self._matrix_cache = matrix
            return matrix

        # 仅计算上三角，同时填充下三角
        for i in range(n):
            id_a = vec_ids[i]
            vec_a = self._vectors[id_a].features
            for j in range(i + 1, n):
                id_b = vec_ids[j]
                vec_b = self._vectors[id_b].features
                sim = self.cosine_similarity(vec_a, vec_b)
                matrix[id_a][id_b] = sim
                matrix[id_b][id_a] = sim  # 对称填充 — O(n²) 只计算一次

        self._matrix_cache = matrix
        return matrix

    def get_statistics(self) -> Dict[str, Any]:
        """返回向量空间的维度级统计信息，用于质量诊断。

        计算每个维度的均值、标准差、最小值和最大值，帮助识别：
        — 全零维度（特征提取 bug）
        — 方差过低维度（区分度不足）
        — 异常偏移（数据分布问题）

        Returns:
            包含 per_dimension 统计和全局汇总的字典。
        """
        if not self._vectors:
            return {
                'vector_count': 0,
                'dimensions': self.dimensions,
                'per_dimension': {},
                'global': {},
            }

        # 将所有向量堆叠为 shape (N, D) 的数组
        all_vecs = np.array(
            [v.features for v in self._vectors.values()],
            dtype=np.float32,
        )
        N = all_vecs.shape[0]

        dim_mean = np.mean(all_vecs, axis=0).tolist()
        dim_std = np.std(all_vecs, axis=0).tolist()
        dim_min = np.min(all_vecs, axis=0).tolist()
        dim_max = np.max(all_vecs, axis=0).tolist()

        # 全零维度检测 — 这类维度对相似度计算没有任何贡献
        zero_var_dims = [
            i for i, std_val in enumerate(dim_std) if std_val < 1e-8
        ]

        per_dim: Dict[str, Any] = {}
        for d in range(self.dimensions):
            per_dim[str(d)] = {
                'mean': round(dim_mean[d], 6),
                'std': round(dim_std[d], 6),
                'min': round(dim_min[d], 6),
                'max': round(dim_max[d], 6),
            }

        # 全局汇总
        global_mean = float(np.mean(all_vecs))
        global_std = float(np.std(all_vecs))
        avg_norm = float(np.mean(np.linalg.norm(all_vecs, axis=1)))

        return {
            'vector_count': N,
            'dimensions': self.dimensions,
            'per_dimension': per_dim,
            'global': {
                'mean': round(global_mean, 6),
                'std': round(global_std, 6),
                'avg_l2_norm': round(avg_norm, 6),
            },
            'zero_variance_dimensions': zero_var_dims,
            'zero_variance_count': len(zero_var_dims),
        }

    def find_clusters(
        self,
        similarity_threshold: float = 0.7,
    ) -> List[List[str]]:
        """Find clusters of similar vectors.

        Args:
            similarity_threshold: Minimum similarity for clustering.

        Returns:
            List of clusters, each a list of vector IDs.
        """
        visited: set = set()
        clusters: List[List[str]] = []

        for vec_id in self._vectors:
            if vec_id in visited:
                continue
            cluster = [vec_id]
            visited.add(vec_id)

            for other_id in self._vectors:
                if other_id in visited:
                    continue
                sim = self.cosine_similarity(
                    self._vectors[vec_id].features,
                    self._vectors[other_id].features,
                )
                if sim >= similarity_threshold:
                    cluster.append(other_id)
                    visited.add(other_id)

            if len(cluster) > 1:
                clusters.append(cluster)

        return clusters

    def clear(self) -> None:
        """Clear all vectors and rebuild empty index."""
        self._vectors.clear()
        self._id_list.clear()
        self._invalidate_cache()
        self.build_index(use_faiss=self._use_faiss)

    def __len__(self) -> int:
        return len(self._vectors)


def search_similar_vectors(
    vectors: List[Dict[str, Any]],
    query: Optional[List[float]] = None,
    top_k: int = 10,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Convenience function for vector search.

    Args:
        vectors: List of vector dicts with 'features' and optional 'label'.
        query: Optional query vector.
        top_k: Number of results.
        **kwargs: Additional options.

    Returns:
        Search results dict.
    """
    accelerator = VectorSearchAccelerator(**kwargs)
    return accelerator.analyze(vectors=vectors, query=query, top_k=top_k)

def _debug_print(*args, **kwargs):  # 调试残余--未删除
    """Print debug info if env var is set. Not currently called."""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
