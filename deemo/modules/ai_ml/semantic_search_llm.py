"""
Semantic Search with LLM - LLM-augmented semantic similarity search.

Combines vector embeddings (FAISS + numpy fallback) with LLM-based
re-ranking and query understanding for binary function search.
"""

from __future__ import annotations

import json
import logging
import os
import pickle
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class FunctionSummary:
    """LLM-generated summary of a function."""
    name: str
    address: int = 0
    summary: str = ""
    purpose: str = ""
    embedding: List[float] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': self.address,
            'summary': self.summary,
            'purpose': self.purpose,
            'embedding': self.embedding,
            'keywords': self.keywords,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FunctionSummary:
        return cls(
            name=data.get('name', ''),
            address=data.get('address', 0),
            summary=data.get('summary', ''),
            purpose=data.get('purpose', ''),
            embedding=data.get('embedding', []),
            keywords=data.get('keywords', []),
            metadata=data.get('metadata', {}),
        )


@dataclass
class SearchResult:
    """A single search result."""
    function: FunctionSummary
    score: float
    rank: int = 0
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function': self.function.to_dict(),
            'score': self.score,
            'rank': self.rank,
            'explanation': self.explanation,
        }


class VectorIndex:
    """Vector index with FAISS acceleration and numpy fallback."""

    def __init__(
        self,
        dimension: int = 768,
        use_faiss: bool = True,
    ) -> None:
        self.dimension = dimension
        self._embeddings: List[np.ndarray] = []
        self._items: List[FunctionSummary] = []
        self._faiss_index: Any = None
        self._use_faiss = False

        if use_faiss:
            try:
                import faiss
                self._faiss_index = faiss.IndexFlatIP(dimension)
                self._use_faiss = True
                logger.info(f"FAISS IndexFlatIP initialized with dim={dimension}")
            except ImportError:
                logger.info("FAISS not available, using numpy fallback")

    @staticmethod
    def _normalize_vector(
        vec: np.ndarray,
        target_dim: int,
    ) -> np.ndarray:
        """规范化向量：补齐/截断至目标维度后L2归一化。

        Args:
            vec: 输入向量。
            target_dim: 目标维度。

        Returns:
            归一化后的float32向量。
        """
        if len(vec) != target_dim:
            if len(vec) > 0:
                padded = np.zeros(target_dim, dtype=np.float32)
                padded[:min(len(vec), target_dim)] = vec[:min(len(vec), target_dim)]
                vec = padded
            else:
                vec = np.zeros(target_dim, dtype=np.float32)

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm

        return vec.astype(np.float32)

    def add(
        self,
        item: FunctionSummary,
        embedding: Optional[List[float]] = None,
    ) -> None:
        """Add an item with its embedding to the index.

        Args:
            item: FunctionSummary to index.
            embedding: Optional explicit embedding (uses item.embedding if None).
        """
        vec = np.array(embedding or item.embedding, dtype=np.float32)
        vec = self._normalize_vector(vec, self.dimension)

        self._embeddings.append(vec)
        self._items.append(item)

        if self._use_faiss and self._faiss_index is not None:
            self._faiss_index.add(np.array([vec], dtype=np.float32))

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        min_score: float = 0.0,
    ) -> List[Tuple[FunctionSummary, float]]:
        """Search for nearest neighbors.

        Args:
            query_embedding: Query vector.
            top_k: Number of results.
            min_score: 最低相似度阈值，低于此值的候选直接丢弃。

        Returns:
            List of (FunctionSummary, similarity_score) tuples.
        """
        if not self._embeddings:
            return []

        query = np.array(query_embedding, dtype=np.float32)
        query = self._normalize_vector(query, self.dimension)

        if self._use_faiss and self._faiss_index is not None:
            try:
                distances, indices = self._faiss_index.search(
                    np.array([query], dtype=np.float32),
                    min(top_k, len(self._items)),
                )
                results: List[Tuple[FunctionSummary, float]] = []
                for i in range(len(indices[0])):
                    idx = indices[0][i]
                    if idx >= 0 and idx < len(self._items):
                        sim = float(distances[0][i])
                        if sim >= min_score:
                            results.append((self._items[idx], sim))
                return results
            except Exception as e:
                logger.warning(f"FAISS search error: {e}")

        # Numpy 回退
        scores = np.dot(np.array(self._embeddings), query)
        top_indices = np.argsort(scores)[::-1][:top_k]

        return [
            (self._items[i], float(scores[i]))
            for i in top_indices
            if float(scores[i]) >= min_score
        ]

    def remove(self, address: int) -> bool:
        """Remove an item by address.

        Args:
            address: Function address to remove.

        Returns:
            True if removed successfully.
        """
        for i, item in enumerate(self._items):
            if item.address == address:
                self._items.pop(i)
                self._embeddings.pop(i)
                if self._use_faiss:
                    self._rebuild_faiss()
                return True
        return False

    def _rebuild_faiss(self) -> None:
        """Rebuild FAISS index from current embeddings."""
        if not self._use_faiss:
            return
        try:
            import faiss
            self._faiss_index = faiss.IndexFlatIP(self.dimension)
            if self._embeddings:
                matrix = np.array(self._embeddings, dtype=np.float32)
                self._faiss_index.add(matrix)
        except ImportError:
            self._use_faiss = False

    # ---- 序列化 / 反序列化 ----
    # 让 VectorIndex 可以独立 pickle 持久化，不再依赖外层 SemanticSearcher 转 JSON

    def save(self, filepath: str) -> None:
        """将索引完整序列化到磁盘（pickle）。

        Args:
            filepath: 输出文件路径（建议 .pkl 后缀）。
        """
        data = {
            'dimension': self.dimension,
            'use_faiss': self._use_faiss,
            'items': [it.to_dict() for it in self._items],
            'embeddings': [e.tolist() for e in self._embeddings],
        }
        with open(filepath, 'wb') as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        logger.info(f"VectorIndex saved to {filepath} ({len(self._items)} vectors)")

    @classmethod
    def load(cls, filepath: str, use_faiss: bool = True) -> VectorIndex:
        """从 pickle 文件恢复 VectorIndex。

        Args:
            filepath: pickle 文件路径。
            use_faiss: 恢复后是否启用 FAISS。

        Returns:
            恢复后的 VectorIndex 实例。
        """
        with open(filepath, 'rb') as f:
            data = pickle.load(f)

        idx = cls(dimension=data['dimension'], use_faiss=False)
        idx._use_faiss = data.get('use_faiss', False)

        for item_dict in data.get('items', []):
            idx._items.append(FunctionSummary.from_dict(item_dict))

        for emb in data.get('embeddings', []):
            idx._embeddings.append(np.array(emb, dtype=np.float32))

        # 如果原始索引用了 FAISS 且当前也用，重建之
        if idx._use_faiss and use_faiss:
            idx._rebuild_faiss()
        elif use_faiss and not idx._use_faiss:
            idx._use_faiss = True
            idx._rebuild_faiss()

        logger.info(f"VectorIndex loaded from {filepath} ({len(idx)} vectors)")
        return idx

    def stats(self) -> Dict[str, Any]:
        """返回索引的基本统计信息。

        Returns:
            包含维度、条目数、FAISS状态等信息的字典。
        """
        emb_matrix = np.array(self._embeddings) if self._embeddings else None
        return {
            'dimension': self.dimension,
            'item_count': len(self._items),
            'faiss_enabled': self._use_faiss,
            'faiss_index_type': type(self._faiss_index).__name__ if self._faiss_index else None,
            'embedding_memory_mb': emb_matrix.nbytes / (1024 * 1024) if emb_matrix is not None else 0.0,
            'mean_norm': float(np.mean(np.linalg.norm(emb_matrix, axis=1))) if emb_matrix is not None and len(emb_matrix) > 0 else 0.0,
        }

    def __len__(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        """Clear all indexed items."""
        self._embeddings.clear()
        self._items.clear()
        if self._use_faiss:
            try:
                import faiss
                self._faiss_index = faiss.IndexFlatIP(self.dimension)
            except ImportError:
                self._faiss_index = None


class SemanticSearcher:
    """Semantic searcher with LLM integration and model loading."""

    DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        dimension: int = 384,
        use_faiss: bool = True,
        cache_dir: Optional[str] = None,
    ) -> None:
        self.model_name = model_name
        self.dimension = dimension
        self.cache_dir = cache_dir or os.path.join(
            os.path.dirname(__file__), "..", "data", "model_cache"
        )
        self.index = VectorIndex(dimension=dimension, use_faiss=use_faiss)
        self._model: Any = None
        self._model_loaded = False
        self._function_cache: Dict[str, FunctionSummary] = {}

    def load_model(self) -> bool:
        """Load the embedding model.

        Returns:
            True if model loaded successfully.
        """
        if self._model_loaded:
            return True

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(
                self.model_name,
                cache_folder=self.cache_dir,
            )
            self._model_loaded = True
            logger.info(f"Loaded model: {self.model_name}")
            return True
        except ImportError:
            logger.warning("sentence-transformers not available, using fallback embeddings")
            return False
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def embed(self, text: str) -> List[float]:
        """Generate embedding for text.

        Args:
            text: Input text to embed.

        Returns:
            Embedding vector.
        """
        if self._model_loaded and self._model is not None:
            try:
                embedding = self._model.encode(text, normalize_embeddings=True)
                return embedding.tolist()
            except Exception as e:
                logger.warning(f"Model encoding failed: {e}")

        return self._fallback_embed(text)

    def _fallback_embed(self, text: str) -> List[float]:
        """Fallback embedding using hash-based TF.

        Args:
            text: Input text.

        Returns:
            Simple hash-based embedding.
        """
        import hashlib
        import re

        tokens = re.findall(r'\w+', text.lower())
        embedding = np.zeros(self.dimension, dtype=np.float32)

        for token in tokens:
            h = hashlib.sha256(token.encode()).digest()
            idx = int.from_bytes(h[:4], 'big') % self.dimension
            embedding[idx] += 1.0

        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding /= norm

        return embedding.tolist()

    def index_function(
        self,
        name: str,
        pseudocode: str = "",
        address: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FunctionSummary:
        """Index a single function.

        Args:
            name: Function name.
            pseudocode: Function pseudocode or summary text.
            address: Function address.
            metadata: Optional metadata.

        Returns:
            Created FunctionSummary.
        """
        summary = FunctionSummary(
            name=name,
            address=address,
            summary=pseudocode[:500] if pseudocode else name,
            purpose="",
            keywords=[],
            metadata=metadata or {},
        )

        summary.embedding = self.embed(summary.summary)
        self.index.add(summary, summary.embedding)
        self._function_cache[name] = summary

        return summary

    def batch_index(
        self,
        functions: List[Dict[str, Any]],
    ) -> List[FunctionSummary]:
        """Index multiple functions at once.

        Args:
            functions: List of dicts with 'name', 'pseudocode', 'address' keys.

        Returns:
            List of created FunctionSummary objects.
        """
        summaries: List[FunctionSummary] = []
        for func in functions:
            summary = self.index_function(
                name=func.get('name', f"func_{len(summaries)}"),
                pseudocode=func.get('pseudocode', ''),
                address=func.get('address', 0),
                metadata=func.get('metadata'),
            )
            summaries.append(summary)
        return summaries

    def search(
        self,
        query: str,
        top_k: int = 10,
        use_llm: bool = False,
        min_score: float = 0.0,
        apply_mmr: bool = False,
        mmr_lambda: float = 0.7,
    ) -> List[SearchResult]:
        """Search for functions matching a query.

        Args:
            query: Natural language query.
            top_k: Number of results.
            use_llm: Whether to use LLM for re-ranking.
            min_score: 最低相似度阈值（丢弃低于此值的候选）。
            apply_mmr: 启用 MMR（最大边际相关性）对结果去重/多样化。
            mmr_lambda: MMR 权衡参数，1.0=纯相似度，0.0=纯多样性。

        Returns:
            List of SearchResult objects.
        """
        query_embedding = self.embed(query)
        # 检索阶段多拉一些候选，方便后续 MMR 剪枝
        retrieval_k = max(top_k * 3, 30) if apply_mmr else top_k
        raw_results = self.index.search(query_embedding, retrieval_k, min_score=min_score)

        results: List[SearchResult] = []
        for rank, (func, score) in enumerate(raw_results):
            results.append(SearchResult(
                function=func,
                score=score,
                rank=rank + 1,
                explanation=f"Similarity score: {score:.4f}" if not use_llm else "",
            ))

        # MMR 多样化：在相似度与信息冗余间取折衷
        if apply_mmr and results:
            results = self._apply_mmr(
                query_embedding=query_embedding,
                candidates=results,
                top_k=top_k,
                lam=mmr_lambda,
            )

        if use_llm and results:
            results = self._llm_rerank(query, results)

        # 最终截断
        return results[:top_k]

    @staticmethod
    def _apply_mmr(
        query_embedding: List[float],
        candidates: List[SearchResult],
        top_k: int,
        lam: float = 0.7,
    ) -> List[SearchResult]:
        """MMR (Maximal Marginal Relevance) 贪心选取。

        参考 Carbonell & Goldstein (1998)。
        每轮选择最大化 λ·sim(q, d) - (1-λ)·max(sim(d, selected)) 的候选。

        Args:
            query_embedding: 查询向量。
            candidates: 候选结果列表。
            top_k: 最终保留数量。
            lam: λ 参数（1.0 = 纯相关性，0.0 = 纯多样性）。

        Returns:
            MMR 排序后的结果列表。
        """
        if len(candidates) <= 1:
            return candidates

        q_vec = np.array(query_embedding, dtype=np.float32)

        # 提取候选向量矩阵 (N, D)
        cand_embeddings = np.array(
            [np.array(c.function.embedding, dtype=np.float32) for c in candidates],
            dtype=np.float32,
        )

        # 查询-候选相似度
        q_sims: np.ndarray
        if cand_embeddings.shape[1] > 0:
            q_norm = np.linalg.norm(q_vec)
            if q_norm > 0:
                q_vec = q_vec / q_norm
            c_norms = np.linalg.norm(cand_embeddings, axis=1, keepdims=True)
            c_norms[c_norms == 0] = 1.0
            cand_embeddings = cand_embeddings / c_norms
            q_sims = np.dot(cand_embeddings, q_vec)
        else:
            q_sims = np.array([c.score for c in candidates])

        # 候选间相似度矩阵（只用到上三角，懒加载）
        pair_sim: Dict[int, np.ndarray] = {}

        def _get_row(i: int) -> np.ndarray:
            if i not in pair_sim:
                di = cand_embeddings[i]
                pair_sim[i] = np.dot(cand_embeddings, di)
            return pair_sim[i]

        selected: List[SearchResult] = []
        available = list(range(len(candidates)))

        # 第一轮：选相关性最高的
        first = int(np.argmax(q_sims))
        selected.append(candidates[first])
        available.remove(first)

        while available and len(selected) < top_k:
            best_idx = -1
            best_mmr = -float('inf')

            for idx in available:
                relevance = q_sims[idx]
                # 与已选集合的最大相似度
                row = _get_row(idx)
                max_red = max(row[sel_idx] for sel_idx in range(len(candidates))
                              if sel_idx not in available)
                mmr = lam * relevance - (1.0 - lam) * max_red

                if mmr > best_mmr:
                    best_mmr = mmr
                    best_idx = idx

            if best_idx == -1:
                break

            selected.append(candidates[best_idx])
            available.remove(best_idx)

        # 剩余未选中的追加到末尾（保持完整）
        for idx in available:
            selected.append(candidates[idx])

        # 重排 rank
        for i, r in enumerate(selected):
            r.rank = i + 1
            if not r.explanation:
                r.explanation = f"Similarity score: {r.score:.4f}"

        return selected

    def _llm_rerank(
        self,
        query: str,
        results: List[SearchResult],
    ) -> List[SearchResult]:
        """Re-rank results using LLM (placeholder).

        Args:
            query: Original query.
            results: Initial search results.

        Returns:
            Re-ranked results.
        """
        for result in results:
            result.explanation = (
                f"LLM rerank: '{result.function.name}' matches '{query}' "
                f"(score: {result.score:.4f})"
            )
        return sorted(results, key=lambda r: r.score, reverse=True)

    def search_by_example(
        self,
        function_name: str,
        top_k: int = 10,
        min_score: float = 0.0,
    ) -> List[SearchResult]:
        """Find functions similar to a known function.

        Args:
            function_name: Name of the example function.
            top_k: Number of results.
            min_score: 最低相似度阈值。

        Returns:
            Similar functions.
        """
        if function_name not in self._function_cache:
            return []

        example = self._function_cache[function_name]
        raw_results = self.index.search(example.embedding, top_k + 1, min_score=min_score)

        results: List[SearchResult] = []
        for rank, (func, score) in enumerate(raw_results):
            if func.name == function_name:
                continue
            results.append(SearchResult(
                function=func,
                score=score,
                rank=rank + 1,
            ))

        return results[:top_k]

    def save(self, directory: str) -> None:
        """Save index and cache to disk.

        Args:
            directory: Output directory path.
        """
        os.makedirs(directory, exist_ok=True)

        items_data = [item.to_dict() for item in self.index._items]
        with open(os.path.join(directory, 'index_items.json'), 'w') as f:
            json.dump(items_data, f, indent=2)

        embeddings = [emb.tolist() for emb in self.index._embeddings]
        with open(os.path.join(directory, 'index_embeddings.json'), 'w') as f:
            json.dump(embeddings, f)

        cache_data = {k: v.to_dict() for k, v in self._function_cache.items()}
        with open(os.path.join(directory, 'function_cache.json'), 'w') as f:
            json.dump(cache_data, f, indent=2)

        config = {
            'model_name': self.model_name,
            'dimension': self.dimension,
        }
        with open(os.path.join(directory, 'config.json'), 'w') as f:
            json.dump(config, f)

        # 同时保存 VectorIndex 的 pickle 快照，便于独立恢复
        self.index.save(os.path.join(directory, 'vector_index.pkl'))

        logger.info(f"Saved index with {len(self.index)} items to {directory}")

    def load(self, directory: str) -> None:
        """Load index and cache from disk.

        Args:
            directory: Input directory path.
        """
        config_path = os.path.join(directory, 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
            self.model_name = config.get('model_name', self.model_name)
            self.dimension = config.get('dimension', self.dimension)

        # 优先尝试从 pickle 恢复（包含 FAISS 重建逻辑）
        pkl_path = os.path.join(directory, 'vector_index.pkl')
        if os.path.exists(pkl_path):
            try:
                self.index = VectorIndex.load(pkl_path, use_faiss=self.index._use_faiss)
                self._function_cache = {
                    item.name: item for item in self.index._items
                }
                logger.info(
                    f"Restored from pickle: {len(self.index)} items"
                )
                return
            except Exception as e:
                logger.warning(f"Pickle load failed, falling back to JSON: {e}")

        # JSON 兼容路径（旧格式）
        items_path = os.path.join(directory, 'index_items.json')
        if os.path.exists(items_path):
            with open(items_path, 'r') as f:
                items_data = json.load(f)

            self.index.clear()
            self._function_cache.clear()

            for data in items_data:
                summary = FunctionSummary.from_dict(data)
                self.index._items.append(summary)
                self._function_cache[summary.name] = summary

        embeddings_path = os.path.join(directory, 'index_embeddings.json')
        if os.path.exists(embeddings_path):
            with open(embeddings_path, 'r') as f:
                embeddings_data = json.load(f)
            self.index._embeddings = [
                np.array(e, dtype=np.float32) for e in embeddings_data
            ]
            if self.index._use_faiss:
                self.index._rebuild_faiss()

        logger.info(f"Loaded index with {len(self.index)} items from {directory}")
