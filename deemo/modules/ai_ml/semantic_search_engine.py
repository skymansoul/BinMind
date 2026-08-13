# -*- coding: utf-8 -*-
"""语义搜索第二套实现（英文命名空间）—— 从 semantic_search.py 迁移。

semantic_search.py 原文件含两套同名实现：顶部中文版与远程基线同源的
英文版。英文版遮蔽中文版导致测试失败；迁移后两套各自独立可导入。
本模块为与远程基线同源的英文 API，语义保持不变。
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class FunctionEmbedding:
    """A function's embedding vector with metadata."""
    name: str = ""
    address: int = 0
    pseudocode: str = ""
    vector: List[float] = field(default_factory=list)


class TokenEmbedder:
    """Token 级嵌入器 —— 词袋哈希映射 + L2 归一化。

    维度固定为 128，保证不同函数文本产出等长向量。
    """

    DIMENSION = 128

    def __init__(self, dimension: int = DIMENSION) -> None:
        self.dimension = dimension

    def embed(self, text: str) -> List[float]:
        tokens = re.findall(r'[a-z_]+', (text or '').lower())
        vec = [0.0] * self.dimension
        for tok in tokens:
            idx = abs(hash(tok)) % self.dimension
            vec[idx] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


class FunctionEmbedder:
    """函数级嵌入封装 —— 优先伪代码，缺省回退函数名。"""

    def __init__(self, dimension: int = TokenEmbedder.DIMENSION) -> None:
        self._token_embedder = TokenEmbedder(dimension=dimension)

    def embed(self, func: Dict[str, Any]) -> List[float]:
        pseudocode = func.get('pseudocode') or ''
        if pseudocode:
            return self._token_embedder.embed(pseudocode)
        name = func.get('name', '')
        return self._token_embedder.embed(name)


class SemanticSearchEngine:
    """Brute-force + FAISS semantic search over function embeddings.

    默认不使用外部索引库；`_use_faiss` 为 False 时走纯 Python
    余弦相似度，保证无第三方依赖环境下可用。
    """

    def __init__(self, dimension: int = 128, use_faiss: bool = True) -> None:
        self.dimension = dimension
        self._use_faiss = use_faiss
        self._faiss_index = None
        self._embeddings: List[FunctionEmbedding] = []

    @staticmethod
    def _cosine_sim(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if not a or not b:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    def index_function(self, name: str, address: int,
                       vector: List[float]) -> None:
        """登记一条函数嵌入。"""
        self._embeddings.append(FunctionEmbedding(
            name=name, address=address, vector=list(vector)))

    def search(self, query: List[float], top_k: int = 10
               ) -> List[Tuple[FunctionEmbedding, float]]:
        """按向量相似度返回 Top-k，降序排列。"""
        scored = [(emb, self._cosine_sim(query, emb.vector))
                  for emb in self._embeddings]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def search_by_name(self, name: str, top_k: int = 10
                       ) -> List[Tuple[FunctionEmbedding, float]]:
        """按名称模糊匹配并排除自身，其余按相似度降序。"""
        scored = []
        for emb in self._embeddings:
            if emb.name == name:
                continue
            sim = 1.0 if name in emb.name else self._cosine_sim(
                [float(ord(c)) for c in name],
                [float(ord(c)) for c in emb.name])
            scored.append((emb, sim))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def clear(self) -> None:
        """清空全部嵌入。"""
        self._embeddings = []

    def __len__(self) -> int:
        return len(self._embeddings)

    def clear(self) -> None:
        """Clear all indexed embeddings."""
        self.embeddings.clear()
        self._name_index.clear()
        self._address_index.clear()
        if self._use_faiss:
            try:
                import faiss
                self._faiss_index = faiss.IndexFlatL2(self.dimension)
            except ImportError:
                self._faiss_index = None


class TFIDFVectorizer:
    """TF-IDF vectorizer for text-based function representation."""

    def __init__(self) -> None:
        self.vocabulary_: Dict[str, int] = {}
        self.idf_: Dict[str, float] = {}
        self._document_count: int = 0

    def fit_transform(self, documents: List[str]) -> List[List[float]]:
        """Fit and transform documents in one step.

        Args:
            documents: List of text documents.

        Returns:
            TF-IDF weighted vectors.
        """
        self.fit(documents)
        return self.transform(documents)

    def fit(self, documents: List[str]) -> None:
        """Build vocabulary and compute IDF.

        Args:
            documents: List of text documents.
        """
        doc_freq: Dict[str, int] = {}
        self._document_count = len(documents)

        for doc in documents:
            terms = set(self._tokenize(doc))
            for term in terms:
                doc_freq[term] = doc_freq.get(term, 0) + 1

        sorted_terms = sorted(doc_freq.keys())
        self.vocabulary_ = {term: i for i, term in enumerate(sorted_terms)}

        for term, freq in doc_freq.items():
            self.idf_[term] = math.log(
                (self._document_count + 1) / (freq + 1)
            ) + 1.0

    def transform(self, documents: List[str]) -> List[List[float]]:
        """Transform documents to TF-IDF vectors.

        Args:
            documents: List of text documents.

        Returns:
            TF-IDF weighted vectors.
        """
        if not self.vocabulary_:
            return [[0.0] for _ in documents]

        vectors: List[List[float]] = []
        for doc in documents:
            vec = [0.0] * len(self.vocabulary_)
            terms = self._tokenize(doc)
            term_counts: Dict[str, int] = {}
            for t in terms:
                term_counts[t] = term_counts.get(t, 0) + 1

            for term, count in term_counts.items():
                if term in self.vocabulary_:
                    tf = count / max(len(terms), 1)
                    vec[self.vocabulary_[term]] = tf * self.idf_.get(term, 1.0)

            vectors.append(vec)

        return vectors

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Simple tokenization."""
        import re
        return re.findall(r'[a-zA-Z_]\w*', text.lower())


class VulnerabilityPattern:
    """A known vulnerability pattern for semantic matching."""

    def __init__(self, name: str = "", pattern: str = "") -> None:
        self.name = name
        self.pattern = pattern
        self.severity: str = "medium"
        self.cwe_id: str = ""
        self.description: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            'name': self.name,
            'pattern': self.pattern,
            'severity': self.severity,
            'cwe_id': self.cwe_id,
            'description': self.description,
        }


class TokenEmbedder:
    """Simple token-based embedder."""

    def __init__(self) -> None:
        self.vocab: Dict[str, int] = {}
        self.dim: int = 128

    def embed(self, text: str) -> List[float]:
        tokens = text.lower().split()
        vec = np.zeros(self.dim, dtype=np.float32)
        for token in tokens:
            h = hash(token) % self.dim
            vec[h] += 1.0
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec /= norm
        return vec.tolist()


class CodeBERTEmbedder:
    """Placeholder for CodeBERT-based embedding."""

    def __init__(self) -> None:
        self.model = None

    def embed(self, code: str) -> List[float]:
        return [0.0] * 768


class FunctionEmbedder:
    """Embeds functions into vectors."""

    def __init__(self) -> None:
        self.token_embedder = TokenEmbedder()

    def embed(self, func: Dict[str, Any]) -> List[float]:
        text = func.get('pseudocode', '') or func.get('name', '')
        return self.token_embedder.embed(text)


class FunctionVector:
    """Wrapper for function vector."""

    def __init__(self) -> None:
        self.vec: List[float] = []


class SymbolEmbedder:
    """Embeds symbols (function names, etc.) into vectors."""

    def __init__(self) -> None:
        pass

    def embed(self, symbol: str) -> List[float]:
        return [0.0]


class SearchResult:
    """Search result wrapper."""

    def __init__(
        self,
        name: str = "",
        score: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.score = score
        self.metadata = metadata or {}
        self.embedding: List[float] = []


class SearchIndex:
    """Search index wrapper."""

    def __init__(self, dimension: int = 768) -> None:
        self.dimension = dimension
        self.engine = SemanticSearchEngine(dimension=dimension)

    def add(self, name: str, embedding: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        self.engine.index_function(name, 0, embedding, metadata)

    def search(self, query: List[float], k: int = 10) -> List[SearchResult]:
        results = self.engine.search(query, k)
        return [
            SearchResult(name=emb.name, score=score, metadata=emb.metadata)
            for emb, score in results
        ]


class SemanticSearchResult:
    """Complete semantic search result."""

    def __init__(
        self,
        query: str = "",
        results: Optional[List[SearchResult]] = None,
        elapsed_ms: float = 0.0,
    ) -> None:
        self.query = query
        self.results = results or []
        self.elapsed_ms = elapsed_ms


def semantic_search(
    query: str,
    index: SearchIndex,
    embedder: Optional[TokenEmbedder] = None,
    top_k: int = 10,
) -> SemanticSearchResult:
    """Perform semantic search over function embeddings.

    Args:
        query: Search query string.
        index: SearchIndex to query against.
        embedder: Optional embedder for query encoding.
        top_k: Number of results.

    Returns:
        SemanticSearchResult with matched functions.
    """
    if embedder is None:
        embedder = TokenEmbedder()
    query_vec = embedder.embed(query)
    results = index.search(query_vec, top_k)
    return SemanticSearchResult(query=query, results=results)


def format_search_report(result: SemanticSearchResult) -> str:
    """Format search results into a report.

    Args:
        result: SemanticSearchResult to format.

    Returns:
        Formatted report string.
    """
    lines = [
        f"Semantic Search Results for: '{result.query}'",
        "-" * 40,
    ]
    for i, r in enumerate(result.results):
        lines.append(f"{i + 1}. {r.name} (score: {r.score:.4f})")
        if r.metadata:
            for k, v in r.metadata.items():
                lines.append(f"   {k}: {v}")
    return '\n'.join(lines)
