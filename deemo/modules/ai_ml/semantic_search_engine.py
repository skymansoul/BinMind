# -*- coding: utf-8 -*-
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import field

import numpy as np


class FunctionEmbedding:
    def __init__(self, name: str = "", address: int = 0,
                 pseudocode: str = "", vector: Optional[List[float]] = None,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        self.name = name
        self.address = address
        self.pseudocode = pseudocode
        self.vector = vector or []
        self.metadata = metadata or {}


class SemanticSearchEngine:
    """暴力 + FAISS 语义搜索。

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
        if not a or not b:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    def index_function(self, name: str, address: int,
                       vector: List[float],
                       metadata: Optional[Dict[str, Any]] = None) -> None:
        """登记一条函数嵌入。"""
        self._embeddings.append(FunctionEmbedding(
            name=name, address=address, vector=list(vector),
            metadata=metadata or {}))

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


class TFIDFVectorizer:
    """TF-IDF 文本向量化器。"""

    def __init__(self) -> None:
        self.vocabulary_: Dict[str, int] = {}
        self.idf_: Dict[str, float] = {}
        self._document_count: int = 0

    def fit_transform(self, documents: List[str]) -> List[List[float]]:
        self.fit(documents)
        return self.transform(documents)

    def fit(self, documents: List[str]) -> None:
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
        return re.findall(r'[a-zA-Z_]\w*', text.lower())


class VulnerabilityPattern:
    """已知漏洞模式 — 语义匹配用。"""

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
    """基于 token 哈希的轻量嵌入器。"""

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
    """CodeBERT 嵌入占位。"""

    def __init__(self) -> None:
        self.model = None

    def embed(self, code: str) -> List[float]:
        return [0.0] * 768


class FunctionEmbedder:
    """函数嵌入器。"""

    def __init__(self) -> None:
        self.token_embedder = TokenEmbedder()

    def embed(self, func: Dict[str, Any]) -> List[float]:
        text = func.get('pseudocode', '') or func.get('name', '')
        return self.token_embedder.embed(text)


class FunctionVector:
    """函数向量包装。"""

    def __init__(self) -> None:
        self.vec: List[float] = []


class SymbolEmbedder:
    """符号嵌入器。"""

    def __init__(self) -> None:
        pass

    def embed(self, symbol: str) -> List[float]:
        return [0.0]


class SearchResult:
    """搜索结果包装。"""

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
    """搜索索引包装。"""

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
    """完整语义搜索结果。"""

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
    if embedder is None:
        embedder = TokenEmbedder()
    query_vec = embedder.embed(query)
    results = index.search(query_vec, top_k)
    return SemanticSearchResult(query=query, results=results)


def format_search_report(result: SemanticSearchResult) -> str:
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
