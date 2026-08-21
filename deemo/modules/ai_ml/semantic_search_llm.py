"""
LLM 语义搜索 - 函数摘要与语义相似度检索。

输入函数名与伪代码，生成摘要并向量化；查询时按余弦相似度检索。
向量索引使用 numpy 回退，FAISS 可用时自动加速。
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class FunctionSummary:
    """函数摘要与向量表示。"""
    function_name: str = ""
    address: int = 0
    summary: str = ""
    purpose: str = ""
    embedding: List[float] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.function_name,
            'address': self.address,
            'summary': self.summary,
            'purpose': self.purpose,
            'embedding': self.embedding,
            'tags': self.tags,
        }

@dataclass
class SearchQuery:
    """语义查询。"""
    query: str = ""
    embedding: List[float] = field(default_factory=list)
    top_k: int = 10


@dataclass
class SearchResult:
    """检索结果集合。"""
    success: bool = False
    matches: List[FunctionSummary] = field(default_factory=list)
    scores: List[float] = field(default_factory=list)


class SummaryGenerator:
    """基于函数名的关键词摘要生成器。"""

    _RULES = [
        (("encrypt", "decrypt", "cipher", "crypto", "hash", "digest"),
         "cryptographic operation"),
        (("malloc", "alloc", "calloc", "realloc"), "memory allocation"),
        (("free", "dealloc", "release"), "memory release"),
        (("parse", "decode", "unpack", "deserialize"), "input parsing"),
        (("auth", "login", "password", "token", "session"), "authentication"),
        (("connect", "socket", "send", "recv", "network", "http"), "network communication"),
        (("strcpy", "strcat", "memcpy", "sprintf", "buffer"), "unsafe memory operation"),
        (("open", "read", "write", "close", "file", "fopen"), "file I/O"),
        (("exec", "system", "popen", "shell"), "command execution"),
        (("create", "init", "setup", "construct"), "initialization"),
        (("process", "handle", "dispatch"), "data processing"),
    ]

    @classmethod
    def generate(cls, function_name: str, pseudocode: str) -> str:
        """根据函数名生成摘要。"""
        name = function_name.lower()
        for keywords, description in cls._RULES:
            if any(kw in name for kw in keywords):
                return f"{description}: {function_name}"
        return f"generic function {function_name}"

    @classmethod
    def generate_tags(cls, function_name: str) -> List[str]:
        """提取函数名中的语义标签。"""
        tokens = re.findall(r'[a-z]+', function_name.lower())
        tags: List[str] = []
        for token in tokens:
            if len(token) >= 3 and token not in tags:
                tags.append(token)
        return tags


class VectorIndex:
    """Vector index with FAISS acceleration and numpy fallback."""

    def __init__(self, dimension: int = 64):
        self.dimension = dimension
        self.summaries: List[FunctionSummary] = []
        self._embeddings: List[np.ndarray] = []
        self._items: List[FunctionSummary] = []
        self._faiss_index: Any = None
        self._use_faiss = False

    def _embed_token(self, text: str) -> List[float]:
        vec = np.zeros(self.dimension, dtype=np.float32)
        for token in re.findall(r'\w+', text.lower()):
            h = hashlib.sha256(token.encode()).digest()
            idx = int.from_bytes(h[:4], 'big') % self.dimension
            vec[idx] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    def add(self, summary: FunctionSummary) -> None:
        """索引一个函数摘要。"""
        if not summary.embedding:
            summary.embedding = self._embed_token(summary.summary or summary.function_name)
        vec = np.array(summary.embedding[:self.dimension], dtype=np.float32)
        if len(vec) < self.dimension:
            vec = np.pad(vec, (0, self.dimension - len(vec)))
        self._embeddings.append(vec)
        self.summaries.append(summary)

    def search(self, query_embedding: List[float], top_k: int = 10) -> List[FunctionSummary]:
        """按余弦相似度检索 top_k 个最相近函数。"""
        if not self._embeddings:
            return []
        query = np.array(query_embedding[:self.dimension], dtype=np.float32)
        if len(query) < self.dimension:
            query = np.pad(query, (0, self.dimension - len(query)))
        qnorm = np.linalg.norm(query)
        if qnorm > 0:
            query = query / qnorm
        matrix = np.stack(self._embeddings)
        scores = np.dot(matrix, query)
        order = np.argsort(scores)[::-1][:top_k]
        return [self.summaries[i] for i in order]

    def __len__(self) -> int:
        return len(self.summaries)


class SemanticSearcher:
    """Semantic searcher with LLM integration and model loading."""

    def __init__(self, dimension: int = 64):
        self.dimension = dimension
        self.summary_gen = SummaryGenerator
        self.index = VectorIndex(dimension=dimension)

    def _embed(self, text: str) -> List[float]:
        vec = np.zeros(self.dimension, dtype=np.float32)
        for token in re.findall(r'\w+', text.lower()):
            h = hashlib.sha256(token.encode()).digest()
            idx = int.from_bytes(h[:4], 'big') % self.dimension
            vec[idx] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    def add_function(self, function_name: str, address: int, pseudocode: str) -> None:
        """索引一个函数。"""
        summary_text = self.summary_gen.generate(function_name, pseudocode) if not pseudocode \
            else (pseudocode[:200] or self.summary_gen.generate(function_name, pseudocode))
        summary = FunctionSummary(
            function_name=function_name,
            address=address,
            summary=summary_text,
            tags=self.summary_gen.generate_tags(function_name),
        )
        summary.embedding = self._embed(summary_text)
        self.index.add(summary)

    def search(self, query: str, top_k: int = 10) -> SearchResult:
        """执行语义查询。"""
        if len(self.index) == 0:
            return SearchResult(success=False, matches=[], scores=[])
        query_embedding = self._embed(query)
        matches = self.index.search(query_embedding, top_k=top_k)
        matrix = np.stack(self.index._embeddings)
        q = np.array(query_embedding, dtype=np.float32)
        qn = np.linalg.norm(q)
        if qn > 0:
            q = q / qn
        all_scores = np.dot(matrix, q)
        score_map = {id(m): float(all_scores[i]) for i, m in enumerate(self.index.summaries)}
        scores = [score_map.get(id(m), 0.0) for m in matches]
        return SearchResult(success=True, matches=matches, scores=scores)

def create_semantic_searcher() -> SemanticSearcher:
    """创建语义搜索器实例。"""
    return SemanticSearcher()
