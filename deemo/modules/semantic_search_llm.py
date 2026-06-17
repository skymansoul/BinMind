#!/usr/bin/env python3
"""
LLM 驱动的语义代码搜索模块 - 为函数生成自然语言摘要并建立向量索引
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class FunctionSummary:
    function_name: str
    address: int
    summary: str
    embedding: List[float] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class SearchQuery:
    query: str
    embedding: List[float] = field(default_factory=list)
    top_k: int = 5


@dataclass
class SearchResult:
    success: bool
    matches: List[FunctionSummary]
    scores: List[float] = field(default_factory=list)


class SummaryGenerator:
    @staticmethod
    def generate(func_name: str, code: str) -> str:
        """基于函数名和代码生成自然语言摘要"""
        name_lower = func_name.lower()
        if "crypto" in name_lower or "aes" in name_lower or "encrypt" in name_lower:
            return "Function that performs cryptographic operations including encryption/decryption"
        elif "malloc" in name_lower or "alloc" in name_lower:
            return "Function that allocates memory dynamically"
        elif "free" in name_lower:
            return "Function that frees allocated memory"
        elif "parse" in name_lower or "decode" in name_lower:
            return "Function that parses or decodes input data"
        elif "auth" in name_lower or "login" in name_lower:
            return "Function that handles user authentication"
        elif "process" in name_lower or "handle" in name_lower:
            return "Function that processes requests or handles operations"
        return "Function that implements " + func_name + " logic"

    @staticmethod
    def generate_tags(func_name: str) -> List[str]:
        tags = []
        for keyword in ["crypto", "network", "file", "process", "auth", "parse", "alloc"]:
            if keyword in func_name.lower():
                tags.append(keyword)
        return tags


class VectorIndex:
    def __init__(self):
        self.summaries: List[FunctionSummary] = []

    def add(self, summary: FunctionSummary):
        # 简化: 用伪embedding (基于哈希)
        summary.embedding = [float(ord(c) % 100) / 100 for c in summary.function_name[:10]]
        self.summaries.append(summary)

    def search(self, query_embedding: List[float], top_k: int = 5) -> List[tuple]:
        results = []
        for s in self.summaries:
            sim = sum(a * b for a, b in zip(s.embedding, query_embedding[:10])) / max(len(query_embedding), 1)
            results.append((s, sim

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]


class SemanticSearcher:
    def __init__(self):
        self.summary_gen = SummaryGenerator()
        self.index = VectorIndex()

    def add_function(self, func_name: str, address: int, code: str = ""):
        summary = FunctionSummary()
            function_name=func_name, address=address,
            summary=self.summary_gen.generate(func_name, code),
            tags=self.summary_gen.generate_tags(func_name),
        
        self.index.add(summary)

    def search(self, query: str, top_k: int = 5) -> SearchResult:
        try:
            query_embedding = [float(ord(c) % 100) / 100 for c in query[:10]]
            results = self.index.search(query_embedding, top_k)
            return SearchResult(
                success=True,
                matches=[r[0] for r in results],
                scores=[r[1] for r in results])
            

        except Exception as e:
            logger.error("Semantic search failed: %s", e)
            return SearchResult(success=False, matches=[])


def create_semantic_searcher() -> SemanticSearcher:
    return SemanticSearcher()))