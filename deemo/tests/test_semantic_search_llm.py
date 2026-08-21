
"""
Test LLM-driven binary summary and semantic search module
"""

import pytest
import os
import tempfile
import shutil

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.semantic_search_llm import (
    SemanticSearcher, FunctionSummary, SearchQuery, SearchResult,
    SummaryGenerator, VectorIndex, create_semantic_searcher
)


class TestFunctionSummary:
    """Test function summary dataclass"""

    def test_function_summary_creation(self):
        summary = FunctionSummary(
            function_name="test_func",
            address=0x401000,
            summary="Test function that processes data",
            embedding=[0.1, 0.2, 0.3],
            tags=["test", "process"],
        )
        assert summary.function_name == "test_func"
        assert summary.address == 0x401000
        assert summary.summary == "Test function that processes data"
        assert len(summary.embedding) == 3
        assert "test" in summary.tags


class TestSearchQuery:
    """Test search query dataclass"""

    def test_search_query_creation(self):
        query = SearchQuery(
            query="memory copy function",
            embedding=[0.1, 0.2, 0.3],
            top_k=10,
        )
        assert query.query == "memory copy function"
        assert query.top_k == 10


class TestSearchResult:

    def test_search_result_success(self):
        summary = FunctionSummary(
            function_name="test_func",
            address=0x401000,
            summary="A test function",
        )
        result = SearchResult(
            success=True,
            matches=[summary],
            scores=[0.95],
        )
        assert result.success is True
        assert len(result.matches) == 1
        assert result.scores[0] == 0.95

    def test_search_result_failure(self):
        result = SearchResult(
            success=False,
            matches=[],
        )
        assert result.success is False
        assert len(result.matches) == 0


class TestSummaryGenerator:
    """Test summary generator"""

    def test_generate_crypto(self):
        summary = SummaryGenerator.generate("encrypt_data", "")
        assert "cryptographic" in summary.lower() or "encrypt" in summary.lower()

    def test_generate_malloc(self):
        summary = SummaryGenerator.generate("malloc_buf", "")
        assert "alloc" in summary.lower()

    def test_generate_free(self):
        summary = SummaryGenerator.generate("free_memory", "")
        assert "free" in summary.lower()

    def test_generate_parse(self):
        summary = SummaryGenerator.generate("parse_input", "")
        assert "parse" in summary.lower() or "decode" in summary.lower()

    def test_generate_auth(self):
        summary = SummaryGenerator.generate("authenticate_user", "")
        assert "auth" in summary.lower()

    def test_generate_generic(self):
        summary = SummaryGenerator.generate("unknown_func", "")
        assert "unknown_func" in summary

    def test_generate_tags(self):
        tags = SummaryGenerator.generate_tags("crypto_func")
        assert "crypto" in tags

        tags = SummaryGenerator.generate_tags("process_request")
        assert "process" in tags


class TestVectorIndex:
    """Test vector index"""

    def test_add_and_search(self):

        index = VectorIndex()
        summary = FunctionSummary(
            function_name="memcpy_func",
            address=0x401000,
            summary="Memory copy function",
        )
        index.add(summary)
        assert len(index.summaries) == 1

        query_embedding = [float(ord(c) % 100) / 100 for c in "memcpy_func"[:10]]
        results = index.search(query_embedding, top_k=5)
        assert len(results) == 1

    def test_search_returns_top_k(self):
        index = VectorIndex()
        for i in range(10):
            summary = FunctionSummary(
                function_name=f"func_{i}",
                address=0x401000 + i * 0x100,
                summary=f"Function {i}",
            )
            index.add(summary)

        query_embedding = [0.5] * 10
        results = index.search(query_embedding, top_k=3)
        assert len(results) == 3


class TestSemanticSearcher:

    def test_initialization(self):
        searcher = SemanticSearcher()
        assert searcher is not None
        assert searcher.summary_gen is not None
        assert searcher.index is not None

    def test_add_function(self):
        searcher = SemanticSearcher()

        searcher.add_function("test_func", 0x401000, "void test() {}")

        assert len(searcher.index.summaries) == 1

    def test_search(self):
        searcher = SemanticSearcher()
        searcher.add_function("memcpy_func", 0x401000, "")

        result = searcher.search("memory copy")

        assert isinstance(result, SearchResult)
        assert result.success is True

    def test_search_empty_index(self):
        searcher = SemanticSearcher()

        result = searcher.search("test query")

        assert isinstance(result, SearchResult)
        # May succeed with empty results or fail
        assert len(result.matches) == 0

    def test_multiple_add_and_search(self):
        searcher = SemanticSearcher()
        searcher.add_function("func_a", 0x401000, "")
        searcher.add_function("func_b", 0x401050, "")

        result = searcher.search("function", top_k=2)

        assert isinstance(result, SearchResult)
        assert result.success is True
        assert len(result.matches) <= 2

    def test_create_semantic_searcher(self):
        searcher = create_semantic_searcher()
        assert isinstance(searcher, SemanticSearcher)



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


