#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 LLM 驱动的二进制摘要与语义搜索模块
"""

import pytest
import os
import tempfile
import shutil

# 添加模块路径
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.semantic_search_llm import (
    SemanticSearchLLM, FunctionSummary, SemanticSearchResult, SearchMode,
    llm_semantic_search, format_search_results
)


class TestSemanticSearchLLM:
    """测试语义搜索LLM模块"""

    def test_initialization(self):
        """测试初始化"""
        searcher = SemanticSearchLLM(llm_type="openai")
        assert searcher is not None
        assert searcher.llm_client is not None

    def test_generate_function_summary(self):
        """测试生成函数摘要"""
        searcher = SemanticSearchLLM(llm_type="openai")
        
        summary = searcher.generate_function_summary(
            function_name="test_function",
            pseudocode="void test() { int a = 1; int b = 2; }",
            assembly="mov eax, 1"
        )
        
        assert isinstance(summary, FunctionSummary)
        assert summary.function_name == "test_function"
        assert summary.summary is not None
        assert summary.summary_vector is not None

    def test_build_index(self):
        """测试构建索引"""
        searcher = SemanticSearchLLM(llm_type="openai")
        
        functions = [
            {
                'function_name': 'func1',
                'address': 0x401000,
                'binary_path': '/tmp/test.bin',
                'pseudocode': 'void func1() { memcpy(dest, src, len); }',
                'assembly': 'call memcpy'
            },
            {
                'function_name': 'func2',
                'address': 0x401050,
                'binary_path': '/tmp/test.bin',
                'pseudocode': 'void func2() { strcpy(buf, input); }',
                'assembly': 'call strcpy'
            }
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            searcher.build_index(functions, index_path=tmpdir)
            assert len(searcher.function_summaries) == 2
            
            # 测试保存和加载索引
            loaded_searcher = SemanticSearchLLM(llm_type="openai")
            loaded_searcher.load_index(tmpdir)
            assert len(loaded_searcher.function_summaries) == 2

    def test_search(self):
        """测试搜索功能"""
        searcher = SemanticSearchLLM(llm_type="openai")
        
        functions = [
            {
                'function_name': 'memcpy_func',
                'address': 0x401000,
                'binary_path': '/tmp/test.bin',
                'pseudocode': 'void memcpy_func(char *dest, char *src, size_t len) { memcpy(dest, src, len); }',
                'assembly': 'call memcpy'
            }
        ]
        
        searcher.build_index(functions)
        
        result = searcher.search("memory copy function")
        
        assert isinstance(result, SemanticSearchResult)
        assert result.query == "memory copy function"
        assert result.search_mode == SearchMode.LLM
        assert result.total_results >= 0

    def test_search_no_index(self):
        """测试没有索引时的搜索"""
        searcher = SemanticSearchLLM(llm_type="openai")
        
        result = searcher.search("test query")
        
        assert result.total_results == 0
        assert "请先构建或加载索引" in result.suggestions

    def test_format_search_results(self):
        """测试格式化搜索结果"""
        result = SemanticSearchResult(
            query="test",
            search_mode=SearchMode.LLM,
            total_results=1,
            results=[{
                'function_name': 'test_func',
                'function_address': 0x401000,
                'binary_path': '/tmp/test.bin',
                'similarity_score': 0.85,
                'summary': 'This is a test function',
                'keywords': ['test', 'function'],
                'vulnerability_indicators': [],
                'confidence_score': 0.9
            }],
            search_time=0.1,
            index_info={'total_indexed': 1, 'index_path': '/tmp/index'}
        )
        
        formatted = format_search_results(result)
        assert "LLM语义搜索报告" in formatted
        assert "test_func" in formatted
        assert "This is a test function" in formatted

    def test_batch_generate_summaries(self):
        """测试批量生成摘要"""
        searcher = SemanticSearchLLM(llm_type="openai")
        
        functions = [
            {'function_name': 'func1', 'pseudocode': 'void func1() {}', 'assembly': ''},
            {'function_name': 'func2', 'pseudocode': 'void func2() {}', 'assembly': ''}
        ]
        
        summaries = searcher.batch_generate_summaries(functions)
        
        assert len(summaries) == 2
        assert all(isinstance(s, FunctionSummary) for s in summaries)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])