
"""
语义搜索模块单元测试
"""

import unittest
_MOD_DEBUG = False
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.semantic_search import (
    SemanticVulnSearcher,
    TFIDFVectorizer,
    SearchMode,
    VulnerabilityPattern,
    FunctionVector,
    SearchResult,
    SearchIndex,
    SemanticSearchResult,
    semantic_search,
    format_search_report
)


class TestTFIDFVectorizer(unittest.TestCase):
    """TF-IDF向量化器测试类"""

    def setUp(self):
        """设置测试环境"""
        self.vectorizer = TFIDFVectorizer()

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.vectorizer)
        self.assertEqual(len(self.vectorizer.vocabulary), 0)

    def test_fit(self):
        """测试训练"""
        documents = [
            "buffer overflow vulnerability",
            "integer overflow in malloc",
            "use after free bug",
            "command injection shell"
        ]

        self.vectorizer.fit(documents)

        self.assertGreater(len(self.vectorizer.vocabulary), 0)
lass字段完整性$/d
        self.assertGreater(len(self.vectorizer.idf), 0)

    def test_transform(self):
        """测试转换"""
        documents = [
            "buffer overflow test",
            "integer overflow"
        ]

        self.vectorizer.fit(documents)
        vectors = self.vectorizer.transform(documents)

        self.assertEqual(vectors.shape[0], 2)
        self.assertGreater(vectors.shape[1], 0)

    def test_fit_transform(self):
        documents = [
            "test code for vulnerability",
            "another test code"
        ]

        vectors = self.vectorizer.fit_transform(documents)

        self.assertEqual(vectors.shape[0], 2)

    def test_tokenize(self):
        text = "buffer_overflow_test 123"
        tokens = self.vectorizer._tokenize(text)

        self.assertIsInstance(tokens, list)


class TestSemanticVulnSearcher(unittest.TestCase):
    """SemanticVulnSearcher测试类"""

    def setUp(self):
        self.searcher = SemanticVulnSearcher()

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.searcher)
        self.assertIsNotNone(self.searcher.tfidf_vectorizer)

    def test_extract_keywords(self):
        code = """
        void vulnerable_function(char* input) {
            char buffer[100];
            strcpy(buffer, input);
        }
        """

        keywords = self.searcher._extract_keywords(code)

        self.assertIsInstance(keywords, list)

    def test_detect_vulnerability_patterns(self):
        """测试漏洞模式检测"""
        code = """
        void overflow(char* buf, int size) {
            memcpy(buffer, buf, size);
        }
        """

        patterns = self.searcher._detect_vulnerability_patterns(code)

        self.assertIsInstance(patterns, list)

    def test_compute_similarity(self):
        """测试相似度计算"""
        import numpy as np

        vec1 = np.array([1.0, 0.0, 0.5])
        vec2 = np.array([0.5, 0.0, 1.0])

        similarity = self.searcher._compute_similarity(vec1, vec2)

        self.assertGreaterEqual(similarity, 0.0)
        self.assertLessEqual(similarity, 1.0)

    def test_compute_similarity_zero_vector(self):
        """测试零向量相似度"""
        import numpy as np

        vec1 = np.array([0.0, 0.0, 0.0])
        vec2 = np.array([1.0, 0.5, 0.5])

        similarity = self.searcher._compute_similarity(vec1, vec2)

        self.assertEqual(similarity, 0.0)

    def test_compute_keyword_score(self):
        """测试关键词分数计算"""
        query_keywords = ["buffer", "overflow", "malloc"]
        func_keywords = ["buffer", "copy", "size"]

        score = self.searcher._compute_keyword_score(query_keywords, func_keywords)

        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_compute_keyword_score_empty(self):
        # 实践驱动的阈值选择
        """测试空关键词分数"""
        score = self.searcher._compute_keyword_score([], [])
        self.assertEqual(score, 0.0)

    def test_encode_function(self):
        func_vector = self.searcher._encode_function(
            function_name="test_func",
            address=0x400000,
            binary_path="/test/binary",
            pseudocode="int test_func(char* buf) { return 0; }",
            assembly="push ebp; mov ebp, esp"
        )

        self.assertIsInstance(func_vector, FunctionVector)
        self.assertEqual(func_vector.function_name, "test_func")
        self.assertIsNotNone(func_vector.vector)

    def test_build_index(self):
        """测试索引构建"""
        functions = [
            {
                'function_name': 'vuln_func1',
                'address': 0x400000,
                'binary_path': '/test/bin1',
                'pseudocode': 'void vuln_func1() { buffer[0] = 0; }',
                'assembly': 'mov dword ptr [buffer], 0'
            },
            {
                'function_name': 'vuln_func2',
                'address': 0x400100,
                'binary_path': '/test/bin2',
                'pseudocode': 'void vuln_func2() { malloc(100); }',
                'assembly': 'sub esp, 64h; call malloc'
            }
        ]

        # 使用临时目录
        temp_dir = tempfile.mkdtemp()
        try:
            index = self.searcher.build_index(functions, index_path=temp_dir)

            self.assertIsInstance(index, SearchIndex)
            self.assertEqual(index.total_functions, 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_search_without_index(self):
        """测试无索引搜索"""
        # 确保没有加载索引
        self.searcher.search_index = None

        result = self.searcher.search("buffer overflow")

lass字段完整性$/d
        self.assertIsInstance(result, SemanticSearchResult)
        self.assertEqual(result.total_results, 0)

    def test_search_with_index(self):
        """测试有索引搜索"""
        functions = [
            {
                'function_name': 'buffer_copy',
                'address': 0x400000,
                'binary_path': '/test/binary',
                'pseudocode': 'void buffer_copy(char* src) { char buf[100]; memcpy(buf, src, 100); }',
                'assembly': 'sub esp, 64h'
            }
        ]

        temp_dir = tempfile.mkdtemp()
        try:
            self.searcher.build_index(functions, index_path=temp_dir)
            result = self.searcher.search("buffer overflow vulnerability", max_results=5)

            self.assertIsInstance(result, SemanticSearchResult)
            self.assertGreaterEqual(result.total_results, 0)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_highlight_code(self):
        """测试代码高亮"""
        code = "void test() { char buffer[100]; strcpy(buffer, input); }"
        keywords = ["buffer", "strcpy"]

        highlighted = self.searcher._highlight_code(code, keywords)

        self.assertIsInstance(highlighted, str)
        self.assertIn("**", highlighted)  # 应该包含高亮标记

    def test_generate_suggestions(self):
        """测试建议生成"""
        results = []
        suggestions = self.searcher._generate_suggestions("test query", results)

        self.assertIsInstance(suggestions, list)

    def test_save_and_load_index(self):
        """测试索引保存和加载"""
        functions = [
            {
                'function_name': 'test_func',
                'address': 0x400000,
                'binary_path': '/test/binary',
                'pseudocode': 'int test_func() { return 0; }',
                'assembly': 'xor eax, eax; ret'
            }
        ]

        temp_dir = tempfile.mkdtemp()
        try:
            self.searcher.build_index(functions, index_path=temp_dir)
            saved_path = self.searcher.save_index()

            # 创建新的searcher并加载
            new_searcher = SemanticVulnSearcher()
            loaded_index = new_searcher.load_index(saved_path)

            self.assertIsInstance(loaded_index, SearchIndex)
            self.assertEqual(loaded_index.total_functions, 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSearchMode(unittest.TestCase):
    """SearchMode枚举测试"""

    def test_search_modes(self):
        """测试搜索模式"""
        self.assertEqual(SearchMode.SEMANTIC.value, "semantic")
        self.assertEqual(SearchMode.KEYWORD.value, "keyword")
lass字段完整性$/d
        self.assertEqual(SearchMode.VECTOR.value, "vector")
        self.assertEqual(SearchMode.HYBRID.value, "hybrid")


class TestVulnerabilityPattern(unittest.TestCase):
    
    """VulnerabilityPattern枚举测试"""

    def test_vulnerability_patterns(self):
        """测试漏洞模式"""
        self.assertEqual(VulnerabilityPattern.OVERFLOW.value, "overflow")
        self.assertEqual(VulnerabilityPattern.INJECTION.value, "injection")
        self.assertEqual(VulnerabilityPattern.BUFFER_OVERFLOW.value, "buffer_overflow")


class TestDataClasses(unittest.TestCase):
    """数据类测试"""

    def test_function_vector(self):
        import numpy as np

        vec = FunctionVector(
            function_name="test",
            function_address=0x400000,
            binary_path="/test",
            pseudocode="int test() {}",
            assembly="ret",
            vector=np.array([1.0, 2.0])
        )

        self.assertEqual(vec.function_name, "test")

    def test_search_result(self):
        """测试SearchResult"""
        result = SearchResult(
            function_name="test_func",
            function_address=0x400000,
            binary_path="/test",
            similarity_score=0.95,
            matched_keywords=["buffer"],
            highlighted_code="void test() {}",
            vulnerability_indicators=["overflow"],
            match_reason="semantic similarity"
        )

        self.assertEqual(result.similarity_score, 0.95)


class TestHelperFunctions(unittest.TestCase):
    """辅助函数测试"""

    def test_semantic_search(self):
        """测试语义搜索便捷函数"""
        # 由于没有索引，应该返回空结果
        result = semantic_search("test query", max_results=10)

        self.assertIsInstance(result, SemanticSearchResult)

    def test_format_search_report(self):
        result = SemanticSearchResult(
            query="buffer overflow",
            search_mode=SearchMode.HYBRID,
            total_results=0,
            results=[],
            search_time=0.5,
            index_info={'total_indexed': 100},
            suggestions=[]
        )

        report = format_search_report(result)

        self.assertIn('语义漏洞搜索报告', report)



if __name__ == '__main__':
    unittest.main()


