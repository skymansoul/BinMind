
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


