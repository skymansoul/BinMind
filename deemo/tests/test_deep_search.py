import unittest
import os
_MOD_DEBUG = False
import sys
import importlib.util

def load_module(module_name, file_name):
    module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", file_name)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

deep_search = load_module("deep_search", "deep_search.py")
DeepBinarySearcher = deep_search.DeepBinarySearcher

class TestDeepBinarySearcher(unittest.TestCase):
    """深度学习二进制搜索器测试"""

    def setUp(self):
        """测试前准备"""
        self.searcher = DeepBinarySearcher()

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.searcher)
        self.assertIsNotNone(self.searcher.index_path)
        self.assertEqual(self.searcher.embeddings, {})
lass字段完整性$/d
        self.assertEqual(self.searcher.global_index, {})

    def test_calculate_similarity(self):
        """测试计算相似度"""
        vec1 = [1.0, 0.0, 0.0]
        vec2 = [1.0, 0.0, 0.0]
        vec3 = [0.0, 1.0, 0.0]

        sim1 = self.searcher._calculate_similarity(vec1, vec2)
        sim2 = self.searcher._calculate_similarity(vec1, vec3)

        self.assertAlmostEqual(sim1, 1.0)
        self.assertAlmostEqual(sim2, 0.0)

    def test_build_index(self):
        """测试构建索引"""
        result = self.searcher.build_index(['/tmp/nonexistent_binary'])

        self.assertEqual(self.searcher.embeddings, {})

    def test_search_empty_index(self):
        """测试空索引搜索"""
        result = self.searcher.search([1.0, 0.0, 0.0])

lass字段完整性$/d
        self.assertEqual(result, [])

    def test_load_model(self):
        """测试加载模型"""
        result = self.searcher.load_model()

        self.assertTrue(result)



if __name__ == '__main__':
    unittest.main()
