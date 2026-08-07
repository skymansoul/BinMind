"""
Path diversity tests — Part 4: Feature vector, RandomProjectionTree, Explorer.

Tests the path diversity subsystem ANN internals and top-level driver:
- _feature_to_vector vector flattening
- _RandomProjectionTree individual tree operations
- DynamicPathExplorator top-level driver
"""
import unittest

from modules.analysis.symbolic.path_diversity import (
    PathFeature,
    _feature_to_vector,
    _RandomProjectionTree,
    DynamicPathExplorator,
    run_path_diversity_exploration,
)


class TestFeatureToVector(unittest.TestCase):
    """Vector flattening for ANN indexing."""

    def test_empty_feature(self):
        """空 feature 返回全零向量"""
        pf = PathFeature(path_id="empty", features={})
        vec = _feature_to_vector(pf, dim=64)
        self.assertEqual(len(vec), 64)
        self.assertTrue(all(v == 0.0 for v in vec))

    def test_vector_dimension(self):
        """默认输出维度为 64"""
        pf = PathFeature(path_id="p1", features={"a": {"deep": {"nested": 42}}})
        vec = _feature_to_vector(pf, dim=64)
        self.assertEqual(len(vec), 64)

    def test_vector_values_normalized(self):
        """向量值在 [0, 1] 范围内"""
        pf = PathFeature(path_id="p1", features={"s": {"depth": 10, "cnt": 5}})
        vec = _feature_to_vector(pf, dim=64)
        for v in vec:
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)


class TestRandomProjectionTree(unittest.TestCase):
    """Individual random projection tree for ANN."""

    def test_build_small(self):
        """小数据集构建单棵树"""
        tree = _RandomProjectionTree(dim=64, leaf_size=2)
        pf1 = PathFeature(path_id="p1", features={"a": 1})
        pf2 = PathFeature(path_id="p2", features={"b": 2})
        vec1 = _feature_to_vector(pf1)
        vec2 = _feature_to_vector(pf2)
        tree.build({"p1": vec1, "p2": vec2})
        self.assertIsNotNone(tree._root)

    def test_query_returns_candidates(self):
        """查询返回最相似的 k 个候选"""
        tree = _RandomProjectionTree(dim=64, leaf_size=2)
        vec1 = _feature_to_vector(PathFeature(path_id="p1", features={"a": 1}))
        vec2 = _feature_to_vector(PathFeature(path_id="p2", features={"a": 1}))
        tree.build({"p1": vec1, "p2": vec2})
        results = tree.query(vec1, {"p1": vec1, "p2": vec2}, k=1)
        self.assertGreater(len(results), 0)

    def test_query_empty_tree(self):
        """未构建的树查询返回空"""
        tree = _RandomProjectionTree(dim=64)
        results = tree.query([0.0] * 64, {}, k=3)
        self.assertEqual(len(results), 0)

    def test_cosine_identical(self):
        """相同向量的余弦相似度为 1"""
        v = [1.0] * 10
        sim = _RandomProjectionTree._cosine(v, v)
        self.assertAlmostEqual(sim, 1.0, places=5)

    def test_cosine_orthogonal(self):
        """正交向量的余弦相似度为 0"""
        v1 = [1.0, 0.0, 0.0]
        v2 = [0.0, 1.0, 0.0]
        sim = _RandomProjectionTree._cosine(v1, v2)
        self.assertAlmostEqual(sim, 0.0, places=5)


class TestDynamicPathExplorator(unittest.TestCase):
    """Top-level exploration driver."""

    def test_explore_successful(self):
        """explore 返回 explored_paths 和 stats"""
        explorer = DynamicPathExplorator(strategy="hybrid")
        for i in range(15):
            explorer.add_path_candidate(f"path_{i}", 0x1000 + i * 0x10, ["x > 0"], depth=i % 3)
        result = explorer.explore(iterations=10)
        self.assertTrue(result["success"])
        self.assertIn("explored_paths", result)
        self.assertGreaterEqual(result["explored_paths"], 0)

    def test_invalid_strategy_falls_back(self):
        """无效 strategy 回退到 HYBRID"""
        explorer = DynamicPathExplorator(strategy="nonexistent")
        explorer.add_path_candidate("p1", 0x1000, ["x > 0"])
        stats = explorer.get_stats()
        self.assertIn("strategy", stats)

    def test_max_explorations_limit(self):
        """达到 max_explorations 上限后停止"""
        explorer = DynamicPathExplorator(strategy="hybrid")
        explorer._max_explorations = 3
        for i in range(20):
            explorer.add_path_candidate(f"p{i}", 0x1000 + i * 0x10, ["x > 0"])
        result = explorer.explore(iterations=50)
        self.assertLessEqual(result["explored_paths"], 3)

    def test_run_path_diversity_exploration(self):
        """run_path_diversity_exploration 一站式运行"""
        result = run_path_diversity_exploration(strategy="hybrid", iterations=10, path_count=5)
        self.assertIn("success", result)
        self.assertIn("final_stats", result)


if __name__ == "__main__":
    unittest.main()
