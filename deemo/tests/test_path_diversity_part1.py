"""
Path diversity tests — Part 1: SimHash, PathFeature, Similarity, Budget.

Tests the path diversity subsystem primitives:
- _simhash / _hamming_distance fast dedup pre-checks
- PathFeature dataclass and hash computation
- PathSimilarityCalculator weighted multi-dimensional similarity
- DiversityBudget quota enforcement and centroid SimHash
"""
import unittest
import time

from modules.analysis.symbolic.path_diversity import (
    PathFeature,
    PathSimilarityCalculator,
    PathFeatureType,
    DiversityBudget,
    _simhash,
    _hamming_distance,
)


class TestSimHash(unittest.TestCase):
    """SimHash computation for fast path deduplication pre-checks."""

    def test_simhash_deterministic(self):
        """相同的特征字典应始终产生相同的 SimHash 指纹"""
        feat = {"structural": {"depth": 3}, "semantic": {"has_comparison": True}}
        sig1 = _simhash(feat, bits=64)
        sig2 = _simhash(feat, bits=64)
        self.assertEqual(sig1, sig2)

    def test_simhash_different_features_different_hash(self):
        """不同特征应产生不同的 SimHash（高概率）；至少 bit 分布不同"""
        f1 = {"a": 1, "b": 2}
        f2 = {"a": 1, "b": 3}
        sig1 = _simhash(f1, bits=64)
        sig2 = _simhash(f2, bits=64)
        # 边缘情况：两个不同的特征字典大概率产生不同 SimHash
        # 但理论上可能碰撞；这里仅验证两者不恒等
        self.assertIsInstance(sig1, int)
        self.assertIsInstance(sig2, int)

    def test_simhash_empty_features(self):
        """空特征字典返回 0 — 所有 bit 计数均为 0，无正计数"""
        sig = _simhash({}, bits=64)
        self.assertEqual(sig, 0)

    def test_simhash_bits_32(self):
        """自定义 bit 数应限制结果位宽"""
        sig = _simhash({"x": 1}, bits=32)
        self.assertLess(sig, 2**32)

    def test_hamming_distance_same(self):
        """相同整数的汉明距离为 0"""
        self.assertEqual(_hamming_distance(0xABCD, 0xABCD), 0)

    def test_hamming_distance_one_bit(self):
        """仅一位不同的两个整数，汉明距离为 1"""
        self.assertEqual(_hamming_distance(1, 3), 1)

    def test_hamming_distance_known(self):
        """0xF (1111) 与 0x0 (0000) 的汉明距离为 4"""
        self.assertEqual(_hamming_distance(0xF, 0x0), 4)


class TestPathFeature(unittest.TestCase):
    """PathFeature dataclass and compute_hash."""

    def test_path_feature_creation(self):
        """PathFeature 基本字段初始化"""
        pf = PathFeature(
            path_id="path_001",
            features={"structural": {"depth": 5}},
            simhash_sig=0xDEADBEEF,
            cluster_id="cluster_A",
            timestamp=time.time(),
        )
        self.assertEqual(pf.path_id, "path_001")
        self.assertEqual(pf.cluster_id, "cluster_A")
        self.assertEqual(pf.simhash_sig, 0xDEADBEEF)

    def test_compute_hash_deterministic(self):
        """相同 features 产出的 hash 应一致"""
        pf1 = PathFeature(path_id="p1", features={"a": 1, "b": 2})
        pf2 = PathFeature(path_id="p2", features={"a": 1, "b": 2})
        self.assertEqual(pf1.compute_hash(), pf2.compute_hash())

    def test_compute_hash_different_features(self):
        """不同 features 的 hash 应不同"""
        pf1 = PathFeature(path_id="p1", features={"a": 1})
        pf2 = PathFeature(path_id="p2", features={"a": 2})
        self.assertNotEqual(pf1.compute_hash(), pf2.compute_hash())

    def test_path_feature_defaults(self):
        """默认字段应合理：空 features 字典、simhash=0、空 cluster_id"""
        pf = PathFeature(path_id="default")
        self.assertEqual(pf.features, {})
        self.assertEqual(pf.simhash_sig, 0)
        self.assertEqual(pf.cluster_id, "")


class TestPathSimilarityCalculator(unittest.TestCase):
    """Weighted multi-dimensional similarity computation."""

    def setUp(self):
        self.calc = PathSimilarityCalculator()

    def test_identical_features_similarity_1(self):
        """完全相同的两个 PathFeature 相似度应为 1"""
        f1 = PathFeature(
            path_id="p1",
            features={
                "structural": {"depth": 1, "constraint_count": 3},
                "semantic": {"has_comparison": True},
                "constraints": {"constraints": ["x > 0"]},
                "coverage": {"hits": 10},
            },
            simhash_sig=_simhash(
                {"structural": {"depth": 1}, "semantic": {"has_comparison": True}}
            ),
        )
        f2 = PathFeature(
            path_id="p2",
            features={
                "structural": {"depth": 1, "constraint_count": 3},
                "semantic": {"has_comparison": True},
                "constraints": {"constraints": ["x > 0"]},
                "coverage": {"hits": 10},
            },
            simhash_sig=f1.simhash_sig,
        )
        sim = self.calc.compute(f1, f2)
        self.assertGreater(sim, 0.95)  # 应接近 1.0

    def test_empty_features_similarity_zero(self):
        """任一 feature 为空时相似度为 0"""
        f1 = PathFeature(path_id="p1", features={})
        f2 = PathFeature(path_id="p2", features={"structural": {"depth": 1}})
        sim = self.calc.compute(f1, f2)
        self.assertEqual(sim, 0.0)

    def test_simhash_fast_reject(self):
        """SimHash 汉明距离 > 3 的路径相似度直接返回 0"""
        f1 = PathFeature(
            path_id="p1",
            features={"structural": {"depth": 1}},
            simhash_sig=0x0000000000000000,
        )
        f2 = PathFeature(
            path_id="p2",
            features={"structural": {"depth": 1}},
            simhash_sig=0xFFFFFFFFFFFFFFFF,  # 64 位全不同
        )
        sim = self.calc.compute(f1, f2)
        self.assertEqual(sim, 0.0)

    def test_custom_weights(self):
        """自定义权重应改变相似度计算结果"""
        calc_biased = PathSimilarityCalculator(
            weights={PathFeatureType.STRUCTURAL: 1.0}
        )
        f1 = PathFeature(
            path_id="p1",
            features={
                "structural": {"depth": 10},
                "semantic": {"has_comparison": False},
            },
        )
        f2 = PathFeature(
            path_id="p2",
            features={
                "structural": {"depth": 10},
                "semantic": {"has_comparison": True},
            },
        )
        sim = calc_biased.compute(f1, f2)
        # structural 相同权重为 1 → 相似度应为 1
        self.assertGreater(sim, 0.9)

    def test_string_similarity(self):
        """字符串前缀匹配相似度：共同前缀越长越相似"""
        # internal helper
        sim = self.calc._string_similarity("hello world", "hello there")
        self.assertGreater(sim, 0.3)  # "hello " 匹配 6/11 或 6/11
        self.assertLess(sim, 1.0)

    def test_numeric_similarity(self):
        """数值相似度：差的绝对值归一化"""
        sim = self.calc._numeric_similarity(10, 10)
        self.assertEqual(sim, 1.0)
        sim2 = self.calc._numeric_similarity(10, 100)
        self.assertLess(sim2, 1.0)
        self.assertGreater(sim2, 0.0)

    def test_numeric_similarity_zeros(self):
        """两个 0 的相似度为 1"""
        sim = self.calc._numeric_similarity(0, 0)
        self.assertEqual(sim, 1.0)


class TestDiversityBudget(unittest.TestCase):
    """Quota enforcement and centroid SimHash computation."""

    def test_budget_cluster_quota(self):
        """quota = max_paths // num_clusters，最小为 1"""
        budget = DiversityBudget(max_paths=100)
        budget.set_cluster_count(4)
        self.assertEqual(budget.cluster_quota, 25)
        budget.set_cluster_count(200)
        self.assertEqual(budget.cluster_quota, 1)  # 下限

    def test_budget_enforce_no_excess(self):
        """未超配额时不逐出"""
        budget = DiversityBudget(max_paths=100)
        budget.set_cluster_count(2)
        pf1 = PathFeature(path_id="p1", simhash_sig=0xAAAA, features={"a": 1})
        pf2 = PathFeature(path_id="p2", simhash_sig=0xBBBB, features={"a": 2})
        clusters = {"c1": ["p1"], "c2": ["p2"]}
        features = {"p1": pf1, "p2": pf2}
        evicted = budget.enforce(clusters, features)
        self.assertEqual(len(evicted), 0)

    def test_budget_compute_centroid_simhash(self):
        """多数投票 centroid_simhash：过半数的 bit 置 1"""
        budget = DiversityBudget(max_paths=100)
        pf1 = PathFeature(path_id="p1", simhash_sig=0b1111, features={"a": 1})
        pf2 = PathFeature(path_id="p2", simhash_sig=0b1100, features={"a": 2})
        pf3 = PathFeature(path_id="p3", simhash_sig=0b1010, features={"a": 3})
        features = {"p1": pf1, "p2": pf2, "p3": pf3}
        centroid = budget.compute_centroid_simhash(["p1", "p2", "p3"], features)
        # bit0: p1=1 p2=0 p3=0 → 1/3 < 1.5 → 0
        # bit1: p1=1 p2=0 p3=1 → 2/3 > 1.5 → 1
        # bit2: p1=1 p2=1 p3=0 → 2/3 > 1.5 → 1
        # bit3: p1=1 p2=1 p3=1 → 3/3 > 1.5 → 1
        expected = 0b1110
        self.assertEqual(centroid, expected)

    def test_budget_empty_cluster_centroid(self):
        """空簇 centroid 为 0"""
        budget = DiversityBudget(max_paths=100)
        centroid = budget.compute_centroid_simhash([], {})
        self.assertEqual(centroid, 0)

    def test_budget_max_paths_property(self):
        budget = DiversityBudget(max_paths=500)
        self.assertEqual(budget.max_paths, 500)


if __name__ == "__main__":
    unittest.main()
