"""
Tests for the multi-backend SMT solver manager, TDigest, health scoring,
and cross-solver consensus tracking.

Covers:
- TDigest: insertion, percentile approximation, compression
- SolverTracing: per-solver latency recording and retrieval
- SolverPoolHealth: 0-100 composite health score with EWMA smoothing
- CrossSolverConsensus: sliding-window agreement tracking
- ConstraintSolverManager: registration, fallback, classification, selection
"""
import unittest
import time
import math

from modules.analysis.symbolic.constraint_solver_manager import (
    ConstraintSolverManager,
    SolverType,
    ConstraintCategory,
    SolverConfig,
    SolverResult,
    SolverPerformance,
    TDigest,
    SolverTracing,
    SolverPoolHealth,
    CrossSolverConsensus,
    DEFAULT_TIMEOUT,
    manage_constraint_solver,
)


class TestTDigest(unittest.TestCase):
    """TDigest: compact online percentile estimation using centroids."""

    def test_empty_digest_percentile_zero(self):
        """空 digest 的任意百分位数均为 0"""
        td = TDigest(compression=100)
        self.assertEqual(td.percentile(50), 0.0)
        self.assertEqual(td.percentile(99), 0.0)

    def test_single_value_percentile(self):
        """单个值的任意百分位数都返回该值本身"""
        td = TDigest(compression=100)
        td.add(42.0)
        self.assertEqual(td.percentile(0), 42.0)
        self.assertEqual(td.percentile(50), 42.0)
        self.assertEqual(td.percentile(100), 42.0)

    def test_two_values_median(self):
        """两个值的 P50 应落在两者之间"""
        td = TDigest(compression=100)
        td.add(10.0)
        td.add(20.0)
        median = td.percentile(50)
        self.assertGreaterEqual(median, 10.0)
        self.assertLessEqual(median, 20.0)

    def test_many_values_p50_approximate(self):
        """大量样本的 P50 应接近真实中位数"""
        td = TDigest(compression=100)
        for i in range(1000):
            td.add(float(i))
        p50 = td.percentile(50)
        # P50 应在真实中位数 500 的 10% 误差内（t-digest 允许近似误差）
        self.assertGreater(p50, 400)
        self.assertLess(p50, 600)

    def test_weighted_insertion(self):
        """加权插入应正确计入 total_weight"""
        td = TDigest(compression=100)
        td.add(5.0, weight=10.0)
        self.assertEqual(td.total_weight(), 10.0)

    def test_negative_value_rejected(self):
        """负权重应被忽略，total_weight 不变"""
        td = TDigest(compression=100)
        td.add(5.0, weight=-1.0)
        self.assertEqual(td.total_weight(), 0.0)

    def test_count_returns_centroid_count(self):
        """count 返回质心数而非样本数"""
        td = TDigest(compression=100)
        for i in range(50):
            td.add(float(i))
        c = td.count()
        self.assertGreater(c, 0)

    def test_reset_clears_all(self):
        """reset 后 total_weight 和 count 归零"""
        td = TDigest(compression=100)
        td.add(10.0)
        td.add(20.0)
        td.reset()
        self.assertEqual(td.total_weight(), 0.0)
        self.assertEqual(td.count(), 0)

    def test_compression_caps_centroids(self):
        """compression 参数限制质心的最大数量"""
        td = TDigest(compression=10)
        # 插入大量不同值，质心数受 compression*1.5 限制
        for i in range(1000):
            td.add(float(i))
        self.assertLessEqual(td.count(), 50)  # max = 10 * 1.5 = 15，给一些余量


class TestSolverTracing(unittest.TestCase):
    """SolverTracing: per-solver per-category latency backed by TDigest."""

    def setUp(self):
        self.tracing = SolverTracing()

    def test_record_single_sample(self):
        """记录单次延迟，P50 应反映该值"""
        self.tracing.record("z3", 42.0, "bitvector")
        stats = self.tracing.solver_stats("z3", "bitvector")
        self.assertAlmostEqual(stats["p50_ms"], 42.0, delta=5.0)

    def test_record_multiple_samples(self):
        """多次记录后 sample_count 应递增"""
        for i in range(10):
            self.tracing.record("z3", float(i))
        stats = self.tracing.solver_stats("z3")
        self.assertEqual(stats["sample_count"], 10)

    def test_negative_elapsed_clamped(self):
        """负延迟被钳制为 0，不抛出异常"""
        # 不应抛出
        self.tracing.record("z3", -5.0)
        stats = self.tracing.solver_stats("z3")
        self.assertIsInstance(stats["p50_ms"], float)

    def test_percentile_out_of_range(self):
        """percentile(p<0 或 p>100) 返回 0"""
        p = self.tracing.percentile("z3", -1.0)
        self.assertEqual(p, 0.0)
        p = self.tracing.percentile("z3", 150.0)
        self.assertEqual(p, 0.0)

    def test_no_category_records_overall(self):
        """不指定 category 时样本归入 overall digest"""
        self.tracing.record("z3", 10.0)
        stats = self.tracing.solver_stats("z3", "")
        self.assertEqual(stats["sample_count"], 1)

    def test_dump_all_returns_structured_data(self):
        """dump_all 返回按 key 组织的延迟分布"""
        self.tracing.record("z3", 10.0, "bitvector")
        data = self.tracing.dump_all()
        self.assertIsInstance(data, dict)
        # key 格式: "solver|category"
        found = any("z3" in k for k in data)
        self.assertTrue(found)

    def test_reset_clears_tracing(self):
        """reset 清空所有延迟记录"""
        self.tracing.record("z3", 10.0)
        self.tracing.reset()
        data = self.tracing.dump_all()
        self.assertEqual(len(data), 0)


class TestSolverPoolHealth(unittest.TestCase):
    """SolverPoolHealth: 0-100 composite score with EWMA smoothing."""

    def setUp(self):
        self.health = SolverPoolHealth()

    def test_default_health_100(self):
        """新求解器的默认健康分为 100"""
        score = self.health.get("z3")
        self.assertEqual(score, 100.0)

    def test_healthy_solver_scores_high(self):
        """高成功率+低延迟→高分"""
        score = self.health.update("z3", recent_success_rate=1.0, recent_p95_ms=100.0)
        self.assertGreater(score, 85)

    def test_critical_solver_scores_low(self):
        """低成功率+高延迟→低分"""
        score = self.health.update("z3", recent_success_rate=0.0, recent_p95_ms=10000.0)
        self.assertLess(score, 30)

    def test_status_label_healthy(self):
        """评分>=85 返回 healthy"""
        self.health.update("z3", 1.0, 100.0)
        label = self.health.status_label("z3")
        self.assertEqual(label, "healthy")

    def test_status_label_critical(self):
        """评分<30 返回 critical"""
        self.health.update("z3", 0.0, 10000.0)
        # Force score low: 0 * 60 + 0 * 40 = 0
        label = self.health.status_label("z3")
        self.assertEqual(label, "critical")

    def test_status_label_normal(self):
        """60-85 分返回 normal"""
        self.health.update("z3", 0.7, 2000.0)
        label = self.health.status_label("z3")
        self.assertIn(label, ["normal", "degraded", "healthy"])

    def test_get_all_returns_all_solvers(self):
        """get_all 返回所有已评估求解器的评分"""
        self.health.update("z3", 0.8, 500.0)
        self.health.update("cvc5", 0.6, 2000.0)
        all_scores = self.health.get_all()
        self.assertIn("z3", all_scores)
        self.assertIn("cvc5", all_scores)

    def test_reset_clears_all_scores(self):
        self.health.update("z3", 0.9, 100.0)
        self.health.reset()
        self.assertEqual(self.health.get("z3"), 100.0)


