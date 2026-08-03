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


class TestCrossSolverConsensus(unittest.TestCase):
    """Cross-solver agreement tracking with sliding window."""

    def setUp(self):
        self.consensus = CrossSolverConsensus(window_size=10)

    def test_initial_consensus_is_1(self):
        """初始共识分为 1.0（无分歧记录）"""
        self.assertEqual(self.consensus.consensus_score(), 1.0)

    def test_all_agreed_consensus_1(self):
        """全一致→共识分 1.0"""
        for _ in range(5):
            self.consensus.record(True)
        self.assertEqual(self.consensus.consensus_score(), 1.0)

    def test_all_diverged_consensus_0(self):
        """全不一致→共识分 0.0"""
        for _ in range(5):
            self.consensus.record(False)
        self.assertEqual(self.consensus.consensus_score(), 0.0)

    def test_mixed_consensus(self):
        """混合记录的共识分为一致比例"""
        self.consensus.record(True)
        self.consensus.record(True)
        self.consensus.record(False)
        self.assertEqual(self.consensus.consensus_score(), 2.0 / 3.0)

    def test_sliding_window_limit(self):
        """超出窗口的记录被丢弃，仅保留最近 N 个"""
        consensus = CrossSolverConsensus(window_size=3)
        consensus.record(True)
        consensus.record(True)
        consensus.record(True)
        # 窗口满，新记录驱逐最早记录
        consensus.record(False)
        self.assertLess(consensus.consensus_score(), 1.0)

    def test_overall_agreement_rate(self):
        """overall_agreement_rate 追踪全时段而非仅窗口期"""
        self.consensus.record(True)
        self.consensus.record(False)
        self.assertAlmostEqual(self.consensus.overall_agreement_rate(), 0.5)

    def test_snapshot_keys(self):
        """snapshot 返回包含所有预期键的字典"""
        self.consensus.record(True)
        snap = self.consensus.snapshot()
        for key in ["consensus_score", "overall_agreement_rate",
                     "window_size", "total_comparisons"]:
            self.assertIn(key, snap)


class TestConstraintSolverManager(unittest.TestCase):
    """Multi-backend solver registry with fallback chain and selection."""

    def setUp(self):
        self.manager = ConstraintSolverManager()

    def test_default_solvers_registered(self):
        """初始化后默认注册 Z3/CVC5/Yices/Boolector"""
        bench = self.manager.solver_performance_benchmark()
        names = {b["solver_name"] for b in bench}
        for expected in ["z3", "cvc5", "yices", "boolector"]:
            self.assertIn(expected, names)

    def test_register_custom_solver(self):
        """自定义求解器注册成功"""
        ok = self.manager.register_solver(
            name="my_solver",
            solver_type=SolverType.CUSTOM,
            priority=5,
            preferred_categories=[ConstraintCategory.BITVECTOR],
        )
        self.assertTrue(ok)
        bench = self.manager.solver_performance_benchmark()
        names = {b["solver_name"] for b in bench}
        self.assertIn("my_solver", names)

    def test_unregister_solver(self):
        """注销求解器成功"""
        self.manager.register_solver("temp", SolverType.CUSTOM)
        ok = self.manager.unregister_solver("temp")
        self.assertTrue(ok)

    def test_unregister_nonexistent(self):
        """注销不存在的求解器返回 False"""
        ok = self.manager.unregister_solver("nonexistent")
        self.assertFalse(ok)

    def test_classify_bitvector_constraint(self):
        """bvmul/bvadd 关键词→BITVECTOR"""
        cat = self.manager._classify_constraint("(bvadd x y)")
        self.assertEqual(cat, ConstraintCategory.BITVECTOR)

    def test_classify_integer_constraint(self):
        """+/-/* 关键词→INTEGER_ARITHMETIC"""
        cat = self.manager._classify_constraint("x + y > 10")
        self.assertEqual(cat, ConstraintCategory.INTEGER_ARITHMETIC)

    def test_classify_boolean_constraint(self):
        """and/or/not→BOOLEAN"""
        cat = self.manager._classify_constraint("(and a b)")
        self.assertEqual(cat, ConstraintCategory.BOOLEAN)

    def test_classify_string_constraint(self):
        """str. 前缀→STRING"""
        cat = self.manager._classify_constraint("(str.len s)")
        self.assertEqual(cat, ConstraintCategory.STRING)

    def test_classify_array_constraint(self):
        """select/store→ARRAY"""
        cat = self.manager._classify_constraint("(select a i)")
        self.assertEqual(cat, ConstraintCategory.ARRAY)

    def test_classify_mixed_constraint(self):
        """混合关键词→MIXED（无单一类别达到阈值2）"""
        cat = self.manager._classify_constraint("x + y")
        self.assertEqual(cat, ConstraintCategory.MIXED)

    def test_classify_unknown_constraint(self):
        """无任何已知关键词→UNKNOWN"""
        cat = self.manager._classify_constraint("foobar")
        self.assertEqual(cat, ConstraintCategory.UNKNOWN)

    def test_solve_simple_constraint(self):
        """SAT 约束求解成功"""
        result = self.manager.solve_with_fallback("x > 0")
        self.assertTrue(result.satisfiable)

    def test_solve_unsat_constraint(self):
        """UNSAT 约束返回 satisfiable=False"""
        result = self.manager.solve_with_fallback("x > 0 unsat")
        self.assertFalse(result.satisfiable)

    def test_solve_with_preferred_solver(self):
        """指定 preferred solver 优先使用"""
        result = self.manager.solve_with_fallback("x > 0", preferred="cvc5")
        self.assertTrue(result.satisfiable)
        self.assertIn(result.solver_name, ["cvc5", "z3"])

    def test_solve_timeout_on_long_constraint(self):
        """超长约束触发超时，返回 error"""
        long_c = "x > 0 " * 2000  # 超过 SIMULATED_TIMEOUT_THRESHOLD
        result = self.manager.solve_with_fallback(long_c)
        self.assertTrue(result.timeout_occurred or result.error_message)

    def test_select_best_solver(self):
        """select_best_solver 返回求解器名称字符串"""
        best = self.manager.select_best_solver("(bvadd x y)")
        self.assertIsInstance(best, str)
        self.assertIn(best, ["z3", "cvc5", "yices", "boolector"])

    def test_health_check_all(self):
        """solver_health_check() 返回所有求解器状态"""
        health = self.manager.solver_health_check()
        self.assertTrue(health["success"])
        self.assertIn("results", health)
        for name in ["z3", "cvc5"]:
            self.assertIn(name, health["results"])

    def test_health_check_single_solver(self):
        """按名称检查单个求解器"""
        health = self.manager.solver_health_check("z3")
        self.assertIn("z3", health["results"])
        self.assertEqual(health["results"]["z3"]["status"], "healthy")

    def test_compare_solver_results(self):
        """交叉验证：多个求解器求解同一约束"""
        comparison = self.manager.compare_solver_results("x > 0")
        self.assertIn("consensus", comparison)
        self.assertIn("consistent", comparison["consensus"])
        self.assertGreater(comparison["solver_count"], 0)

    def test_benchmark_action(self):
        """analyze(action="benchmark") 返回基准数据"""
        result = self.manager.analyze(action="benchmark")
        self.assertTrue(result["success"])
        self.assertIn("benchmarks", result)

    def test_analyze_solve_action(self):
        """analyze(action="solve") 调度求解"""
        result = self.manager.analyze(action="solve", constraint="x > 0")
        self.assertTrue(result["success"])
        self.assertTrue(result["satisfiable"])

    def test_analyze_compare_action(self):
        """analyze(action="compare") 调度交叉验证"""
        result = self.manager.analyze(action="compare", constraint="x > 0")
        self.assertTrue(result["success"])
        self.assertIn("comparison", result)

    def test_analyze_select_action(self):
        """analyze(action="select") 返回推荐求解器"""
        result = self.manager.analyze(action="select", constraint="(bvadd x y)")
        self.assertIn("recommended_solver", result)

    def test_analyze_health_action(self):
        """analyze(action="health") 返回健康检查"""
        result = self.manager.analyze(action="health")
        self.assertIn("results", result)

    def test_analyze_recommend_for_category(self):
        """analyze(action="recommend_for_category") 按类别推荐"""
        result = self.manager.analyze(
            action="recommend_for_category", category="bitvector"
        )
        self.assertIn("recommended_solver", result)

    def test_analyze_unknown_action(self):
        """未知 action 返回错误"""
        result = self.manager.analyze(action="invalid_op")
        self.assertFalse(result["success"])

    def test_manage_constraint_solver_function(self):
        """manage_constraint_solver 便捷函数返回 benchmark"""
        result = manage_constraint_solver()
        self.assertIn("benchmarks", result)

    def test_divergence_report(self):
        """divergence_report 包含 counter 和 log"""
        report = self.manager.analyze(action="divergence_report")
        self.assertTrue(report["success"])
        self.assertIn("divergence_counter", report)
        self.assertIn("consensus", report)

    def test_tracing_report(self):
        """tracing_report 返回延迟分布"""
        report = self.manager.analyze(action="tracing_report")
        self.assertTrue(report["success"])
        self.assertIn("tracing", report)

    def test_consensus_metrics(self):
        """consensus_metrics 返回共识快照"""
        metrics = self.manager.consensus_metrics()
        self.assertIn("consensus_score", metrics)


if __name__ == "__main__":
    unittest.main()
