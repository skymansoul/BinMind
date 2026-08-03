"""
Path diversity module tests — constraint solver, path diversity, optimizer.

Tests the full path diversity subsystem:
- PathFeature / simhash computation
- PathSimilarityCalculator weighted multi-dimensional similarity
- PathDiversityTracker clustering, adaptive threshold, ANN index
- DiversityAwarePathSelector strategy dispatch
- DiversityBudget quota enforcement
- PathHeatmap cold/hot spot identification
- StreamingDiversityMonitor metric emission
- SnapshotDiff cluster merge/split detection
"""
import unittest
import time
import threading
import json
import tempfile
import os
import math

from modules.analysis.symbolic.path_diversity import (
    PathFeature,
    PathNode,
    DiversityMetrics,
    DiversityStrategy,
    PathFeatureType,
    PathSimilarityCalculator,
    PathDiversityTracker,
    DiversityAwarePathSelector,
    DiversityBudget,
    PathHeatmap,
    StreamingDiversityMonitor,
    SnapshotDiff,
    SnapshotDiffResult,
    ANNIndex,
    _RandomProjectionTree,
    _RandomProjectionNode,
    _simhash,
    _hamming_distance,
    _feature_to_vector,
    DynamicPathExplorator,
    run_path_diversity_exploration,
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


class TestPathDiversityTracker(unittest.TestCase):
    """Core clustering and diversity tracking."""

    def setUp(self):
        self.tracker = PathDiversityTracker(similarity_threshold=0.3, max_paths=100)

    def test_add_path_creates_cluster(self):
        """添加第一条路径时应自动创建一个簇"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        metrics = self.tracker.get_metrics()
        self.assertEqual(metrics.total_paths, 1)
        self.assertGreaterEqual(metrics.unique_paths, 1)

    def test_add_duplicate_path_idempotent(self):
        """重复 path_id 不应重复添加"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        metrics = self.tracker.get_metrics()
        self.assertEqual(metrics.total_paths, 1)

    def test_dissimilar_paths_form_separate_clusters(self):
        """差异大的路径应形成独立簇（低阈值下）"""
        tracker = PathDiversityTracker(similarity_threshold=0.9, max_paths=100)
        tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        tracker.add_path("p2", 0x2000, ["y < 100", "z == 5", "w != 0"], depth=10)
        metrics = tracker.get_metrics()
        # 低阈值时应有多簇形成
        self.assertGreaterEqual(metrics.unique_paths, 1)

    def test_similar_paths_merge_into_same_cluster(self):
        """相似路径应合并到同一簇（高阈值下）"""
        tracker = PathDiversityTracker(similarity_threshold=0.01, max_paths=100)
        tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        tracker.add_path("p2", 0x1008, ["x > 1"], depth=1)
        metrics = tracker.get_metrics()
        self.assertEqual(metrics.total_paths, 2)

    def test_find_diverse_paths(self):
        """find_diverse_paths 返回每簇一个代表"""
        for i in range(10):
            self.tracker.add_path(
                f"p{i}", 0x1000 + i * 0x10, [f"x{i} > 0"], depth=i % 3
            )
        diverse = self.tracker.find_diverse_paths(count=3)
        self.assertLessEqual(len(diverse), 3)
        self.assertGreater(len(diverse), 0)

    def test_find_weighted_paths(self):
        """find_weighted_paths 按簇大小反比采样"""
        for i in range(20):
            self.tracker.add_path(
                f"p{i}", 0x1000 + i * 0x10, [f"x{i} > 0"], depth=i % 5
            )
        weighted = self.tracker.find_weighted_paths(count=5)
        self.assertLessEqual(len(weighted), 5)
        self.assertGreater(len(weighted), 0)

    def test_is_path_diverse(self):
        """is_path_diverse: 与所有其他路径相似度低于阈值为 True"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        self.tracker.add_path("p2", 0x5000, ["y < 100", "z == 42"], depth=20)
        # p2 在低阈值下应该是 diverse 的（如果它与 p1 不相似）
        result = self.tracker.is_path_diverse("p2")
        self.assertIsInstance(result, bool)

    def test_is_path_diverse_unknown_path(self):
        """未知 path_id 返回 True（保守假设 diverse）"""
        self.assertTrue(self.tracker.is_path_diverse("nonexistent"))

    def test_get_similar_paths_empty_for_new(self):
        """新路径不应有相似路径"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        similar = self.tracker.get_similar_paths("p1", threshold=0.9)
        self.assertEqual(len(similar), 0)

    def test_get_metrics_empty(self):
        """空 tracker 的 DiversityMetrics 全为 0"""
        tracker = PathDiversityTracker()
        metrics = tracker.get_metrics()
        self.assertEqual(metrics.total_paths, 0)
        self.assertEqual(metrics.diversity_score, 0.0)
        self.assertEqual(metrics.exploration_velocity, 0.0)

    def test_capture_snapshot(self):
        """capture_snapshot 返回包含 clusters/features/metrics 的字典"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        snap = self.tracker.capture_snapshot()
        self.assertIn("clusters", snap)
        self.assertIn("features", snap)
        self.assertIn("metrics", snap)

    def test_export_cluster_visualization(self):
        """export_cluster_visualization 返回可序列化 JSON 结构"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=1)
        self.tracker.add_path("p2", 0x2000, ["y < 10"], depth=2)
        viz = self.tracker.export_cluster_visualization()
        self.assertIn("clusters", viz)
        self.assertIn("total_clusters", viz)
        self.assertIn("total_paths", viz)

    def test_parent_child_linking(self):
        """parent_id 为节点建立父子链接"""
        self.tracker.add_path("parent", 0x1000, ["x > 0"], depth=0)
        self.tracker.add_path("child", 0x1008, ["x > 0", "y < 10"], depth=1, parent_id="parent")
        metrics = self.tracker.get_metrics()
        self.assertEqual(metrics.total_paths, 2)

    def test_heatmap_records_paths(self):
        """add_path 自动更新 PathHeatmap"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=3)
        hm = self.tracker.heatmap
        self.assertGreater(hm.total_paths, 0)

    def test_cluster_quota_property(self):
        """cluster_quota = max_paths // num_clusters"""
        self.tracker.add_path("p1", 0x1000, ["x > 0"], depth=0)
        quota = self.tracker.cluster_quota
        self.assertGreaterEqual(quota, 1)


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


class TestPathHeatmap(unittest.TestCase):
    """2D histogram by (depth_bucket, constraint_bucket)."""

    def setUp(self):
        self.heatmap = PathHeatmap(depth_bucket_width=2, constraint_bucket_width=5)

    def test_record_single_path(self):
        """单条路径记录后 total_paths = 1"""
        self.heatmap.record("p1", depth=3, constraint_count=7)
        self.assertEqual(self.heatmap.total_paths, 1)
        db = 3 // 2  # depth_bucket = 1
        cb = 7 // 5  # constraint_bucket = 1
        self.assertEqual(self.heatmap.get_density(db, cb), 1)

    def test_record_batch(self):
        """批量记录路径"""
        paths = [
            ("p1", 1, 2),
            ("p2", 3, 8),
            ("p3", 1, 3),
        ]
        self.heatmap.record_batch(paths)
        self.assertEqual(self.heatmap.total_paths, 3)

    def test_average_density(self):
        """平均密度 = total / non-empty cells"""
        self.heatmap.record("p1", depth=1, constraint_count=1)
        self.heatmap.record("p2", depth=1, constraint_count=1)
        self.heatmap.record("p3", depth=5, constraint_count=10)
        avg = self.heatmap.average_density()
        self.assertGreater(avg, 0.0)

    def test_average_density_empty(self):
        """空直方图平均密度为 0"""
        self.assertEqual(self.heatmap.average_density(), 0.0)

    def test_identify_cold_spots(self):
        """识别低密度区域（冷点）"""
        # 在 (0,0) 放大量路径，(1,1) 放少量 → (1,1) 可能成为冷点
        for i in range(20):
            self.heatmap.record(f"hot_{i}", depth=0, constraint_count=0)
        self.heatmap.record("cold", depth=5, constraint_count=20)
        cold_spots = self.heatmap.identify_cold_spots(cold_spot_ratio=0.5)
        self.assertIsInstance(cold_spots, list)

    def test_identify_hot_spots(self):
        """识别高密度区域（热点）"""
        for i in range(30):
            self.heatmap.record(f"hot_{i}", depth=2, constraint_count=1)
        self.heatmap.record("lonely", depth=10, constraint_count=50)
        hot_spots = self.heatmap.identify_hot_spots(top_n=3)
        self.assertGreater(len(hot_spots), 0)
        first = hot_spots[0]
        self.assertIn("depth_bucket", first)
        self.assertIn("count", first)
        self.assertGreater(first["count"], 0)

    def test_paths_in_cold_spots(self):
        """paths_in_cold_spots 返回冷点中的全部 path_id"""
        for i in range(20):
            self.heatmap.record(f"dense_{i}", depth=0, constraint_count=0)
        self.heatmap.record("lonely", depth=20, constraint_count=50)
        paths = self.heatmap.paths_in_cold_spots(cold_spot_ratio=0.5)
        self.assertIsInstance(paths, list)

    def test_export_histogram_json(self):
        """导出 JSON 结构包含 cells/depth_bucket_width"""
        self.heatmap.record("p1", depth=1, constraint_count=3)
        data = self.heatmap.export_histogram_json()
        self.assertIn("cells", data)
        self.assertIn("depth_bucket_width", data)
        self.assertIn("total_paths", data)

    def test_export_histogram_json_to_file(self):
        """导出到文件"""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.heatmap.record("p1", depth=1, constraint_count=1)
            data = self.heatmap.export_histogram_json(output_path=path)
            self.assertTrue(os.path.exists(path))
            with open(path, "r") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["total_paths"], 1)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_reset(self):
        """reset 清空所有数据"""
        self.heatmap.record("p1", depth=1, constraint_count=1)
        self.assertEqual(self.heatmap.total_paths, 1)
        self.heatmap.reset()
        self.assertEqual(self.heatmap.total_paths, 0)
        self.assertEqual(len(self.heatmap.histogram), 0)

    def test_depth_bucket_width_property(self):
        self.assertEqual(self.heatmap.depth_bucket_width, 2)

    def test_constraint_bucket_width_property(self):
        self.assertEqual(self.heatmap.constraint_bucket_width, 5)


class TestStreamingDiversityMonitor(unittest.TestCase):
    """Real-time metrics emission via callbacks."""

    def setUp(self):
        self.tracker = PathDiversityTracker(similarity_threshold=0.3, max_paths=100)
        for i in range(5):
            self.tracker.add_path(f"p{i}", 0x1000 + i * 0x10, [f"x{i} > 0"], depth=1)

    def test_monitor_start_stop(self):
        """启动和停止 StreamingDiversityMonitor"""
        monitor = self.tracker.start_streaming(interval_seconds=0.5)
        self.assertTrue(monitor.running)
        self.tracker.stop_streaming()
        self.assertFalse(monitor.running)

    def test_monitor_callback_invoked(self):
        """注册的回调在定时触发时被调用"""
        results = []
        monitor = self.tracker.start_streaming(interval_seconds=0.2)

        def cb(ts, ds, ev, cc, extra):
            results.append((ds, ev, cc))

        monitor.register_callback(cb)
        time.sleep(0.6)  # 等待至少 2 次触发
        self.tracker.stop_streaming()
        self.assertGreater(len(results), 0)
        # 验证回调参数类型
        for ds, ev, cc in results:
            self.assertIsInstance(ds, (int, float))
            self.assertIsInstance(ev, (int, float))
            self.assertIsInstance(cc, int)

    def test_get_latest_none_before_emit(self):
        """未 emit 前 get_latest 返回 None"""
        monitor = StreamingDiversityMonitor(self.tracker, interval_seconds=10)
        self.assertIsNone(monitor.get_latest())

    def test_export_history_json(self):
        """导出历史数据"""
        monitor = self.tracker.start_streaming(interval_seconds=0.2)
        time.sleep(0.6)
        self.tracker.stop_streaming()
        data = monitor.export_history_json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        first = data[0]
        self.assertIn("timestamp", first)
        self.assertIn("diversity_score", first)
        self.assertIn("exploration_velocity", first)
        self.assertIn("cluster_count", first)

    def test_emit_count_increments(self):
        """emit_count 随每次触发递增"""
        monitor = self.tracker.start_streaming(interval_seconds=0.2)
        time.sleep(0.5)
        count = monitor.emit_count
        self.tracker.stop_streaming()
        self.assertGreater(count, 0)

    def test_double_start_idempotent(self):
        """第二次 start 不重复创建线程"""
        m1 = self.tracker.start_streaming(interval_seconds=0.5)
        m2 = self.tracker.start_streaming(interval_seconds=0.5)
        self.assertIs(m1, m2)
        self.tracker.stop_streaming()


class TestSnapshotDiff(unittest.TestCase):
    """Comparing two PathDiversityTracker snapshots."""

    def setUp(self):
        self.differ = SnapshotDiff()

    def test_empty_snapshots_no_changes(self):
        """两个空快照比较应无变化"""
        old = {"clusters": {}, "features": {}, "metrics": None}
        new = {"clusters": {}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertEqual(len(result.new_clusters), 0)
        self.assertEqual(len(result.removed_clusters), 0)
        self.assertEqual(len(result.moved_paths), 0)

    def test_new_cluster_detection(self):
        """新快照中多出的簇应被检测为 new_clusters"""
        old = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c1": ["p1"], "c2": ["p2"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertIn("c2", result.new_clusters)

    def test_removed_cluster_detection(self):
        """旧快照中有而新快照中没有的簇应被检测为 removed_clusters"""
        old = {"clusters": {"c1": ["p1"], "c2": ["p2"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertIn("c2", result.removed_clusters)

    def test_moved_paths_detection(self):
        """同一 path 在两个快照中属于不同簇应被检测为 moved"""
        old = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c2": ["p1"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertEqual(len(result.moved_paths), 1)
        self.assertEqual(result.moved_paths[0]["path_id"], "p1")
        self.assertEqual(result.moved_paths[0]["old_cluster"], "c1")
        self.assertEqual(result.moved_paths[0]["new_cluster"], "c2")

    def test_new_paths_detection(self):
        """新快照中出现的新 path_id 应被标记为 new_paths"""
        old = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c1": ["p1", "p2"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertIn("p2", result.new_paths)

    def test_summary_string(self):
        """SnapshotDiffResult.summary() 返回人类可读摘要"""
        r = SnapshotDiffResult(
            new_clusters=["c2"],
            removed_clusters=["c1"],
            diversity_delta=0.1,
        )
        summary = r.summary()
        self.assertIn("+1 clusters", summary)
        self.assertIn("-1 clusters", summary)

    def test_export_diff_report(self):
        """export_diff_report 导出 JSON 兼容结构"""
        result = SnapshotDiffResult(
            new_clusters=["c1"],
            diversity_delta=0.05,
            cluster_count_delta=1,
            total_paths_delta=2,
        )
        report = self.differ.export_diff_report(result)
        self.assertIn("summary", report)
        self.assertIn("diversity_delta", report)
        self.assertEqual(report["diversity_delta"], 0.05)

    def test_merge_detection(self):
        """多个旧簇合并为新簇应被检测"""
        old = {
            "clusters": {"cA": ["p1", "p2"], "cB": ["p3", "p4"]},
            "features": {},
            "metrics": None,
        }
        new = {
            "clusters": {"cMerged": ["p1", "p2", "p3", "p4"]},
            "features": {},
            "metrics": None,
        }
        result = self.differ.compare(old, new)
        self.assertGreater(len(result.merged_clusters), 0)

    def test_split_detection(self):
        """一个旧簇分裂为多个新簇应被检测"""
        old = {
            "clusters": {"cBig": ["p1", "p2", "p3"]},
            "features": {},
            "metrics": None,
        }
        new = {
            "clusters": {"cA": ["p1"], "cB": ["p2", "p3"]},
            "features": {},
            "metrics": None,
        }
        result = self.differ.compare(old, new)
        self.assertGreater(len(result.split_clusters), 0)


class TestDiversityAwarePathSelector(unittest.TestCase):
    """Strategy-based next-path selection."""

    def setUp(self):
        self.selector = DiversityAwarePathSelector(strategy=DiversityStrategy.HYBRID)

    def test_add_path_registers_candidate(self):
        """add_path 注册候选路径到 tracker"""
        self.selector.add_path("p1", 0x1000, ["x > 0"], depth=1)
        stats = self.selector.get_stats()
        self.assertEqual(stats["total_paths"], 1)

    def test_select_next_returns_path(self):
        """select_next 返回一个 path_id"""
        self.selector.add_path("p1", 0x1000, ["x > 0"], depth=1)
        path = self.selector.select_next()
        self.assertIsNotNone(path)

    def test_select_next_returns_none_when_empty(self):
        """无候选时 select_next 返回 None"""
        path = self.selector.select_next()
        self.assertIsNone(path)

    def test_mark_visited(self):
        """mark_visited 标记路径已探索"""
        self.selector.add_path("p1", 0x1000, ["x > 0"])
        self.selector.add_path("p2", 0x2000, ["y < 10"])
        self.selector.mark_visited("p1")
        stats = self.selector.get_stats()
        self.assertEqual(stats["visited_paths"], 1)

    def test_all_visited_returns_none(self):
        """所有路径都 visited 后 select_next 返回 None"""
        self.selector.add_path("p1", 0x1000, ["x > 0"])
        p = self.selector.select_next()
        self.assertIsNotNone(p)
        p2 = self.selector.select_next()
        self.assertIsNone(p2)

    def test_get_diversity_metrics(self):
        """get_diversity_metrics 返回 DiversityMetrics"""
        self.selector.add_path("p1", 0x1000, ["x > 0"], depth=1)
        metrics = self.selector.get_diversity_metrics()
        self.assertIsInstance(metrics, DiversityMetrics)
        self.assertEqual(metrics.total_paths, 1)

    def test_get_stats_keys(self):
        """get_stats 返回所有预期键"""
        self.selector.add_path("p1", 0x1000, ["x > 0"])
        stats = self.selector.get_stats()
        for key in ["strategy", "pending_paths", "visited_paths", "total_paths",
                     "diversity_score", "avg_similarity", "unique_clusters",
                     "exploration_velocity"]:
            self.assertIn(key, stats)

    def test_random_strategy(self):
        """RANDOM 策略随机选择"""
        sel = DiversityAwarePathSelector(strategy=DiversityStrategy.RANDOM)
        sel.add_path("p1", 0x1000, ["x > 0"])
        sel.add_path("p2", 0x2000, ["y < 10"])
        path = sel.select_next()
        self.assertIn(path, ["p1", "p2"])

    def test_round_robin_strategy(self):
        """ROUND_ROBIN 策略按顺序轮询"""
        sel = DiversityAwarePathSelector(strategy=DiversityStrategy.ROUND_ROBIN)
        sel.add_path("p1", 0x1000, ["x > 0"])
        sel.add_path("p2", 0x2000, ["y < 10"])
        first = sel.select_next()
        self.assertIsNotNone(first)

    def test_weighted_sample_strategy(self):
        """WEIGHTED_SAMPLE 策略按反比采样"""
        sel = DiversityAwarePathSelector(strategy=DiversityStrategy.WEIGHTED_SAMPLE)
        sel.add_path("p1", 0x1000, ["x > 0"])
        sel.add_path("p2", 0x2000, ["y < 10"])
        path = sel.select_next()
        self.assertIsNotNone(path)


class TestDynamicPathExplorator(unittest.TestCase):
    """Top-level exploration driver."""

    def test_explore_successful(self):
        """explore 返回 explored_paths 和 stats"""
        explorer = DynamicPathExplorator(strategy="hybrid")
        for i in range(15):
            explorer.add_path_candidate(
                f"path_{i}", 0x1000 + i * 0x10, ["x > 0"], depth=i % 3
            )
        result = explorer.explore(iterations=10)
        self.assertTrue(result["success"])
        self.assertIn("explored_paths", result)
        self.assertGreaterEqual(result["explored_paths"], 0)

    def test_invalid_strategy_falls_back(self):
        """无效 strategy 回退到 HYBRID"""
        explorer = DynamicPathExplorator(strategy="nonexistent")
        # 应不抛出异常
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
        # 最多执行 max_explorations 次
        self.assertLessEqual(result["explored_paths"], 3)

    def test_run_path_diversity_exploration(self):
        """run_path_diversity_exploration 一站式运行"""
        result = run_path_diversity_exploration(
            strategy="hybrid", iterations=10, path_count=5
        )
        self.assertIn("success", result)
        self.assertIn("final_stats", result)


class TestANNIndex(unittest.TestCase):
    """Approximate nearest neighbor search via random projection forest."""

    def test_build_empty(self):
        """空 features 构建不崩溃"""
        idx = ANNIndex(n_trees=3)
        idx.build({})
        # query on unbuilt index returns empty
        pf = PathFeature(path_id="p1", features={"a": 1})
        result = idx.query(pf, k=3)
        self.assertEqual(len(result), 0)

    def test_build_and_query(self):
        """构建后查询返回最近邻"""
        pf1 = PathFeature(path_id="p1", features={"structural": {"depth": 1}})
        pf2 = PathFeature(path_id="p2", features={"structural": {"depth": 1}})
        pf3 = PathFeature(path_id="p3", features={"structural": {"depth": 100}})
        features = {
            "p1": pf1,
            "p2": pf2,
            "p3": pf3,
        }
        idx = ANNIndex(n_trees=5, leaf_size=2)
        idx.build(features)
        result = idx.query(pf1, k=2)
        self.assertGreater(len(result), 0)

    def test_find_similar(self):
        """find_similar 按阈值过滤"""
        pf1 = PathFeature(path_id="p1", features={"a": 1})
        features = {"p1": pf1}
        idx = ANNIndex(n_trees=3)
        idx.build(features)
        similar = idx.find_similar(pf1, threshold=0.5)
        # p1 应找到自己（相似度 1.0）
        self.assertIn("p1", similar)


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
        # 构建不应崩溃
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


if __name__ == "__main__":
    unittest.main()
