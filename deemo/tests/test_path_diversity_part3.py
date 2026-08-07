"""
Path diversity tests — Part 3: SnapshotDiff, PathSelector, StreamingMonitor, ANN.

Tests the path diversity subsystem higher-order components:
- SnapshotDiff cluster merge/split detection
- DiversityAwarePathSelector strategy dispatch
- StreamingDiversityMonitor metric emission
- ANNIndex approximate nearest neighbor search
"""
import unittest
import time

from modules.analysis.symbolic.path_diversity import (
    PathFeature,
    DiversityMetrics,
    DiversityStrategy,
    DiversityAwarePathSelector,
    PathDiversityTracker,
    SnapshotDiff,
    SnapshotDiffResult,
    StreamingDiversityMonitor,
    ANNIndex,
)


class TestSnapshotDiff(unittest.TestCase):
    """Comparing two PathDiversityTracker snapshots."""

    def setUp(self):
        self.differ = SnapshotDiff()

    def test_empty_snapshots_no_changes(self):
        old = {"clusters": {}, "features": {}, "metrics": None}
        new = {"clusters": {}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertEqual(len(result.new_clusters), 0)
        self.assertEqual(len(result.removed_clusters), 0)
        self.assertEqual(len(result.moved_paths), 0)

    def test_new_cluster_detection(self):
        old = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c1": ["p1"], "c2": ["p2"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertIn("c2", result.new_clusters)

    def test_removed_cluster_detection(self):
        old = {"clusters": {"c1": ["p1"], "c2": ["p2"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertIn("c2", result.removed_clusters)

    def test_moved_paths_detection(self):
        old = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c2": ["p1"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertEqual(len(result.moved_paths), 1)
        self.assertEqual(result.moved_paths[0]["path_id"], "p1")
        self.assertEqual(result.moved_paths[0]["old_cluster"], "c1")
        self.assertEqual(result.moved_paths[0]["new_cluster"], "c2")

    def test_new_paths_detection(self):
        old = {"clusters": {"c1": ["p1"]}, "features": {}, "metrics": None}
        new = {"clusters": {"c1": ["p1", "p2"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertIn("p2", result.new_paths)

    def test_summary_string(self):
        r = SnapshotDiffResult(new_clusters=["c2"], removed_clusters=["c1"], diversity_delta=0.1)
        summary = r.summary()
        self.assertIn("+1 clusters", summary)
        self.assertIn("-1 clusters", summary)

    def test_export_diff_report(self):
        result = SnapshotDiffResult(new_clusters=["c1"], diversity_delta=0.05,
                                    cluster_count_delta=1, total_paths_delta=2)
        report = self.differ.export_diff_report(result)
        self.assertIn("summary", report)
        self.assertIn("diversity_delta", report)
        self.assertEqual(report["diversity_delta"], 0.05)

    def test_merge_detection(self):
        old = {"clusters": {"cA": ["p1", "p2"], "cB": ["p3", "p4"]}, "features": {}, "metrics": None}
        new = {"clusters": {"cMerged": ["p1", "p2", "p3", "p4"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertGreater(len(result.merged_clusters), 0)

    def test_split_detection(self):
        old = {"clusters": {"cBig": ["p1", "p2", "p3"]}, "features": {}, "metrics": None}
        new = {"clusters": {"cA": ["p1"], "cB": ["p2", "p3"]}, "features": {}, "metrics": None}
        result = self.differ.compare(old, new)
        self.assertGreater(len(result.split_clusters), 0)


class TestDiversityAwarePathSelector(unittest.TestCase):
    """Strategy-based next-path selection."""

    def setUp(self):
        self.selector = DiversityAwarePathSelector(strategy=DiversityStrategy.HYBRID)

    def test_add_path_registers_candidate(self):
        self.selector.add_path("p1", 0x1000, ["x > 0"], depth=1)
        stats = self.selector.get_stats()
        self.assertEqual(stats["total_paths"], 1)

    def test_select_next_returns_path(self):
        self.selector.add_path("p1", 0x1000, ["x > 0"], depth=1)
        path = self.selector.select_next()
        self.assertIsNotNone(path)

    def test_select_next_returns_none_when_empty(self):
        path = self.selector.select_next()
        self.assertIsNone(path)

    def test_mark_visited(self):
        self.selector.add_path("p1", 0x1000, ["x > 0"])
        self.selector.add_path("p2", 0x2000, ["y < 10"])
        self.selector.mark_visited("p1")
        stats = self.selector.get_stats()
        self.assertEqual(stats["visited_paths"], 1)

    def test_all_visited_returns_none(self):
        self.selector.add_path("p1", 0x1000, ["x > 0"])
        p = self.selector.select_next()
        self.assertIsNotNone(p)
        p2 = self.selector.select_next()
        self.assertIsNone(p2)

    def test_get_diversity_metrics(self):
        self.selector.add_path("p1", 0x1000, ["x > 0"], depth=1)
        metrics = self.selector.get_diversity_metrics()
        self.assertIsInstance(metrics, DiversityMetrics)
        self.assertEqual(metrics.total_paths, 1)

    def test_get_stats_keys(self):
        self.selector.add_path("p1", 0x1000, ["x > 0"])
        stats = self.selector.get_stats()
        for key in ["strategy", "pending_paths", "visited_paths", "total_paths",
                     "diversity_score", "avg_similarity", "unique_clusters", "exploration_velocity"]:
            self.assertIn(key, stats)

    def test_random_strategy(self):
        sel = DiversityAwarePathSelector(strategy=DiversityStrategy.RANDOM)
        sel.add_path("p1", 0x1000, ["x > 0"])
        sel.add_path("p2", 0x2000, ["y < 10"])
        path = sel.select_next()
        self.assertIn(path, ["p1", "p2"])

    def test_round_robin_strategy(self):
        sel = DiversityAwarePathSelector(strategy=DiversityStrategy.ROUND_ROBIN)
        sel.add_path("p1", 0x1000, ["x > 0"])
        sel.add_path("p2", 0x2000, ["y < 10"])
        first = sel.select_next()
        self.assertIsNotNone(first)

    def test_weighted_sample_strategy(self):
        sel = DiversityAwarePathSelector(strategy=DiversityStrategy.WEIGHTED_SAMPLE)
        sel.add_path("p1", 0x1000, ["x > 0"])
        sel.add_path("p2", 0x2000, ["y < 10"])
        path = sel.select_next()
        self.assertIsNotNone(path)


class TestStreamingDiversityMonitor(unittest.TestCase):
    """Real-time metrics emission via callbacks."""

    def setUp(self):
        self.tracker = PathDiversityTracker(similarity_threshold=0.3, max_paths=100)
        for i in range(5):
            self.tracker.add_path(f"p{i}", 0x1000 + i * 0x10, [f"x{i} > 0"], depth=1)

    def test_monitor_start_stop(self):
        monitor = self.tracker.start_streaming(interval_seconds=0.5)
        self.assertTrue(monitor.running)
        self.tracker.stop_streaming()
        self.assertFalse(monitor.running)

    def test_monitor_callback_invoked(self):
        results = []
        monitor = self.tracker.start_streaming(interval_seconds=0.2)

        def cb(ts, ds, ev, cc, extra):
            results.append((ds, ev, cc))

        monitor.register_callback(cb)
        time.sleep(0.6)
        self.tracker.stop_streaming()
        self.assertGreater(len(results), 0)
        for ds, ev, cc in results:
            self.assertIsInstance(ds, (int, float))
            self.assertIsInstance(ev, (int, float))
            self.assertIsInstance(cc, int)

    def test_get_latest_none_before_emit(self):
        monitor = StreamingDiversityMonitor(self.tracker, interval_seconds=10)
        self.assertIsNone(monitor.get_latest())

    def test_export_history_json(self):
        monitor = self.tracker.start_streaming(interval_seconds=0.2)
        time.sleep(0.6)
        self.tracker.stop_streaming()
        data = monitor.export_history_json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        first = data[0]
        self.assertIn("timestamp", first)
        self.assertIn("diversity_score", first)

    def test_emit_count_increments(self):
        monitor = self.tracker.start_streaming(interval_seconds=0.2)
        time.sleep(0.5)
        count = monitor.emit_count
        self.tracker.stop_streaming()
        self.assertGreater(count, 0)

    def test_double_start_idempotent(self):
        m1 = self.tracker.start_streaming(interval_seconds=0.5)
        m2 = self.tracker.start_streaming(interval_seconds=0.5)
        self.assertIs(m1, m2)
        self.tracker.stop_streaming()


class TestANNIndex(unittest.TestCase):
    """Approximate nearest neighbor search via random projection forest."""

    def test_build_empty(self):
        idx = ANNIndex(n_trees=3)
        idx.build({})
        pf = PathFeature(path_id="p1", features={"a": 1})
        result = idx.query(pf, k=3)
        self.assertEqual(len(result), 0)

    def test_build_and_query(self):
        pf1 = PathFeature(path_id="p1", features={"structural": {"depth": 1}})
        pf2 = PathFeature(path_id="p2", features={"structural": {"depth": 1}})
        pf3 = PathFeature(path_id="p3", features={"structural": {"depth": 100}})
        features = {"p1": pf1, "p2": pf2, "p3": pf3}
        idx = ANNIndex(n_trees=5, leaf_size=2)
        idx.build(features)
        result = idx.query(pf1, k=2)
        self.assertGreater(len(result), 0)

    def test_find_similar(self):
        pf1 = PathFeature(path_id="p1", features={"a": 1})
        features = {"p1": pf1}
        idx = ANNIndex(n_trees=3)
        idx.build(features)
        similar = idx.find_similar(pf1, threshold=0.5)
        self.assertIn("p1", similar)


if __name__ == "__main__":
    unittest.main()
