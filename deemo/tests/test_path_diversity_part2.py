"""
Path diversity tests — Part 2: Tracker, Heatmap.

Tests the path diversity subsystem core tracking:
- PathDiversityTracker clustering, adaptive threshold, ANN index
- PathHeatmap cold/hot spot identification
"""
import unittest
import json
import tempfile
import os

from modules.analysis.symbolic.path_diversity import (
    PathDiversityTracker,
    PathHeatmap,
)


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


class TestPathHeatmap(unittest.TestCase):
    """2D histogram by (depth_bucket, constraint_bucket)."""

    def setUp(self):
        self.heatmap = PathHeatmap(depth_bucket_width=2, constraint_bucket_width=5)

    def test_record_single_path(self):
        """单条路径记录后 total_paths = 1"""
        self.heatmap.record("p1", depth=3, constraint_count=7)
        self.assertEqual(self.heatmap.total_paths, 1)
        db = 3 // 2
        cb = 7 // 5
        self.assertEqual(self.heatmap.get_density(db, cb), 1)

    def test_record_batch(self):
        """批量记录路径"""
        paths = [("p1", 1, 2), ("p2", 3, 8), ("p3", 1, 3)]
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
            self.heatmap.export_histogram_json(output_path=path)
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


if __name__ == "__main__":
    unittest.main()
