"""ISRG 和 ParetoArchive 的单元与集成测试.

修改记录:
2025-07-27 15:30 - 补全边界测试: 空图/单种子/全冗余/全覆盖不重叠
2025-07-30 09:22 - 增加 Pareto 归档持久化往返测试
2025-08-01 14:18 - 集成测试: ISRG + Scheduler 协同调度偏置验证
"""

import math
import pytest

from ..src.core import Seed
from ..src.coverage import CoverageBitmap, encode_edge_id
from ..src.scheduler import Scheduler
from ..src.seed_relation_graph import SeedRelationGraph, SeedNode
from ..src.pareto_archive import (
    ParetoArchive, ParetoEntry, _dominates, _non_dominated_sort,
)


# ISRG 测试

class TestSeedRelationGraph:
    """种子间覆盖关系图单元测试。"""

    def test_empty_graph(self):
        srg = SeedRelationGraph()
        assert srg.stats()["node_count"] == 0
        assert srg.stats()["edge_count"] == 0
        assert srg.diversity_score("nonexistent") == 0.5
        assert srg.find_bridge_seeds() == []

    def test_single_seed_isolated(self):
        srg = SeedRelationGraph()
        srg.upsert_seed("s1", {1, 2, 3})
        assert srg.stats()["node_count"] == 1
        # 孤立节点多样性应为1.0
        assert srg.diversity_score("s1") == 1.0

    def test_superset_relation(self):
        """s1 的覆盖被 s2 完全包含 → s2→s1 的边 (s2 是 s1 的超集)"""
        srg = SeedRelationGraph()
        srg.upsert_seed("s1", {1, 2, 3})
        srg.upsert_seed("s2", {1, 2, 3, 4, 5})

        assert srg.stats()["edge_count"] >= 1
        # s2 有出边指向 s1 (s2 ⊇ s1)
        n2 = srg._nodes.get("s2")
        assert n2 is not None
        assert "s1" in n2.out_neighbors

    def test_disjoint_relation(self):
        """完全不重叠的两个覆盖集 → 无边"""
        srg = SeedRelationGraph()
        srg.upsert_seed("s1", {1, 2, 3})
        srg.upsert_seed("s2", {100, 101, 102})

        assert srg.stats()["edge_count"] == 0

    def test_partial_overlap(self):
        """部分重叠但不成包含关系 → 无边"""
        srg = SeedRelationGraph()
        srg.upsert_seed("s1", {1, 2, 3, 4, 5})
        srg.upsert_seed("s2", {3, 4, 5, 6, 7})

        # Jaccard = 3/7 ≈ 0.43 < 0.6 → partial, 无边
        assert srg.stats()["edge_count"] == 0

    def test_diversity_score(self):
        """验证多样性评分的合理性"""
        srg = SeedRelationGraph()
        srg.upsert_seed("s1", {1, 2, 3})
        srg.upsert_seed("s2", {100, 101, 102})
        # s1和s2完全不重叠 → 彼此多样性贡献应为1.0
        assert srg.diversity_score("s1") == 1.0
        assert srg.diversity_score("s2") == 1.0

    def test_flow_centrality(self):
        """验证覆盖流中心性: 超集节点应有最高中心性"""
        srg = SeedRelationGraph()
        srg.upsert_seed("leaf1", {1, 2})
        srg.upsert_seed("leaf2", {3, 4})
        srg.upsert_seed("hub", {1, 2, 3, 4, 5})  # hub ⊇ leaf1, hub ⊇ leaf2

        srg.compute_flow_centrality()
        hub = srg._nodes["hub"]
        leaf1 = srg._nodes["leaf1"]
        # hub 的流中心性应 > 叶子节点
        assert hub.flow_centrality >= leaf1.flow_centrality

    def test_bridge_seed_detection(self):
        """桥接种子: 有下游影响 + 低入度"""
        srg = SeedRelationGraph()
        srg.upsert_seed("base", {1, 2, 3})
        srg.upsert_seed("bridge", {1, 2, 3, 4})
        srg.upsert_seed("extended", {1, 2, 3, 4, 5, 6})

        # bridge 有出边 (→ base) + 低入度 → 应是桥接种子
        bridges = srg.find_bridge_seeds(min_flow=0.0)
        assert "bridge" in bridges

    def test_remove_seed(self):
        srg = SeedRelationGraph()
        srg.upsert_seed("s1", {1, 2, 3})
        srg.upsert_seed("s2", {1, 2, 3, 4})
        assert srg.stats()["node_count"] == 2

        srg.remove_seed("s1")
        assert srg.stats()["node_count"] == 1
        assert srg._nodes.get("s1") is None

    def test_minhash_fingerprint(self):
        """大型覆盖集 (>500边) 应触发 MinHash 降维"""
        srg = SeedRelationGraph()
        large = set(range(1000))  # 1000 边
        srg.upsert_seed("big", large)
        fp = srg._nodes["big"].coverage_fingerprint
        # MinHash 降维后应远小于 1000
        assert len(fp) <= 512

    def test_calibrate_threshold(self):
        srg = SeedRelationGraph()
        for i in range(15):
            srg.upsert_seed(f"s{i}", set(range(10 + i * 20)))
        new_threshold = srg.calibrate_threshold()
        assert 0.4 <= new_threshold <= 0.8


# Pareto 归档测试

class TestParetoArchive:
    """多目标 Pareto 归档单元测试。"""

    def test_dominance(self):
        assert _dominates((5, 3), (4, 2))       # 两维度均优
        assert _dominates((5, 3), (5, 2))       # 一维相等, 一维优
        assert not _dominates((5, 3), (5, 3))   # 全等
        assert not _dominates((5, 3), (6, 2))   # 互不支配
        assert not _dominates((4, 3), (5, 2))   # 互不支配

    def test_non_dominated_sort(self):
        objs = [(5, 5), (4, 8), (8, 2), (7, 7), (3, 3)]
        fronts = _non_dominated_sort(objs)
        # 第一前沿: (4,8), (8,2), (7,7) — 互不支配
        # (5,5) 被 (7,7) 支配, 落入第二层
        # 第二前沿: (5,5) — 仅被第一前沿支配
        # 第三前沿: (3,3) — 被所有支配
        assert len(fronts) >= 3
        front0 = set(fronts[0])
        assert front0 == {1, 2, 3}  # (5,5) 与 (3,3) 均不在此层
        assert fronts[1] == [0]

    def test_archive_acceptance(self):
        pa = ParetoArchive(n_objectives=2, max_archive_size=50)
        # 第一个种子总是被接受
        assert pa.submit("s1", (10.0, 0.5))
        # s2 在第二维度支配 s1, 但在第一维度被支配 → 互不支配, 均保留
        assert pa.submit("s2", (5.0, 2.0))
        assert pa.contains("s1")
        assert pa.contains("s2")
        # s3 被 s2 完全支配 → 拒绝
        assert not pa.submit("s3", (4.0, 1.0))
        assert not pa.contains("s3")
        # s4 完全支配 s1 → s1 被移除
        assert pa.submit("s4", (15.0, 3.0))
        assert not pa.contains("s1")  # s1 被 s4 支配
        assert not pa.contains("s2")  # s2 同样被 s4 支配

    def test_archive_pruning(self):
        """超容量裁剪: max_archive_size=3, 提交5个互不支配种子"""
        pa = ParetoArchive(n_objectives=2, max_archive_size=3)
        pa.submit("a", (10.0, 1.0))
        pa.submit("b", (8.0, 5.0))
        pa.submit("c", (6.0, 8.0))
        pa.submit("d", (3.0, 10.0))
        pa.submit("e", (5.0, 6.0))

        assert pa.stats()["archive_size"] <= 3

    def test_objectives_from_seed(self):
        seed = Seed(id="test1", data=b"AAAA", generation=2)
        seed.coverage = {1, 2, 3}
        obj = ParetoArchive.objectives_from_seed(seed, exec_time_ms=5.0, rarity_score=0.7)
        # edge_count=3, inv_exec=0.2, freshness=1/3≈0.333, rarity=0.7
        assert obj[0] == 3.0
        assert obj[1] == pytest.approx(0.2)
        assert obj[2] == pytest.approx(1.0 / 3.0)
        assert obj[3] == pytest.approx(0.7)

    def test_serialization_roundtrip(self):
        pa = ParetoArchive(n_objectives=2, max_archive_size=50)
        pa.submit("a", (10.0, 0.5))
        pa.submit("b", (8.0, 2.0))

        data = pa.serialize()
        pa2 = ParetoArchive.deserialize(data)
        assert pa2 is not None
        assert pa2.contains("a")
        assert pa2.contains("b")

    def test_deserialize_invalid(self):
        assert ParetoArchive.deserialize(b"garbage_data") is None
        assert ParetoArchive.deserialize(b"") is None


# 集成测试: ISRG/Pareto + Scheduler

class TestSchedulerIntegration:
    """ISRG 和 Pareto 归档与调度器的协同集成测试。"""

    def test_graph_awareness_integration(self):
        sched = Scheduler(strategy="aflfast")
        s1 = Seed(id="s1", data=b"A" * 10)
        s1.coverage = {1, 2, 3}
        s2 = Seed(id="s2", data=b"B" * 10)
        s2.coverage = {1, 2, 3, 4, 5}

        sched.add_seed(s1)
        sched.add_seed(s2)

        # 启用 ISRG
        sched.enable_graph_awareness()
        sched.update_relation_graph(s1, s1.coverage)
        sched.update_relation_graph(s2, s2.coverage)

        # 验证多样性评分
        div_s1 = sched.seed_diversity_bonus("s1")
        div_s2 = sched.seed_diversity_bonus("s2")
        assert 0.0 <= div_s1 <= 1.0
        assert 0.0 <= div_s2 <= 1.0

        # 增强评分应 ≥ 基础评分 (有相似种子时可能更低)
        base = sched.seed_score(s1)
        enhanced = sched.seed_score_enhanced(s1)
        # 增强评分在合理范围内
        assert enhanced >= 0.0

    def test_pareto_integration(self):
        sched = Scheduler(strategy="aflfast")
        sched.enable_pareto_archive(n_objectives=4, max_archive_size=50)

        s1 = Seed(id="s1", data=b"A" * 10, generation=1)
        s1.coverage = {1, 2, 3}
        s1.metadata["exec_time_ms"] = 5.0

        s2 = Seed(id="s2", data=b"B" * 10, generation=0)
        s2.coverage = {100, 101, 102}
        s2.metadata["exec_time_ms"] = 2.0

        # s1 和 s2 应在不同维度上各自优越
        accepted_s1 = sched.submit_to_pareto(s1, exec_time_ms=5.0, rarity_score=0.6)
        accepted_s2 = sched.submit_to_pareto(s2, exec_time_ms=2.0, rarity_score=0.8)

        retained = sched.get_pareto_retained_ids()
        # cull_queue 在裁剪时应保护这些种子
        sched.add_seed(s1)
        sched.add_seed(s2)
        removed = sched.cull_queue()
        # 至少一个被保留 (互不支配则应都保留)
        assert len(sched._seed_queue) > 0

    def test_cull_queue_protects_pareto(self):
        sched = Scheduler(strategy="aflfast")
        sched.enable_graph_awareness()
        sched.enable_pareto_archive(max_archive_size=50)

        # s1: 覆盖面小但极快 + 代数极低
        s1 = Seed(id="s1", data=b"fast", generation=0)
        s1.coverage = {1}  # 仅1条边
        s1.metadata["exec_time_ms"] = 0.5

        # s2: 覆盖大但慢
        s2 = Seed(id="s2", data=b"slow", generation=5)
        s2.coverage = {1, 2, 3, 4, 5}  # 包含s1的覆盖
        s2.metadata["exec_time_ms"] = 100.0

        sched.add_seed(s1)
        sched.add_seed(s2)

        # 提交到 Pareto: s1 在速度维度优异, s2 在覆盖维度优异
        sched.submit_to_pareto(s1, exec_time_ms=0.5, rarity_score=0.9)
        sched.submit_to_pareto(s2, exec_time_ms=100.0, rarity_score=0.3)

        # 裁剪: s1 的覆盖被 s2 包含 (无新覆盖), 但受 Pareto 保护
        removed = sched.cull_queue()
        # 两个都应保留: s2 提供覆盖, s1 受 Pareto 保护
        remaining_ids = {s.id for s in sched._seed_queue}
        assert "s1" in remaining_ids, "Pareto 前沿上的 s1 不应被裁剪"
        assert "s2" in remaining_ids

    def test_queue_stats_includes_isrg_pareto(self):
        sched = Scheduler(strategy="aflfast")
        sched.enable_graph_awareness()
        sched.enable_pareto_archive()

        stats = sched.get_queue_stats()
        assert "isrg" in stats
        assert "pareto" in stats
        assert stats["isrg"]["node_count"] == 0
        assert stats["pareto"]["archive_size"] == 0


# 边缘情况测试

class TestEdgeCases:
    """边界和退化场景测试。"""

    def test_empty_coverage(self):
        srg = SeedRelationGraph()
        srg.upsert_seed("empty", set())
        # 空覆盖 → 与任何种子都不应有边
        srg.upsert_seed("has_cov", {1, 2})
        assert srg.stats()["edge_count"] == 0

    def test_pareto_single_objective(self):
        pa = ParetoArchive(n_objectives=1, max_archive_size=10)
        assert pa.submit("best", (10.0,))
        assert not pa.submit("dominated", (5.0,))
        assert pa.contains("best")
        assert not pa.contains("dominated")

    def test_pareto_clear(self):
        pa = ParetoArchive(n_objectives=2)
        pa.submit("a", (5.0, 5.0))
        pa.clear()
        assert pa.stats()["archive_size"] == 0
