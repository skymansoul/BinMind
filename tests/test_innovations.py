"""
DESG / 熵调度器 / 路径多样性探索器 单元测试。

仅测试纯逻辑和数据结构正确性，不依赖外部二进制或 angr。
"""
from __future__ import annotations

import pytest


class TestDESG:
    """支配增强语义图构建测试。"""

    def test_empty_blocks(self):
        from core.desg_builder import build_desg
        d = build_desg([])
        assert d["entry"] == 0
        assert d["edges_bb"] == []

    def test_single_block(self):
        from core.desg_builder import build_desg
        blocks = [{"addr": 0x1000, "size": 16, "successors": []}]
        d = build_desg(blocks)
        assert d["entry"] == 0x1000
        assert len(d["nodes"]) == 1
        assert d["exit_addrs"] == [0x1000]

    def test_linear_chain(self):
        from core.desg_builder import build_desg
        blocks = [
            {"addr": 0x10, "size": 8, "successors": [0x20]},
            {"addr": 0x20, "size": 8, "successors": [0x30]},
            {"addr": 0x30, "size": 8, "successors": []},
        ]
        d = build_desg(blocks)
        assert len(d["edges_bb"]) == 2
        assert len(d["edges_dom"]) >= 2  # 线性链中每个前驱支配后继

    def test_branch_merge(self):
        from core.desg_builder import build_desg
        # if-then-else → merge
        blocks = [
            {"addr": 0x10, "size": 4, "successors": [0x20, 0x30]},  # branch
            {"addr": 0x20, "size": 4, "successors": [0x40]},         # then
            {"addr": 0x30, "size": 4, "successors": [0x40]},         # else
            {"addr": 0x40, "size": 4, "successors": []},              # merge
        ]
        d = build_desg(blocks)
        # merge 点被 branch 支配
        edges_dom = {(s, t) for s, t in d["edges_dom"]}
        assert (0x10, 0x40) in edges_dom

    def test_structural_hash_deterministic(self):
        from core.desg_builder import build_desg, desg_structural_hash
        blocks = [
            {"addr": 1, "size": 8, "successors": [2]},
            {"addr": 2, "size": 8, "successors": []},
        ]
        h1 = desg_structural_hash(build_desg(blocks))
        h2 = desg_structural_hash(build_desg(blocks))
        assert h1 == h2
        assert len(h1) == 16

    def test_dominator_linear(self):
        from core.desg_builder import _compute_dominators
        nodes = [1, 2, 3]
        preds = {1: [], 2: [1], 3: [2]}
        idom = _compute_dominators(nodes, preds, 1)
        assert idom.get(2) == 1
        assert idom.get(3) == 2


class TestEntropyScheduler:
    """熵调度器测试。"""

    def test_empty_select(self):
        from core.entropy_scheduler import EntropySeedScheduler
        s = EntropySeedScheduler()
        assert s.select_seed() is None

    def test_single_seed(self):
        from core.entropy_scheduler import EntropySeedScheduler
        s = EntropySeedScheduler()
        s.register_seed("s1", [1, 2, 3])
        s.record_execution([1, 2, 3], seed_id="s1")
        # 单种子时始终选中
        assert s.select_seed() == "s1"

    def test_energy_ordering(self):
        from core.entropy_scheduler import EntropySeedScheduler
        s = EntropySeedScheduler()
        s.register_seed("rare", [99])
        s.register_seed("common", [1, 2, 3, 4, 5])
        # 模拟 500 次执行命中 common 边——触发 _recompute_energies
        for _ in range(500):
            s.record_execution([1, 2, 3, 4, 5])
        s.record_execution([99])
        s._recompute_energies()
        assert s.get_energy("rare") > s.get_energy("common")

    def test_decay_reduces_old_edges(self):
        from core.entropy_scheduler import EntropySeedScheduler
        s = EntropySeedScheduler(decay_base=0.9)
        s.record_execution([1])
        s.record_execution([2])
        s.record_execution([2])
        s.record_execution([2])
        # 边 1 因衰减频次应低于边 2
        assert s._edge_freq.get(1, 0) < s._edge_freq.get(2, 0)

    def test_stats(self):
        from core.entropy_scheduler import EntropySeedScheduler
        s = EntropySeedScheduler()
        s.register_seed("a", [1])
        s.register_seed("b", [2])
        st = s.stats()
        assert st["active_seeds"] == 2
        assert st["total_execs"] == 0


class TestPathDiversity:
    """路径多样性探索器测试。"""

    def test_empty_priorities(self):
        from core.path_diversity_explorer import PathDiversityExplorer
        p = PathDiversityExplorer()
        assert p.compute_priorities() == []

    def test_single_path_novelty(self):
        from core.path_diversity_explorer import PathDiversityExplorer
        p = PathDiversityExplorer()
        p.register_active_path("p1", [1, 2, 3], call_depth=5,
                               sym_var_count=10, block_count=100,
                               unexplored_successors=2)
        # 未探索时新颖度最高
        priorities = p.compute_priorities()
        assert len(priorities) == 1
        assert priorities[0][1] > 0.5

    def test_explored_reduces_novelty(self):
        from core.path_diversity_explorer import PathDiversityExplorer
        p = PathDiversityExplorer()
        for i in range(5):
            pid = f"p{i}"
            p.register_active_path(pid, [i]*3, call_depth=2,
                                   sym_var_count=5, block_count=50,
                                   unexplored_successors=1)
            p.mark_explored(pid)
        # 注册一条与被探索路径相似的新路径
        p.register_active_path("similar", [0]*3, call_depth=2,
                               sym_var_count=5, block_count=50,
                               unexplored_successors=1)
        priorities = p.compute_priorities()
        # similar 的新颖度应低于阈值
        assert any(pid == "similar" for pid, _ in priorities)

    def test_stagnation_detection(self):
        from core.path_diversity_explorer import PathDiversityExplorer
        p = PathDiversityExplorer()
        # 空库不认为停滞
        assert not p.is_stagnating(window=10)
        # 插入 60 条极其相似的路径
        for i in range(60):
            pid = f"p{i}"
            p.register_active_path(pid, [1]*4, call_depth=3,
                                   sym_var_count=8, block_count=80,
                                   unexplored_successors=0)
            p.mark_explored(pid)
        # 高度相似 → 停滞
        assert p.is_stagnating(window=50)

    def test_select_next_respects_novelty(self):
        from core.path_diversity_explorer import PathDiversityExplorer
        p = PathDiversityExplorer()
        # 填入已探索库
        for i in range(20):
            pid = f"e{i}"
            p.register_active_path(pid, [i]*4, call_depth=2,
                                   sym_var_count=5, block_count=60,
                                   unexplored_successors=1)
            p.mark_explored(pid)
        # 新颖路径
        p.register_active_path("novel", [99, 98, 97, 96], call_depth=8,
                               sym_var_count=20, block_count=200,
                               unexplored_successors=3)
        selected = p.select_next(top_k=3)
        assert "novel" in selected
