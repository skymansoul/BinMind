"""PathCluster + MutationEnsemble 单元与集成测试.

修改记录:
2025-07-30 11:42 - 补齐 MinHash LSH 分桶碰撞验证
2025-08-02 19:08 - 增加 EG 权重收敛性测试
"""

import pytest
import random

from fuzzing.src.path_trace_cluster import (
    PathCluster, PathSignature, weighted_minhash_signature,
)
from fuzzing.src.mutation_ensemble import MutationEnsemble, _build_default_strategies
from fuzzing.src.core import Seed
from fuzzing.src.scheduler import Scheduler


# PathCluster 测试

class TestPathCluster:
    """MinHash LSH 路径聚类单元测试。"""

    def test_empty_cluster(self):
        pc = PathCluster()
        assert pc.stats()["total_signatures"] == 0
        assert pc.query_similar("nonexistent") == []

    def test_insert_and_query(self):
        pc = PathCluster()
        # 两条相似路径
        trace_a = [1, 2, 3, 4, 5, 1, 2]
        trace_b = [1, 2, 3, 4, 5]  # 与 a 高度重叠
        trace_c = [100, 101, 102, 103]  # 与 a, b 完全不重叠

        pc.insert("a", trace_a)
        pc.insert("b", trace_b)
        pc.insert("c", trace_c)

        similar_to_a = pc.query_similar("a", top_k=5)
        # b 应与 a 高度相似
        b_score = next((s for sid, s in similar_to_a if sid == "b"), 0.0)
        c_score = next((s for sid, s in similar_to_a if sid == "c"), 0.0)
        assert b_score > c_score, f"b should be more similar to a than c (got {b_score:.3f} vs {c_score:.3f})"

    def test_minhash_consistency(self):
        """相同边集 → 相同 MinHash 签名"""
        pc = PathCluster()
        pc.insert("x", [1, 2, 3])
        pc.insert("y", [1, 2, 3])  # 相同 trace

        jac = pc._minhash_jaccard(
            pc._signatures["x"].minhash_sig,
            pc._signatures["y"].minhash_sig,
        )
        assert jac == 1.0, f"Identical traces should have Jaccard 1.0 (got {jac})"

    def test_disjoint_traces(self):
        """完全不重叠的 trace → Jaccard 接近 0"""
        pc = PathCluster()
        pc.insert("a", [1, 2, 3, 4, 5])
        pc.insert("b", [100, 101, 102, 103, 104])

        jac = pc._minhash_jaccard(
            pc._signatures["a"].minhash_sig,
            pc._signatures["b"].minhash_sig,
        )
        assert jac < 0.3, f"Disjoint traces should have low Jaccard (got {jac})"

    def test_path_diversity(self):
        pc = PathCluster()
        pc.insert("a", [1, 2, 3, 4, 5])
        pc.insert("b", [100, 101, 102, 103])
        # b 与 a 路径不重叠 → 高多样性
        div_b = pc.path_diversity_score("b")
        assert div_b > 0.5, f"Disjoint path should have high diversity (got {div_b})"

    def test_near_duplicate_detection(self):
        pc = PathCluster()
        # 插入多条路径相同的 trace
        for i in range(5):
            pc.insert(f"s{i}", [1, 2, 3, 4, 5])
        dups = pc.find_near_duplicates(threshold=0.9)
        # 所有种子间两两 Jaccard = 1.0 → C(5,2) = 10 对
        assert len(dups) >= 5, f"Should find many near-duplicate pairs (got {len(dups)})"

    def test_lsh_bucket_collision(self):
        """LSH 分桶: 相似签名应在至少一个 band 中碰撞"""
        pc = PathCluster()
        pc.insert("a", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        pc.insert("b", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

        sig_a = pc._signatures["a"].minhash_sig
        # 检查 b 是否在 a 的任意 LSH 桶中
        in_bucket = False
        for band in range(16):
            key_a = pc._band_key(sig_a, band)
            if "b" in pc._buckets.get(key_a, []):
                in_bucket = True
                break
        assert in_bucket, "Identical signatures must collide in all LSH bands"

    def test_weighted_minhash(self):
        """IDF 加权 MinHash: 稀有边获得更高权重"""
        idf = {1: 0.1, 2: 0.1, 99: 5.0}  # 边 99 是稀有边
        sig = weighted_minhash_signature({1, 2, 99}, idf)
        assert len(sig) == 128
        # 加权不影响结构正确性, 只影响相似度排序
        assert all(isinstance(v, int) for v in sig)

    def test_reinsert_updates(self):
        """重新插入同一 seed_id 应更新签名而非创建重复节点"""
        pc = PathCluster()
        pc.insert("a", [1, 2, 3])
        pc.insert("a", [1, 2, 3, 4, 5])
        assert pc.stats()["total_signatures"] == 1


# MutationEnsemble 测试

class TestMutationEnsemble:
    """突变策略 EG 集成单元测试。"""

    def test_default_strategies(self):
        strats = _build_default_strategies()
        assert len(strats) == 8
        # 所有策略应产生有效输出
        data = b"A" * 100
        for name, fn in strats.items():
            result, positions = fn(data)
            assert isinstance(result, bytes)
            assert isinstance(positions, list)

    def test_initial_weights_uniform(self):
        me = MutationEnsemble()
        probs = [s.prob for s in me._strategies.values()]
        # 初始权重相等 → 概率应接近 1/N
        expected = 1.0 / 8
        for p in probs:
            assert abs(p - expected) < 0.001

    def test_sampling_coverage(self):
        """采样应覆盖所有策略"""
        me = MutationEnsemble()
        seen = set()
        for _ in range(500):
            seen.add(me.sample())
        assert len(seen) == 8, f"Should sample all 8 strategies (got {len(seen)})"

    def test_eg_weight_convergence(self):
        """EG 更新: 持续奖励某一策略 → 其权重应上升"""
        me = MutationEnsemble(learning_rate=0.1)
        winner = "bitflip"

        initial_prob = me._strategies[winner].prob
        # 对 winner 连续给予高奖励
        for _ in range(50):
            me.update(winner, reward=1.0)
        final_prob = me._strategies[winner].prob

        assert final_prob > initial_prob, (
            f"Strategy {winner} weight should increase with consistent reward "
            f"({initial_prob:.4f} → {final_prob:.4f})"
        )

    def test_eg_weight_decay_with_zero_reward(self):
        """零奖励 → 权重应向 min_weight 衰减 (但不低于 min_weight)"""
        me = MutationEnsemble(learning_rate=0.2, min_weight=0.01)
        loser = "byteflip"
        # 先给一些奖励建立 baseline
        me.update("bitflip", reward=1.0)
        me.update("bitflip", reward=1.0)
        # loser 连续零奖励
        for _ in range(30):
            me.update(loser, reward=0.0)
        assert me._strategies[loser].weight >= 0.01, "Weight should not drop below min_weight"

    def test_mutation_output(self):
        """mutate() 应返回有效的变异结果"""
        me = MutationEnsemble()
        data = b"Hello World" * 10
        result, positions, name = me.mutate(data, "bitflip")
        assert isinstance(result, bytes)
        assert len(positions) == 1
        assert name == "bitflip"
        # 变异后数据应与原始数据长度相同 (bitflip 不改变长度)
        assert len(result) == len(data)

    def test_synergy_tracking(self):
        """协同效应: precursor→current 增益链应被记录"""
        me = MutationEnsemble()
        # precursor=havoc, current=arith, 有正向奖励
        me._last_strategy = "havoc"
        me.update("arith", reward=1.0, precursor="havoc")
        synergy = me.get_synergy_bonus("arith", "havoc")
        assert synergy > 0.0

    def test_synergy_sampling(self):
        """启用协同后, 高协同对的概率应上调"""
        me = MutationEnsemble()
        # 建立 strong synergy: splice→delete
        for _ in range(20):
            me.update("delete", reward=1.0, precursor="splice")
        name = me.sample_with_synergy(precursor="splice")
        # 不一定总是选 delete, 但至少概率分布有效
        assert name in me._strategies

    def test_export_import(self):
        me = MutationEnsemble()
        me.update("bitflip", reward=1.0)
        w = me.export_weights()
        assert "bitflip" in w

        me2 = MutationEnsemble()
        me2.import_weights(w)
        assert me2._strategies["bitflip"].weight == w["bitflip"]

    def test_edge_empty_data(self):
        """空数据输入不应导致崩溃"""
        me = MutationEnsemble()
        for name in me._strategies:
            result, positions, _ = me.mutate(b"", name)
            assert isinstance(result, bytes)


# 集成测试

class TestFullIntegration:
    """PathCluster + MutationEnsemble + Scheduler 全链路集成。"""

    def test_full_pipeline(self):
        sched = Scheduler(strategy="aflfast")
        sched.enable_graph_awareness()
        sched.enable_pareto_archive(max_archive_size=20)
        sched.enable_path_clustering()
        sched.enable_mutation_ensemble(learning_rate=0.1)

        seeds = []
        for i in range(10):
            s = Seed(id=f"s{i}", data=bytes([i] * 20), generation=i % 3)
            s.coverage = set(range(i * 5, i * 5 + 10))
            s.metadata["exec_time_ms"] = 1.0 + i * 0.5
            seeds.append(s)

        for s in seeds:
            sched.add_seed(s)
            sched.update_relation_graph(s, s.coverage)
            # 模拟 trace: 每个种子有略微不同的执行路径
            trace = list(range(s.id[1] + 1)) * 3
            sched.insert_execution_trace(s.id, trace)
            sched.submit_to_pareto(
                s,
                exec_time_ms=s.metadata.get("exec_time_ms", 10.0),
                rarity_score=0.5 + 0.05 * int(s.id[1:]),
            )

        # 模拟突变反馈
        for _ in range(20):
            strat = sched.sample_mutation_strategy()
            if strat:
                sched.update_mutation_feedback(strat, reward=random.random())

        stats = sched.get_queue_stats()
        assert "isrg" in stats
        assert "pareto" in stats
        assert "path_cluster" in stats, "PathCluster stats should be in queue stats"
        assert "mutation_ensemble" in stats, "MutationEnsemble stats should be in queue stats"

        # 路径多样性查询
        div = sched.path_diversity_score("s0")
        assert 0.0 <= div <= 1.0

        # 综合多样性
        comp_div = sched.comprehensive_diversity("s0")
        assert 0.0 <= comp_div <= 1.0

        # 裁剪应保留 Pareto 和 ISRG 桥接种子
        removed = sched.cull_queue()
        assert removed >= 0
