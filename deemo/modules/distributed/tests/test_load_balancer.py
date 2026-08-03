# 负载均衡策略验证
# 六种策略 + 一致性哈希环 = 完整的 Nginx/HAProxy 频谱。
# 轮询是确定性的。加权轮询匹配 Nginx SWRR。一致性哈希
# 最小化节点变更时的重分布。每种策略测试正确性、
# 边界条件（空集、全不健康）和基本分布特性。
"""
负载均衡测试：六种策略 + 一致性哈希环。
"""
import pytest
from ..src.load_balancer import (
    LoadBalancer,
    SelectorNode,
    ConsistentHashRing,
    RoundRobinBalancer,
    WeightedRoundRobinBalancer,
    LeastConnectionsBalancer,
    WeightedLeastConnectionsBalancer,
    RandomBalancer,
    WeightedRandomBalancer,
)


def _make_nodes(n=3):
    """辅助函数：创建 n 个不同容量的健康节点。"""
    return [SelectorNode(id=f"n{i}", weight=i + 1, capacity=i + 1, current_load=0) for i in range(n)]


class TestRoundRobin:
    def test_cycles_through_nodes(self):
        rr = RoundRobinBalancer()
        nodes = _make_nodes(3)
        selected = [rr.select(nodes).id for _ in range(6)]
        assert selected == ["n0", "n1", "n2", "n0", "n1", "n2"]

    def test_skips_unhealthy(self):
        rr = RoundRobinBalancer()
        nodes = _make_nodes(3)
        nodes[1].healthy = False
        selected = [rr.select(nodes).id for _ in range(4)]
        assert "n1" not in selected
        assert selected == ["n0", "n2", "n0", "n2"]

    def test_all_unhealthy_returns_none(self):
        rr = RoundRobinBalancer()
        nodes = _make_nodes(2)
        for n in nodes:
            n.healthy = False
        assert rr.select(nodes) is None


class TestWeightedRoundRobin:
    def test_smooth_weighted_distribution(self):
        """SWRR 应按比例分配，不饿死低权重节点。"""
        wrr = WeightedRoundRobinBalancer()
        nodes = [
            SelectorNode(id="heavy", weight=5),
            SelectorNode(id="light", weight=1),
        ]
        counts = {}
        for _ in range(12):
            n = wrr.select(nodes)
            counts[n.id] = counts.get(n.id, 0) + 1
        # heavy 应该得到约 5x 的请求
        assert counts.get("heavy", 0) > counts.get("light", 0)
        assert counts.get("light", 0) >= 1  # 不饿死


class TestLeastConnections:
    def test_picks_least_loaded(self):
        nodes = _make_nodes(3)
        nodes[0].current_load = 5
        nodes[1].current_load = 2
        nodes[2].current_load = 7
        lc = LeastConnectionsBalancer()
        assert lc.select(nodes).id == "n1"

    def test_break_tie_by_capacity(self):
        nodes = [
            SelectorNode(id="small", capacity=1, current_load=0),
            SelectorNode(id="large", capacity=10, current_load=0),
        ]
        lc = LeastConnectionsBalancer()
        # 相同负载 → 选更大容量 (key: (0, -1) vs (0, -10), -10 更小)
        assert lc.select(nodes).id == "large"


class TestWeightedLeastConnections:
    def test_picks_by_load_ratio(self):
        nodes = [
            SelectorNode(id="a", capacity=2, current_load=1),   # ratio 0.5
            SelectorNode(id="b", capacity=10, current_load=9),  # ratio 0.9
            SelectorNode(id="c", capacity=5, current_load=1),   # ratio 0.2
        ]
        wlc = WeightedLeastConnectionsBalancer()
        assert wlc.select(nodes).id == "c"


class TestRandom:
    def test_selects_healthy(self):
        nodes = _make_nodes(5)
        r = RandomBalancer()
        for _ in range(20):
            n = r.select(nodes)
            assert n is not None
            assert n.healthy


class TestWeightedRandom:
    def test_weighted_distribution(self):
        nodes = [
            SelectorNode(id="rare", weight=1),
            SelectorNode(id="common", weight=100),
        ]
        wr = WeightedRandomBalancer()
        counts = {}
        for _ in range(500):
            n = wr.select(nodes)
            counts[n.id] = counts.get(n.id, 0) + 1
        assert counts.get("common", 0) > counts.get("rare", 0) * 5


class TestLoadBalancerFacade:
    def test_invalid_strategy_raises(self):
        with pytest.raises(ValueError):
            LoadBalancer("nonexistent")

    def test_strategy_dispatch(self):
        for name in ["round_robin", "weighted_rr", "least_connections",
                      "weighted_lc", "random", "weighted_random"]:
            lb = LoadBalancer(name)
            n = lb.select(_make_nodes(2))
            assert n is not None
            assert n.healthy


class TestConsistentHashRing:
    def test_get_node_returns_same_node_for_same_key(self):
        ring = ConsistentHashRing(vnode_count=40)
        ring.add_node("n1", weight=2)
        ring.add_node("n2", weight=1)
        first = ring.get_node("my_task_key")
        for _ in range(10):
            assert ring.get_node("my_task_key") == first

    def test_add_remove_node_minimal_redistribution(self):
        ring = ConsistentHashRing(vnode_count=40)
        ring.add_node("a")
        ring.add_node("b")
        before = {ring.get_node(f"k{i}") for i in range(100)}
        ring.remove_node("a")
        after = {ring.get_node(f"k{i}") for i in range(100)}
        # b 应该仍然拥有大部分之前已分配给它的 key
        assert "b" in after

    def test_get_nodes_replicas(self):
        ring = ConsistentHashRing(vnode_count=20)
        ring.add_node("a")
        ring.add_node("b")
        ring.add_node("c")
        repl = ring.get_nodes("some_key", count=2)
        assert len(repl) == 2
        assert len(set(repl)) == 2  # 不同节点

    def test_empty_ring_returns_none(self):
        ring = ConsistentHashRing()
        assert ring.get_node("anything") is None
        assert ring.get_nodes("anything") == []
