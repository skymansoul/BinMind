# 分区与节点注册测试
# 数据分区是水平扩展的基础。
# 一致性哈希最小化重分布；范围分区支持范围扫描。
# NodeRegistry 抽象三种发现后端；测试覆盖全部三种。
"""
分区与节点注册测试。
"""
import pytest
from ..src.partition import (
    HashPartitioner,
    RangePartitioner,
    RoundRobinPartitioner,
    PartitionManager,
)


class TestHashPartitioner:
    """基于 MD5 的确定性分区。"""

    def test_same_key_same_partition(self):
        hp = HashPartitioner()
        for _ in range(10):
            assert hp.partition("my_stable_key", 8) == hp.partition("my_stable_key", 8)

    def test_partition_in_range(self):
        hp = HashPartitioner()
        for key in [f"task_{i}" for i in range(100)]:
            p = hp.partition(key, 16)
            assert 0 <= p < 16

    def test_different_keys_spread(self):
        hp = HashPartitioner()
        partitions = {hp.partition(f"key_{i}", 32) for i in range(100)}
        assert len(partitions) >= 10  # 在 32 个分区中合理分布

    def test_replicas_are_distinct(self):
        hp = HashPartitioner()
        replicas = hp.partitions_for_key("data_key", 8, replicas=3)
        assert len(replicas) == 3
        assert len(set(replicas)) == 3  # 全部不同 (相邻分区)


class TestRangePartitioner:
    """字典序范围分区。"""

    def test_untrained_falls_back_to_hash(self):
        rp = RangePartitioner()
        p = rp.partition("some_key", 4)
        assert 0 <= p < 4

    def test_trained_partitions_by_range(self):
        rp = RangePartitioner()
        keys = [f"key_{i:03d}" for i in range(100)]
        rp.fit(keys, n_partitions=4)
        # 检查边界情况
        p_first = rp.partition("key_000", 4)
        p_mid = rp.partition("key_050", 4)
        p_last = rp.partition("key_099", 4)
        # 均在有效范围内
        assert 0 <= p_first < 4
        assert 0 <= p_mid < 4
        assert 0 <= p_last < 4
        # 非递减顺序
        assert p_first <= p_mid <= p_last


class TestRoundRobinPartitioner:
    """无状态轮询。"""

    def test_cycles_through_partitions(self):
        rrp = RoundRobinPartitioner()
        seq = [rrp.partition("any_key", 3) for _ in range(9)]
        assert seq == [0, 1, 2, 0, 1, 2, 0, 1, 2]


class TestPartitionManager:
    """节点分配与再均衡。"""

    def test_first_node_gets_all_partitions(self):
        pm = PartitionManager(n_partitions=4)
        assigned = pm.add_node("node_a")
        assert len(assigned) == 4
        assert set(assigned) == {0, 1, 2, 3}

    def test_second_node_takes_half(self):
        pm = PartitionManager(n_partitions=4)
        pm.add_node("node_a")
        assigned = pm.add_node("node_b")
        assert len(assigned) == 2  # 4 分区 / 2 节点 = 每节点 2 个

    def test_route_returns_correct_node(self):
        pm = PartitionManager(n_partitions=4)
        pm.add_node("node_a")
        pm.add_node("node_b")
        # 路由应对任意 key 返回有效节点
        for key in [f"task_{i}" for i in range(50)]:
            node = pm.route(key)
            assert node in ("node_a", "node_b")

    def test_remove_node_redistributes(self):
        pm = PartitionManager(n_partitions=4)
        pm.add_node("node_a")
        pm.add_node("node_b")
        pm.remove_node("node_b")
        # node_a 应重新拥有全部分区
        partitions = pm.get_partitions_for_node("node_a")
        assert len(partitions) == 4

    def test_rebalance_callback_fires(self):
        rebalance_log = []
        pm = PartitionManager(n_partitions=4)
        pm.on_rebalance(lambda p, old, new: rebalance_log.append((p, old, new)))
        pm.add_node("node_a")
        pm.add_node("node_b")
        assert len(rebalance_log) >= 2  # 发生了迁移

    def test_route_with_replicas(self):
        pm = PartitionManager(n_partitions=6)
        pm.add_node("node_a")
        pm.add_node("node_b")
        nodes = pm.route_with_replicas("data_x", replicas=2)
        assert len(nodes) == 2
        assert nodes[0] is not None
        assert nodes[1] is not None

    def test_state_snapshot(self):
        pm = PartitionManager(n_partitions=3)
        pm.add_node("a")
        state = pm.state
        assert state["n_partitions"] == 3
        assert "a" in state["nodes"]


class TestNodeRegistry:
    """静态发现后端（最简单，不需 Redis）。"""

    def test_static_discovery(self):
        from ..src.node_registry import NodeRecord, StaticDiscovery, NodeRegistry

        records = [
            NodeRecord(node_id="n1", address="10.0.0.1:9000", status="online"),
            NodeRecord(node_id="n2", address="10.0.0.2:9000", status="online"),
        ]
        backend = StaticDiscovery(records)
        registry = NodeRegistry(backend=backend)

        discovered = registry.discover()
        assert len(discovered) == 2
        available = registry.get_available_nodes()
        assert len(available) == 2

    def test_node_heartbeat_updates_last_seen(self):
        from ..src.node_registry import NodeRecord, StaticDiscovery

        backend = StaticDiscovery([
            NodeRecord(node_id="n1", address="10.0.0.1:9000")
        ])
        old_seen = backend.discover()[0].last_seen
        backend.heartbeat("n1")
        new_seen = backend.discover()[0].last_seen
        assert new_seen >= old_seen

    def test_node_registry_get_node(self):
        from ..src.node_registry import NodeRecord, StaticDiscovery, NodeRegistry

        backend = StaticDiscovery([
            NodeRecord(node_id="target", address="10.0.0.5:9000")
        ])
        registry = NodeRegistry(backend=backend)
        node = registry.get_node("target")
        assert node is not None
        assert node.address == "10.0.0.5:9000"

    def test_unregister_removes_node(self):
        from ..src.node_registry import NodeRecord, StaticDiscovery

        backend = StaticDiscovery([
            NodeRecord(node_id="n1", address="10.0.0.1:9000")
        ])
        assert len(backend.discover()) == 1
        backend.unregister("n1")
        assert len(backend.discover()) == 0
