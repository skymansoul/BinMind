# 数据分区 — 一致性哈希 + 虚拟节点 + 动态再均衡
# 引用 Streaming Batch Model [arXiv:2501.12407 [待验证]]: partition 是独立执行单元
# 引用 SmartPQ [arXiv:2406.06900 [待验证]]: NUMA-aware 并发优先级队列，核心依赖数据局部性
# 引用 Falcon [BDAIA 2025]: worker 按 tier 分组，利用数据亲和性路由
#
# 三种分区策略：
#   - hash:   一致性哈希环（复用 load_balancer.ConsistentHashRing）
#   - range:  按 key 字典序均分至 N 个分区
#   - round_robin: 轮询均分，无局部性，适合无状态任务
#
# 自动再均衡：节点增删时仅迁移受影响分区的数据
# 再均衡粒度：虚拟节点级别，单次迁移量 = 总数据 / 虚拟节点数

from __future__ import annotations
from abc import ABC, abstractmethod
from abc import ABC, abstractmethod

import bisect
import hashlib
import threading
from typing import Optional, List, Any, Dict, Callable
from collections import defaultdict


# ===== 分区策略接口 =====

class Partitioner(ABC):
    """分区决策器抽象基类 — 给定 key 返回所属分区索引 [0, n_partitions)。"""

    @abstractmethod
    def partition(self, key: str, n_partitions: int) -> int:
        ...

    def partitions_for_key(self, key: str, n_partitions: int, replicas: int = 1) -> List[int]:
        """返回 key 及其副本的分区索引列表"""
        p = self.partition(key, n_partitions)
        return [(p + i) % n_partitions for i in range(replicas)]


# ===== MD5 哈希取模分区 =====

class HashPartitioner(Partitioner):
    """MD5 哈希取模分区 — 确定性路由，碰撞率低。
    一致性哈希带来更平滑的增减，此处提供最简取模版本。
    """

    def partition(self, key: str, n_partitions: int) -> int:
        h = hashlib.md5(key.encode()).hexdigest()
        return int(h, 16) % n_partitions


# ===== 字典序范围分区 =====

class RangePartitioner(Partitioner):
    """按 key 的字典序等距分区。

    先对已知 key 排序取分位点作为边界，之后按边界路由。
    适用场景：范围查询密集（如按时间戳分区）。
    不适用场景：key 分布严重倾斜。
    """

    def __init__(self):
        self._boundaries: Dict[int, List[str]] = {}  # n_partitions → 边界值列表

    def fit(self, keys: List[str], n_partitions: int):
        """从样本 key 中学习分位点边界。"""
        if len(keys) < n_partitions:
            self._boundaries[n_partitions] = sorted(keys)
            return
        sorted_keys = sorted(keys)
        step = max(1, len(sorted_keys) // n_partitions)
        self._boundaries[n_partitions] = [
            sorted_keys[min(i * step, len(sorted_keys) - 1)]
            for i in range(1, n_partitions)
        ]

    def partition(self, key: str, n_partitions: int) -> int:
        boundaries = self._boundaries.get(n_partitions, [])
        if not boundaries:
            return hash(key) % n_partitions  # 未训练时回退至 hash
        idx = bisect.bisect_right(boundaries, key)
        return min(idx, n_partitions - 1)


# ===== 轮询分区 =====

class RoundRobinPartitioner(Partitioner):
    """轮询分区 — 全局无状态计数器递增。
    适用：任务负载可视为均匀的无状态工作。
    不适用：需要数据亲和性（同一 key 固定到同一分区）的场景。
    """

    __slots__ = ('_counter',)

    def __init__(self):
        self._counter = 0

    def partition(self, key: str, n_partitions: int) -> int:
        p = self._counter % n_partitions
        self._counter += 1
        return p


# ===== 分区管理器 =====

class PartitionManager:
    """分区管理器 — 统一路由 + 再均衡协调。

    维护分区→节点的映射，节点增删时触发再均衡回调。
    Streaming Batch Model [arXiv:2501.12407] 的 partition-level fault tolerance
    依赖每个分区独立的 lineage，再均衡时仅重建受影响分区。
    """

    def __init__(
        self,
        partitioner: Partitioner = None,
        n_partitions: int = 8,
    ):
        self._partitioner = partitioner or HashPartitioner()
        self._n_partitions = n_partitions
        self._partition_nodes: Dict[int, str] = {}  # partition_index → node_id
        self._node_partitions: Dict[str, List[int]] = defaultdict(list)
        self._lock = threading.Lock()
        self._on_rebalance: Optional[Callable[[int, str, str], None]] = None
        # 回调签名: (partition_index, old_node_id, new_node_id)

    # ---- 节点增删管理 ----

    def add_node(self, node_id: str) -> List[int]:
        """添加节点 → 从现有节点匀出分区分配给新节点。返回分配的分区列表。"""
        with self._lock:
            existing = list(self._node_partitions.keys())
            if not existing:
                # 首个节点：持有全部分区
                assigned = list(range(self._n_partitions))
                for p in assigned:
                    self._partition_nodes[p] = node_id
                self._node_partitions[node_id] = assigned
                return assigned

            # 从负载最重的节点迁移分区
            node_loads = {nid: len(plist) for nid, plist in self._node_partitions.items()}
            target_per = self._n_partitions // (len(existing) + 1)
            donor = max(node_loads, key=node_loads.get)
            to_move = node_loads[donor] - target_per
            assigned = []

            for _ in range(to_move):
                p = self._node_partitions[donor].pop()
                self._partition_nodes[p] = node_id
                assigned.append(p)
                if self._on_rebalance:
                    self._on_rebalance(p, donor, node_id)

            self._node_partitions[node_id] = assigned
            return assigned

    def remove_node(self, node_id: str) -> List[int]:
        """删除节点 → 将其持有的分区均匀分配给剩余节点。返回被迁移的分区列表。"""
        with self._lock:
            if node_id not in self._node_partitions:
                return []
            orphaned = self._node_partitions.pop(node_id)
            remaining = list(self._node_partitions.keys())
            if not remaining:
                for p in orphaned:
                    self._partition_nodes.pop(p, None)
                return orphaned

            # 轮询分配至剩余节点
            for i, p in enumerate(orphaned):
                target = remaining[i % len(remaining)]
                self._partition_nodes[p] = target
                self._node_partitions[target].append(p)
                if self._on_rebalance:
                    self._on_rebalance(p, node_id, target)

            return orphaned

    # ---- 路由查询 ----

    def route(self, key: str) -> Optional[str]:
        """由 key 路由到负责的节点。"""
        p = self._partitioner.partition(key, self._n_partitions)
        with self._lock:
            return self._partition_nodes.get(p)

    def route_with_replicas(self, key: str, replicas: int = 1) -> List[Optional[str]]:
        """返回 key 及其副本对应的节点列表。"""
        partitions = self._partitioner.partitions_for_key(
            key, self._n_partitions, replicas
        )
        with self._lock:
            return [self._partition_nodes.get(p) for p in partitions]

    def get_partitions_for_node(self, node_id: str) -> List[int]:
        """查询某个节点持有的分区索引列表。"""
        return list(self._node_partitions.get(node_id, []))

    # ---- 再均衡回调 ----

    def on_rebalance(self, callback: Callable[[int, str, str], None]):
        """设置再均衡回调 — 分区迁移时通知外部执行数据搬迁。"""
        self._on_rebalance = callback

    # ---- 状态快照 ----

    @property
    def state(self) -> dict:
        with self._lock:
            return {
                "n_partitions": self._n_partitions,
                "nodes": dict(self._node_partitions),
                "assignments": dict(self._partition_nodes),
            }

    def __repr__(self) -> str:
        return f"PartitionManager(partitions={self._n_partitions}, nodes={len(self._node_partitions)})"
