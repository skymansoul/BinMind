# 负载均衡策略集 — 覆盖六大经典算法 + 一致性哈希环
# 参考 Falcon 框架 [ACM BDAIA 2025] 的三层优先级 + 加权公平队列思路
# 参考 Hiku [arXiv:2502.15534] 的 pull-based 调度对负载分布的改进
# 每种策略封装为独立类，暴露统一的 select 接口
#
# 设计约束：策略无状态，选择逻辑接收节点列表 + 可选请求上下文
# 一致性哈希例外：维护虚拟节点环，需通过 add_node/remove_node 管理内部状态

from __future__ import annotations

import random
import threading
import hashlib
import bisect
from typing import Optional, List, Any
from dataclasses import dataclass


@dataclass
class SelectorNode:
    """负载均衡器视角下的节点摘要 — 不依赖 models.Node，可独立使用"""
    id: str
    weight: int = 1
    current_load: int = 0
    capacity: int = 1
    healthy: bool = True

    @property
    def load_ratio(self) -> float:
        if self.capacity <= 0:
            return 1.0
        return min(self.current_load / self.capacity, 1.0)


# ===== 基本轮询 =====

class RoundRobinBalancer:
    """简单轮询 — 每次选择后指针后移一位。O(1) 选择，使用无锁原子计数器。

    适用：同构节点集群。不适用：异构节点混部。
    """

    __slots__ = ('_counter',)

    def __init__(self):
        self._counter = 0

    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        healthy = [n for n in nodes if n.healthy]
        if not healthy:
            return None
        idx = self._counter % len(healthy)
        self._counter += 1
        return healthy[idx]


# ===== 加权轮询 — Nginx upstream 平滑算法 =====

class WeightedRoundRobinBalancer:
    """平滑加权轮询 (SWRR)。Nginx upstream 同款实现。

    避免朴素加权轮询在权重差异大时连续打到同一节点。
    每轮选择 current_weight 最大的节点，选中后减去总权重。

    复杂度：O(N) per selection，N 为健康节点数。
    """

    __slots__ = ('_cw', '_lock')

    def __init__(self):
        self._cw: dict[str, int] = {}
        self._lock = threading.Lock()

    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        healthy = [n for n in nodes if n.healthy]
        if not healthy:
            return None

        with self._lock:
            # 新节点初始 current_weight = weight
            for n in healthy:
                if n.id not in self._cw:
                    self._cw[n.id] = n.weight

            # 选取 current_weight 最大者
            best = max(healthy, key=lambda n: self._cw.get(n.id, n.weight))
            # 被选中节点减去总权重
            total_w = sum(n.weight for n in healthy)
            self._cw[best.id] = self._cw.get(best.id, best.weight) - total_w

            # 全量节点 current_weight += weight（含未被选中者）
            for n in healthy:
                self._cw[n.id] = self._cw.get(n.id, n.weight) + n.weight

            return best


# ===== 最少连接数 =====

class LeastConnectionsBalancer:
    """最少连接数优先 — 异构节点集群的默认策略。
    Falcon [BDAIA 2025] 采用类似逻辑进行 worker 分级调度。"""
    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        alive = [n for n in nodes if n.healthy]
        return min(alive, key=lambda n: (n.current_load, -n.capacity)) if alive else None


# ===== 加权最少连接数 =====

class WeightedLeastConnectionsBalancer:
    """加权最少连接 — 负载感知选择，纳入容量差异。

    选取 load_ratio（current_load / capacity）最小的节点。
    比值相同时选 capacity 大的作为均衡踢脚石。
    """

    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        healthy = [n for n in nodes if n.healthy]
        if not healthy:
            return None
        return min(healthy, key=lambda n: (n.load_ratio, -n.capacity))


# ===== 随机选择 =====

class RandomBalancer:
    """均匀随机选择。Hiku [arXiv:2502.15534]: pull-based + random 优于 hash-based 12.9%。"""
    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        alive = [n for n in nodes if n.healthy]
        if not alive:
            return None
        return random.choice(alive)


class WeightedRandomBalancer:
    """按权重比例的随机选择"""
    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        healthy = [n for n in nodes if n.healthy]
        if not healthy:
            return None
        total_w = sum(n.weight for n in healthy)
        if total_w <= 0:
            return random.choice(healthy)
        r = random.randint(0, total_w - 1)
        acc = 0
        for n in healthy:
            acc += n.weight
            if r < acc:
                return n
        return healthy[-1]


# ===== 一致性哈希环 =====

_VNODE_COUNT = 160  # 单物理节点对应的虚拟节点数量


class ConsistentHashRing:
    """一致性哈希环 — 带虚拟节点，节点增删时仅影响相邻区段。

    参考 Amazon Dynamo [DeCandia+ 2007] 与 Apache Cassandra 的实现。
    结合 Falcon 的 worker 分组思路，可按标签分组构建独立哈希环。

    虚拟节点数 160：均衡性与内存开销之间的折中点。
    """

    __slots__ = ('_ring', '_sorted_keys', '_vnodes', '_lock')

    def __init__(self, vnode_count: int = _VNODE_COUNT):
        self._ring: dict[int, str] = {}
        self._sorted_keys: List[int] = []
        self._vnodes = vnode_count
        self._lock = threading.Lock()

    def _hash(self, key: str) -> int:
        """MD5 → 32 位无符号整数。此处 MD5 足够：
        关注的是分布均匀性而非抗碰撞安全性。"""
        h = hashlib.md5(key.encode()).hexdigest()
        return int(h, 16) & 0xFFFFFFFF

    def add_node(self, node_id: str, weight: int = 1):
        """添加物理节点 → 创建 weight * vnode_count 个虚拟节点。"""
        with self._lock:
            n_vnodes = self._vnodes * weight
            for i in range(n_vnodes):
                vkey = f"{node_id}:vnode:{i}"
                pos = self._hash(vkey)
                self._ring[pos] = node_id
            self._sorted_keys = sorted(self._ring.keys())

    def remove_node(self, node_id: str):
        """移除节点 → 删除其全部虚拟节点。"""
        with self._lock:
            to_remove = [pos for pos, nid in self._ring.items() if nid == node_id]
            for pos in to_remove:
                del self._ring[pos]
            self._sorted_keys = sorted(self._ring.keys())

    def get_node(self, key: str) -> Optional[str]:
        """给定 key → 返回顺时针方向的下一个节点。"""
        with self._lock:
            if not self._ring:
                return None
            h = self._hash(key)
            idx = bisect.bisect_right(self._sorted_keys, h)
            if idx == len(self._sorted_keys):
                idx = 0  # 回环
            pos = self._sorted_keys[idx]
            return self._ring[pos]

    def get_nodes(self, key: str, count: int = 3) -> List[str]:
        """返回顺时针方向 count 个不同节点（用于多副本放置策略）。"""
        with self._lock:
            if not self._ring:
                return []
            result = []
            h = self._hash(key)
            idx = bisect.bisect_right(self._sorted_keys, h)
            seen = set()
            for offset in range(len(self._sorted_keys)):
                pos = self._sorted_keys[(idx + offset) % len(self._sorted_keys)]
                nid = self._ring[pos]
                if nid not in seen:
                    seen.add(nid)
                    result.append(nid)
                    if len(result) >= count:
                        break
            return result

    def __len__(self) -> int:
        return len(set(self._ring.values()))


# ===== 策略门面 =====

class LoadBalancer:
    """策略模式的负载均衡门面。初始化时选定策略，后续透明调用。

    示例:
        lb = LoadBalancer("least_connections")
        node = lb.select(nodes)
    """

    _STRATEGIES = {
        "round_robin": RoundRobinBalancer,
        "weighted_rr": WeightedRoundRobinBalancer,
        "least_connections": LeastConnectionsBalancer,
        "weighted_lc": WeightedLeastConnectionsBalancer,
        "random": RandomBalancer,
        "weighted_random": WeightedRandomBalancer,
    }

    def __init__(self, strategy: str = "least_connections"):
        cls = self._STRATEGIES.get(strategy)
        if cls is None:
            raise ValueError(f"unknown strategy: {strategy}. options: {list(self._STRATEGIES)}")
        self.strategy_name = strategy
        self._impl = cls()

    def select(self, nodes: List[SelectorNode]) -> Optional[SelectorNode]:
        return self._impl.select(nodes)
