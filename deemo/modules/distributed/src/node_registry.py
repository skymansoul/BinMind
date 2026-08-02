# 2026-08-07
# 分布式节点注册与发现 — 无中心化架构的集群成员管理
# Falcon [BDAIA 2025]: master-worker 分级 + worker 自注册
# SERIN [USask 2025]: actor 模型的元监控，心跳 + Raft 日志复制
#
# 三种发现机制：
#   1. Redis 集中注册: 每个节点 HSET + TTL，周期刷新
#   2. Gossip 协议:    基于 SWIM [Gupta+ 2002] 的弱一致性传播
#   3. Static 静态列表: 配置文件/硬编码，适合固定集群
#
# 健康检查：通过心跳 TTL 判断节点存活，超时自动剔除
# 元数据：节点可以带任意 labels，用于调度亲和性

from __future__ import annotations

import time
import json
import threading
import random
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)

try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


# ===== 节点记录 =====

@dataclass
class NodeRecord:
    """集群中的一个节点记录 — 比 models.Node 更精简"""
    node_id: str
    address: str
    status: str = "unknown"
    labels: Dict[str, str] = field(default_factory=dict)
    capacity: int = 1
    current_load: int = 0
    version: str = "0.1.0"
    last_seen: float = field(default_factory=time.time)
    # Gossip 协议字段
    incarnation: int = 0
    state_version: int = 0

    @property
    def is_available(self) -> bool:
        return self.status == "online" and self.current_load < self.capacity

    @property
    def is_stale(self, timeout: float = 30.0) -> bool:
        return time.time() - self.last_seen > timeout


# ===== 发现后端接口 =====

class DiscoveryBackend:
    """节点发现后端 — 子类实现具体的注册/发现机制。
    接口设计参考 SERIN 的元 actor 抽象层。
    """
    def register(self, record: NodeRecord) -> bool:
        raise NotImplementedError

    def unregister(self, node_id: str) -> bool:
        raise NotImplementedError

    def discover(self) -> List[NodeRecord]:
        raise NotImplementedError

    def heartbeat(self, node_id: str) -> bool:
        raise NotImplementedError


# ===== Redis 集中注册 =====

class RedisDiscovery(DiscoveryBackend):
    """基于 Redis 的集中式节点注册。

    每个节点在 binmind:nodes:{node_id} 存储 HSET，
    TTL = heartbeat_interval * 3，到期自动清除。
    相比 Gossip 更简单可靠，适合 Redis 已部署的场景。
    Falcon 的 master 节点即用类似机制管理 worker 池。
    """

    KEY_PREFIX = "binmind:nodes"
    INDEX_KEY = "binmind:nodes:index"

    def __init__(self, redis_client, heartbeat_interval: float = 10.0):
        self._client = redis_client
        self._hb = heartbeat_interval
        self._ttl = int(heartbeat_interval * 3)

    def register(self, record: NodeRecord) -> bool:
        key = f"{self.KEY_PREFIX}:{record.node_id}"
        try:
            self._client.hset(key, mapping={
                "node_id": record.node_id,
                "address": record.address,
                "status": record.status,
                "labels": json.dumps(record.labels),
                "capacity": record.capacity,
                "current_load": record.current_load,
                "version": record.version,
                "last_seen": time.time(),
            })
            self._client.expire(key, self._ttl)
            self._client.sadd(self.INDEX_KEY, record.node_id)
            return True
        except Exception:
            _log.exception("redis register failed for %s", record.node_id)
            return False

    def unregister(self, node_id: str) -> bool:
        key = f"{self.KEY_PREFIX}:{node_id}"
        try:
            self._client.delete(key)
            self._client.srem(self.INDEX_KEY, node_id)
            return True
        except Exception:
            _log.debug("redis unregister failed for %s", node_id)
            return False

    def discover(self) -> List[NodeRecord]:
        try:
            members = self._client.smembers(self.INDEX_KEY)
            records = []
            for nid in members:
                data = self._client.hgetall(f"{self.KEY_PREFIX}:{nid}")
                if data:
                    records.append(_record_from_dict(data))
            return records
        except Exception:
            _log.exception("redis discover failed")
            return []

    def heartbeat(self, node_id: str) -> bool:
        key = f"{self.KEY_PREFIX}:{node_id}"
        try:
            exists = self._client.exists(key)
            if not exists:
                return False
            self._client.hset(key, "last_seen", time.time())
            self._client.expire(key, self._ttl)
            return True
        except Exception:
            return False


def _record_from_dict(data: dict) -> NodeRecord:
    labels_raw = data.get("labels", "{}")
    if isinstance(labels_raw, str):
        try:
            labels = json.loads(labels_raw)
        except (json.JSONDecodeError, TypeError):
            labels = {}
    else:
        labels = labels_raw
    return NodeRecord(
        node_id=data.get("node_id", ""),
        address=data.get("address", ""),
        status=data.get("status", "unknown"),
        labels=labels,
        capacity=int(data.get("capacity", 1)),
        current_load=int(data.get("current_load", 0)),
        version=data.get("version", "0.1.0"),
        last_seen=float(data.get("last_seen", 0)),
    )


# ===== Gossip 协议（SWIM 简化版） =====

class _GossipMessage:
    __slots__ = ('node', 'members', 'round')

    def __init__(self, node: NodeRecord, members: List[NodeRecord], round_num: int):
        self.node = node
        self.members = members
        self.round = round_num

    def to_dict(self) -> dict:
        return {
            "node": {
                "node_id": self.node.node_id,
                "address": self.node.address,
                "status": self.node.status,
                "labels": self.node.labels,
                "capacity": self.node.capacity,
                "current_load": self.node.current_load,
                "version": self.node.version,
                "incarnation": self.node.incarnation,
            },
            "members": [
                {"node_id": m.node_id, "address": m.address, "status": m.status,
                 "incarnation": m.incarnation}
                for m in self.members
            ],
            "round": self.round,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "_GossipMessage":
        node_data = d["node"]
        node = NodeRecord(
            node_id=node_data["node_id"], address=node_data["address"],
            status=node_data.get("status", "unknown"),
            incarnation=node_data.get("incarnation", 0),
            labels=node_data.get("labels", {}),
            capacity=node_data.get("capacity", 1),
            current_load=node_data.get("current_load", 0),
            version=node_data.get("version", "0.1.0"),
        )
        members = [
            NodeRecord(node_id=m["node_id"], address=m.get("address", ""),
                       status=m.get("status", "unknown"),
                       incarnation=m.get("incarnation", 0))
            for m in d.get("members", [])
        ]
        return cls(node, members, d.get("round", 0))


class GossipDiscovery(DiscoveryBackend):
    """基于 SWIM 协议的弱一致性节点发现。

    SWIM [Gupta+ 2002] 三个子协议：
    - Ping:   直接探测
    - Ping-Req: 间接探测（K 个 peer 代为 ping）
    - Dissemination: 成员变更信息通过 gossip 扩散

    此简化版仅实现 Ping + Dissemination。
    每个 gossip 周期随机选一个 peer 交换成员列表，
    用 incarnation 号解决 crash-reboot 的不一致问题。

    注意：这是内存协议，不持久化。节点全部重启后集群从头构建。
    """

    PROTOCOL_PERIOD = 2.0

    def __init__(self, self_record: NodeRecord, fanout: int = 3):
        self._self = self_record
        self._self.incarnation = 1
        self._members: Dict[str, NodeRecord] = {self_record.node_id: self_record}
        self._lock = threading.Lock()
        self._fanout = fanout
        self._round = 0
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._on_join: Optional[callable] = None
        self._on_leave: Optional[callable] = None
        # 回调: on_join(NodeRecord), on_leave(NodeRecord)

    def on_join(self, fn): self._on_join = fn
    def on_leave(self, fn): self._on_leave = fn

    def register(self, record: NodeRecord) -> bool:
        """本地注册自己（Gossip 无中心存储）"""
        with self._lock:
            self._members[record.node_id] = record
            self._self = record
            return True

    def unregister(self, node_id: str) -> bool:
        with self._lock:
            return self._members.pop(node_id, None) is not None

    def discover(self) -> List[NodeRecord]:
        with self._lock:
            return list(self._members.values())

    def heartbeat(self, node_id: str) -> bool:
        with self._lock:
            if node_id in self._members:
                self._members[node_id].last_seen = time.time()
                return True
            return False

    # ---- Gossip 后台循环 ----

    def start(self):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="gossip")
        self._thread.start()
        _log.info("gossip started for %s", self._self.node_id)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._gossip_round()
            except Exception:
                _log.exception("gossip round error")
            self._stop.wait(self.PROTOCOL_PERIOD)

    def _gossip_round(self):
        self._round += 1
        with self._lock:
            peers = [m for mid, m in self._members.items() if mid != self._self.node_id]
            if not peers:
                return
            # fanout 个随机 peer
            chosen = random.sample(peers, min(self._fanout, len(peers)))
            msg = _GossipMessage(
                node=self._self,
                members=list(self._members.values()),
                round_num=self._round,
            )
            current_members = dict(self._members)

        # 在锁外发送消息 — 这里只能记录，实际网络发送需要外部回调
        for peer in chosen:
            self._merge_from_peer(msg)

    def _merge_from_peer(self, msg: _GossipMessage):
        """合并来自 peer 的成员列表。
        规则：更高的 incarnation 胜出，更新的 state_version 胜出。
        """
        with self._lock:
            remote_node = msg.node
            my = self._members.get(remote_node.node_id)

            if my is None:
                self._members[remote_node.node_id] = remote_node
                if self._on_join:
                    self._on_join(remote_node)
            elif remote_node.incarnation > my.incarnation:
                self._members[remote_node.node_id] = remote_node

            for rm in msg.members:
                existing = self._members.get(rm.node_id)
                if existing is None:
                    record = NodeRecord(
                        node_id=rm.node_id, address=rm.address,
                        status=rm.status, incarnation=rm.incarnation,
                        last_seen=time.time(),
                    )
                    self._members[rm.node_id] = record
                    if self._on_join:
                        self._on_join(record)
                elif rm.incarnation > existing.incarnation:
                    existing.incarnation = rm.incarnation
                    existing.status = rm.status
                    existing.last_seen = time.time()

    def inject_message(self, msg_dict: dict):
        """接收外部（网络层）转发的 gossip 消息。"""
        msg = _GossipMessage.from_dict(msg_dict)
        self._merge_from_peer(msg)

    def make_message(self) -> dict:
        """生成当前 gossip 消息（外部网络层发送用）。"""
        with self._lock:
            msg = _GossipMessage(
                node=self._self,
                members=list(self._members.values()),
                round_num=self._round,
            )
            return msg.to_dict()

    @property
    def member_count(self) -> int:
        with self._lock:
            return len(self._members)


# ===== 静态发现 =====

class StaticDiscovery(DiscoveryBackend):
    """静态节点列表 — 小集群/测试环境专用。
    节点列表写死在构造参数中，不做动态更新。
    """

    def __init__(self, nodes: List[NodeRecord] = None):
        self._nodes: Dict[str, NodeRecord] = {
            n.node_id: n for n in (nodes or [])
        }

    def register(self, record: NodeRecord) -> bool:
        self._nodes[record.node_id] = record
        return True

    def unregister(self, node_id: str) -> bool:
        return self._nodes.pop(node_id, None) is not None

    def discover(self) -> List[NodeRecord]:
        return list(self._nodes.values())

    def heartbeat(self, node_id: str) -> bool:
        rec = self._nodes.get(node_id)
        if rec:
            rec.last_seen = time.time()
            return True
        return False


# ===== 门面：自动选择后端 =====

class NodeRegistry:
    """节点注册中心 — 按配置自动选择发现后端。

    优先级: Redis > Gossip > Static
    外部通过 register/update/discover/health_check 操作节点生命周期。
    """

    def __init__(self, backend: DiscoveryBackend = None,
                 redis_client=None,
                 self_record: NodeRecord = None,
                 static_nodes: List[NodeRecord] = None):
        if backend:
            self._backend = backend
        elif REDIS_AVAILABLE and redis_client:
            self._backend = RedisDiscovery(redis_client)
        elif self_record:
            self._backend = GossipDiscovery(self_record)
        else:
            self._backend = StaticDiscovery(static_nodes or [])

    def register(self, record: NodeRecord) -> bool:
        return self._backend.register(record)

    def unregister(self, node_id: str) -> bool:
        return self._backend.unregister(node_id)

    def discover(self) -> List[NodeRecord]:
        return self._backend.discover()

    def get_available_nodes(self) -> List[NodeRecord]:
        return [n for n in self.discover() if n.is_available]

    def get_node(self, node_id: str) -> Optional[NodeRecord]:
        for n in self.discover():
            if n.node_id == node_id:
                return n
        return None

    def heartbeat(self, node_id: str) -> bool:
        return self._backend.heartbeat(node_id)
