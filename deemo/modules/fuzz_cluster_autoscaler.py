"""
分布式模糊测试集群自动弹性伸缩模块

功能:
    1. 基于 Kubernetes 或自研调度器, 根据待 fuzz 任务队列长度自动增减 worker 节点
    2. 支持混合云和本地节点
    3. 优先级抢占和节点故障转移

核心技术:
    - 任务队列 (RabbitMQ/Redis Streams/文件队列) 抽象
    - 节点注册与心跳
    - 自动扩缩容决策 (阈值 + 冷却时间)
    - 故障检测 (心跳超时) + 任务再分配
"""

import logging
import os
import time
import json
import socket
import threading
import uuid
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class NodeState(Enum):
    HEALTHY = "healthy"
    BUSY = "busy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    DRAINING = "draining"


class NodeKind(Enum):
    LOCAL = "local"
    CLOUD = "cloud"
    EDGE = "edge"


@dataclass
class FuzzTask:
    task_id: str
    binary_path: str
    engine: str
    priority: int = 5
    corpus_dir: str = ""
    timeout: int = 600
    cpu_cores: int = 1
    memory_mb: int = 1024
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    assigned_node: Optional[str] = None
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None


@dataclass
class WorkerNode:
    node_id: str
    host: str
    port: int
    kind: NodeKind
    cpu_cores: int = 4
    memory_mb: int = 8192
    state: NodeState = NodeState.HEALTHY
    last_heartbeat: float = field(default_factory=time.time)
    running_tasks: List[str] = field(default_factory=list)
    region: str = "local"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['kind'] = self.kind.value
        d['state'] = self.state.value
        return d


class TaskQueue:
    """任务队列 (内存 + 文件持久化)"""

    def __init__(self, persist_path: Optional[str] = None):
        self.persist_path = persist_path or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'fuzz_queue.json'
        )
        os.makedirs(os.path.dirname(self.persist_path), exist_ok=True)
        self._tasks: Dict[str, FuzzTask] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(self.persist_path):
            try:
                with open(self.persist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for tid, t in data.items():
                    self._tasks[tid] = FuzzTask(**t)
            except Exception as e:
                logger.warning(f"加载任务队列失败: {e}")

    def _flush(self):
        try:
            with open(self.persist_path, 'w', encoding='utf-8') as f:
                json.dump({tid: asdict(t)
                          for tid, t in self._tasks.items()},
                         f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"持久化任务队列失败: {e}")

    def submit(self, task: FuzzTask) -> str:
        with self._lock:
            self._tasks[task.task_id] = task
            self._flush()
        return task.task_id

    def next_pending(self) -> Optional[FuzzTask]:
        with self._lock:
            pending = [t for t in self._tasks.values() if t.status == "pending"]
        if not pending:
            return None
        # 按优先级升序, 时间升序
        pending.sort(key=lambda t: (t.priority, t.created_at))
        return pending[0]

    def update(self, task_id: str, **kwargs) -> bool:
        with self._lock:
            if task_id not in self._tasks:
                return False
            t = self._tasks[task_id]
            for k, v in kwargs.items():
                if hasattr(t, k):
                    setattr(t, k, v)
            self._flush()
        return True

    def list_by_status(self, status: str) -> List[FuzzTask]:
        with self._lock:
            return [t for t in self._tasks.values( if t.status == status])

    def stats(self) -> Dict[str, int]:
        with self._lock:
            cnt = defaultdict(int)
            for t in self._tasks.values():
                cnt[t.status] += 1
        return dict(cnt)


class NodeRegistry:
    """节点注册表"""

    HEARTBEAT_TIMEOUT = 30.0  # 秒

    def __init__(self):
        self.nodes: Dict[str, WorkerNode] = {}
        self._lock = threading.Lock()

    def register(self, node: WorkerNode) -> str:
        with self._lock:
            self.nodes[node.node_id] = node
        return node.node_id

    def heartbeat(self, node_id: str) -> bool:
        with self._lock:
            if node_id not in self.nodes:
                return False
            self.nodes[node_id].last_heartbeat = time.time()
            if self.nodes[node_id].state == NodeState.OFFLINE:
                self.nodes[node_id].state = NodeState.HEALTHY
        return True

    def detect_failed(self) -> List[str]:
        failed = []
        with self._lock:
            for nid, n in self.nodes.items():
                if n.state == NodeState.OFFLINE:
                    continue
                if time.time() - n.last_heartbeat > self.HEARTBEAT_TIMEOUT:
                    n.state = NodeState.OFFLINE
                    failed.append(nid)
        return failed

    def healthy_nodes(self) -> List[WorkerNode]:
        with self._lock:
            return [n for n in self.nodes.values()
                    if n.state in (NodeState.HEALTHY, NodeState.BUSY)]

    def available_capacity(self) -> int:
        """所有健康节点的可用 CPU 核心数总和"""
        with self._lock:
            total = 0
            for n in self.nodes.values():
                if n.state in (NodeState.HEALTHY, NodeState.BUSY):
                    used = len(n.running_tasks)
                    avail = max(0, n.cpu_cores - used)
                    total += avail
        return total


class FuzzClusterAutoscaler:
    """
    模糊测试集群自动伸缩控制器
    - 监控任务队列长度 + 节点健康
    - 触发扩容 / 缩容
    - 故障节点任务再分配
    """

    SCALE_UP_THRESHOLD = 5         # 队列长度超过此值触发扩容
    SCALE_DOWN_THRESHOLD = 1       # 队列长度低于此值触发缩容
    MIN_NODES = 1
    MAX_NODES = 50
    COOLDOWN = 60                  # 两次扩缩容之间最小间隔 (秒)
    SCALE_UP_INCREMENT = 2         # 一次扩容几个节点
    SCALE_DOWN_INCREMENT = 1

    def __init__(self, registry: Optional[NodeRegistry] = None,
                 queue: Optional[TaskQueue] = None,
                 node_provisioner: Optional[Callable[[int], List[WorkerNode]]] = None,
                 node_decommissioner: Optional[Callable[[List[str]], None]] = None):
        self.registry = registry or NodeRegistry()
        self.queue = queue or TaskQueue()
        self.provisioner = node_provisioner
        self.decommissioner = node_decommissioner
        self._last_scale_ts = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scale_history: deque = deque(maxlen=200)

    def start(self, interval: float = 5.0):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, args=(interval), daemon=True
        )
        self._thread.start()
        logger.info("[autoscaler] 启动")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self, interval: float):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:
                logger.warning(f"autoscaler tick 失败: {e}")
            self._stop.wait(interval)

    def tick(self) -> Dict[str, Any]:
        """执行一次调度决策"""
        with self._lock:
            actions: List[str] = []
            # 1. 故障检测
            failed = self.registry.detect_failed()
            for nid in failed:
                # 再分配任务
                self._reassign_tasks(nid)
                actions.append(f"failover:{nid}")
            # 2. 决策扩容/缩容
            pending = len(self.queue.list_by_status("pending"))
            healthy = len(self.registry.healthy_nodes())
            capacity = self.registry.available_capacity()
            now = time.time()
            cooldown_ok = (now - self._last_scale_ts) > self.COOLDOWN
            if pending >= self.SCALE_UP_THRESHOLD and capacity < pending and cooldown_ok:
                if healthy < self.MAX_NODES:
                    self._scale_up()
                    actions.append("scale_up")
            elif pending <= self.SCALE_DOWN_THRESHOLD and healthy > self.MIN_NODES and cooldown_ok:
                # 缩容: 找空闲节点
                idle = self._find_idle_nodes()
                if idle:
                    self._scale_down(idle)
                    actions.append("scale_down")
            self._scale_history.append({
                'ts': now, 'actions': actions, 'pending': pending,
                'healthy': healthy
            })
            return {
                'actions': actions,
                'pending': pending,
                'healthy': healthy,
                'capacity': capacity,
                'failed_nodes': failed
            }

    def _scale_up(self):
        increment = min(self.SCALE_UP_INCREMENT,
                        self.MAX_NODES - len(self.registry.nodes))
        if increment <= 0:
            return
        if self.provisioner:
            new_nodes = self.provisioner(increment)
            for n in new_nodes:
                self.registry.register(n)
        else:
            # 默认: 创建本地节点占位
            for i in range(increment):
                node = WorkerNode(
                    node_id=f"local-{uuid.uuid4().hex[:8]}",
                    host="127.0.0.1",
                    port=20000 + len(self.registry.nodes),
                    kind=NodeKind.LOCAL,
                    cpu_cores=4, memory_mb=8192
                )
                self.registry.register(node)
        self._last_scale_ts = time.time()
        logger.info(f"[autoscaler] 扩容 +{increment} 节点")

    def _scale_down(self, node_ids: List[str]):
        if self.decommissioner:
            self.decommissioner(node_ids)
        for nid in node_ids:
            n = self.registry.nodes.get(nid)
            if n:
                n.state = NodeState.DRAINING
                # 等待任务结束 (简化: 立即)
                del self.registry.nodes[nid]
        self._last_scale_ts = time.time()
        logger.info(f"[autoscaler] 缩容 {node_ids}")

    def _find_idle_nodes(self) -> List[str]:
        return [nid for nid, n in self.registry.nodes.items()
                if n.state == NodeState.HEALTHY and not n.running_tasks]

    def _reassign_tasks(self, failed_node_id: str):
        node = self.registry.nodes.get(failed_node_id)
        if not node:
            return
        for tid in node.running_tasks:
            t = self.queue.list_by_status("running")
            for tsk in t:
                if tsk.task_id == tid:
                    tsk.status = "pending"
                    tsk.assigned_node = None
                    tsk.started_at = None
                    self.queue.update(tsk.task_id, status="pending",
                                      assigned_node=None, started_at=None)
        node.running_tasks.clear()

    def assign_task(self, task: FuzzTask) -> Optional[str]:
        """为任务挑选一个节点"""
        nodes = sorted(
            self.registry.healthy_nodes(),
            key=lambda n: (n.state == NodeState.BUSY, len(n.running_tasks))
        )
        for n in nodes:
            used = len(n.running_tasks)
            if used >= n.cpu_cores:
                continue
            if task.cpu_cores > n.cpu_cores - used:
                continue
            n.running_tasks.append(task.task_id)
            n.state = NodeState.BUSY
            return n.node_id
        return None

    def complete_task(self, node_id: str, task_id: str,
                      result: Optional[Dict[str, Any]] = None):
        node = self.registry.nodes.get(node_id)
        if node and task_id in node.running_tasks:
            node.running_tasks.remove(task_id)
            if not node.running_tasks:
                node.state = NodeState.HEALTHY
        self.queue.update(task_id, status="completed",
                          finished_at=time.time(), result=result or {})

    def history(self) -> List[Dict[str, Any]]:
        return list(self._scale_history)
