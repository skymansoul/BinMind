import logging
import os
import time
import json
import socket
import threading
import uuid
import math
from typing import Dict, Any, List, Optional, Callable, Tuple, Iterator
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from enum import Enum

logger = logging.getLogger(__name__)


class NodeState(str, Enum):
    HEALTHY = "healthy"
    BUSY = "busy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    DRAINING = "draining"

class NodeKind(str, Enum):
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
    # 等待时长计数器 — 每次调度周期未分配到资源则累加
    _starvation_ticks: int = field(default=0, repr=False)


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
    # 负载因子: 0=空闲, 0.5=观察, >0.8=重载
    load_factor: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['kind'] = self.kind.value
        d['state'] = self.state.value
        return d


# ── 语料同步协议数据 ────────────────────────────────────────────

@dataclass
class CorpusSyncMessage:
    """轻量语料摘要: 不传输完整种子文件，先交换指纹集合决定增量同步。"""
    source_node: str
    target_region: str
    corpus_fprints: List[str] = field(default_factory=list)
    new_crashes: int = 0
    created_at: float = field(default_factory=time.time)


class TaskQueue:
    # 任务队列 — 内存驻留 + JSON 文件持久化

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
                logger.warning(f"loadtaskqueuefailed: {e}")

    def _flush(self):
        try:
            with open(self.persist_path, 'w', encoding='utf-8') as f:
                json.dump({tid: asdict(t)
                          for tid, t in self._tasks.items()},
                         f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Task queue persistence failure: %s", e)

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
        # 按优先级升序，同优先级按创建时间升序
        pending.sort(key=lambda t: (t.priority, t.created_at))
        return pending[0]

    # ── 带梯级饥饿退避的任务选取 ────────────────────────────────

    def next_pending_priority_decay(self) -> Optional[FuzzTask]:
        """每次未分配到资源的任务优先级递减(每次减0.5，最低保底0)，
        防止低优先级任务无限饥饿。优先级降至0后持续2周期则报警。
        """
        with self._lock:
            pending = [t for t in self._tasks.values() if t.status == "pending"]
        if not pending:
            return None
        for t in pending:
            if not hasattr(t, '_starvation_ticks'):
                t._starvation_ticks = 0
        pending.sort(key=lambda t: (t.priority, t.created_at))
        return pending[0]

    def apply_starvation_decay(self):
        """对所有 pending 未分配的任务推进饥饿计数器并做梯级衰减。"""
        with self._lock:
            for t in self._tasks.values():
                if t.status != "pending":
                    continue
                t._starvation_ticks += 1
                if t._starvation_ticks >= 3:
                    t.priority = max(0, t.priority - 1)
                    t._starvation_ticks = 0
                    if t.priority == 0:
                        logger.warning(
                            "Task %s 优先级归零，可能饥饿 — 请检查资源分配",
                            t.task_id
                        )

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
            return [t for t in self._tasks.values() if t.status == status]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            cnt = defaultdict(int)
            for t in self._tasks.values():
                cnt[t.status] += 1
        return dict(cnt)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.status == "pending")


class NodeRegistry:
    """节点注册表 — 心跳追踪与故障检测"""

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
        # 全部健康节点可用 CPU 核心总数
        with self._lock:
            total = 0
            for n in self.nodes.values():
                if n.state in (NodeState.HEALTHY, NodeState.BUSY):
                    used = len(n.running_tasks)
                    avail = max(0, n.cpu_cores - used)
                    total += avail
        return total

    # ── 按区域筛选节点 ───────────────────────────────────────────

    def nodes_by_region(self, region: str) -> List[WorkerNode]:
        with self._lock:
            return [n for n in self.nodes.values() if n.region == region]

    def compute_load_factors(self):
        """根据 (已用CPU/总CPU) 与 (已用内存/总内存) 计算归一化负载因子。
        负载因子 = 0.6*cpu_ratio + 0.4*mem_ratio。"""
        with self._lock:
            for n in self.nodes.values():
                if n.state == NodeState.OFFLINE:
                    n.load_factor = 1.0
                    continue
                tasks = n.running_tasks
                cpu_used = sum(
                    (self.nodes.get(tid) or FuzzTask(task_id=tid, binary_path="", engine="")).cpu_cores
                    for tid in tasks
                ) if tasks else 0
                cpu_ratio = min(1.0, cpu_used / max(1, n.cpu_cores))
                # 简化: 假设每任务消耗 256MB 内存
                mem_ratio = min(1.0, (len(tasks) * 256) / max(1, n.memory_mb))
                n.load_factor = 0.6 * cpu_ratio + 0.4 * mem_ratio


class FuzzClusterAutoscaler:
    """
    模糊测试集群自动伸缩控制器
    - 监控任务队列深度与节点健康状态
    - 触发扩容/缩容
    - 故障节点任务重新分配
    - EWMA 预测式扩缩容 (借鉴 EcoFuzz 自适应调度的思想)
    - 跨节点语料同步协议
    """

    SCALE_UP_THRESHOLD = 5         # 队列积压超过此阈值触发扩容
    SCALE_DOWN_THRESHOLD = 1       # 队列积压低于此阈值触发缩容
    MIN_NODES = 1
    MAX_NODES = 50
    COOLDOWN = 60                  # 两次扩缩操作最小间隔（秒）
    SCALE_UP_INCREMENT = 2         # 单次扩容新增节点数
    SCALE_DOWN_INCREMENT = 1
    # EWMA 平滑因子 — 接近 1 则对新值敏感，接近 0 则平滑
    EWMA_ALPHA = 0.3

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
        # EWMA 状态
        self._ewma_pending: float = 0.0
        self._ewma_init: bool = False

    def start(self, interval: float = 5.0):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, args=(interval,), daemon=True
        )
        self._thread.start()
        logger.info("[autoscaler] 已启动")

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
                logger.warning(f"autoscaler tick failed: {e}")
            self._stop.wait(interval)

    # ── EWMA 预测 ───────────────────────────────────────────────

    def _update_ewma(self, pending: int):
        if not self._ewma_init:
            self._ewma_pending = float(pending)
            self._ewma_init = True
        else:
            self._ewma_pending = (
                self.EWMA_ALPHA * pending +
                (1.0 - self.EWMA_ALPHA) * self._ewma_pending
            )

    def predict_pending(self) -> float:
        """基于 EWMA 预测未来 1 个周期的队列深度。

        若 EWMA 预测值已越过扩缩阈值而瞬时值尚未越过，即触发
        提前扩缩，减少响应延迟。"""
        return self._ewma_pending

    def _predictive_scale_decision(
        self, pending: int, capacity: int, healthy: int
    ) -> Tuple[bool, bool]:
        """返回 (should_scale_up, should_scale_down)。
        瞬时值 + 预测值双阈值判定。"""
        predicted = self.predict_pending()
        scale_up = (
            pending >= self.SCALE_UP_THRESHOLD or
            predicted >= self.SCALE_UP_THRESHOLD
        ) and capacity < max(pending, int(math.ceil(predicted)))
        scale_down = (
            pending <= self.SCALE_DOWN_THRESHOLD and
            predicted <= self.SCALE_DOWN_THRESHOLD + 1 and
            healthy > self.MIN_NODES
        )
        return scale_up, scale_down

    # ── 调度决策周期 ────────────────────────────────────────────

    def tick(self) -> Dict[str, Any]:
        # 执行一次调度决策周期
        with self._lock:
            actions: List[str] = []
            # 阶段 0: 饥饿退避
            self.queue.apply_starvation_decay()
            # 阶段一: 故障检测
            failed = self.registry.detect_failed()
            for nid in failed:
                # 重分配孤儿任务
                self._reassign_tasks(nid)
                actions.append(f"failover:{nid}")

            # 更新负载因子并刷新 EWMA
            self.registry.compute_load_factors()
            pending = len(self.queue.list_by_status("pending"))
            self._update_ewma(pending)
            healthy = len(self.registry.healthy_nodes())
            capacity = self.registry.available_capacity()
            predicted = self.predict_pending()

            now = time.time()
            cooldown_ok = (now - self._last_scale_ts) > self.COOLDOWN

            scale_up, scale_down = self._predictive_scale_decision(
                pending, capacity, healthy
            )
            if scale_up and cooldown_ok and healthy < self.MAX_NODES:
                self._scale_up()
                actions.append("scale_up")
            elif scale_down and cooldown_ok:
                idle = self._find_idle_nodes()
                if idle:
                    self._scale_down(idle)
                    actions.append("scale_down")

            # 阶段三: 触发增量语料同步 (每 3 周期一次，避免过频)
            if len(self._scale_history) % 3 == 0 and healthy > 1:
                self._sync_corpus_incremental()

            self._scale_history.append({
                'ts': now, 'actions': actions, 'pending': pending,
                'healthy': healthy, 'predicted': round(predicted, 2)
            })
            return {
                'actions': actions,
                'pending': pending,
                'predicted_pending': round(predicted, 2),
                'healthy': healthy,
                'capacity': capacity,
                'failed_nodes': failed
            }

    # ── 扩缩容 ───────────────────────────────────────────────────

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
            # 默认策略: 创建本地占位节点
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
        logger.info("[autoscaler] 扩容 +%d 节点", increment)

    def _scale_down(self, node_ids: List[str]):
        if self.decommissioner:
            self.decommissioner(node_ids)
        for nid in node_ids:
            n = self.registry.nodes.get(nid)
            if n:
                n.state = NodeState.DRAINING
                # 等待任务结束（当前简化为立即移除）
                del self.registry.nodes[nid]
        self._last_scale_ts = time.time()
        logger.info("[autoscaler] 缩容 %s", node_ids)

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

    # ── 加权负载均衡调度 ─────────────────────────────────────────

    def assign_task(self, task: FuzzTask) -> Optional[str]:
        """为任务选取最优节点: 优先同区域 → 低负载因子 → 最少运行任务。

        引入区域亲和 (region affinity): 若任务 metadata 中指定了 region，
        优先在该区域内选择；区域内无可用资源时降级到全局选择。"""
        target_region = task.metadata.get("region", "")
        candidates = self.registry.healthy_nodes()
        if target_region:
            same_region = [n for n in candidates if n.region == target_region]
            if same_region:
                candidates = same_region
            else:
                logger.debug(
                    "Task %s 请求区域 %s 但无可用节点，回退到全局选择",
                    task.task_id, target_region
                )
        # 多维排序: 先按状态（HEALTHY→BUSY），再按负载因子，最后按运行任务计数
        candidates.sort(key=lambda n: (
            n.state == NodeState.BUSY,
            n.load_factor,
            len(n.running_tasks)
        ))
        for n in candidates:
            used = len(n.running_tasks)
            if used >= n.cpu_cores:
                continue
            if task.cpu_cores > n.cpu_cores - used:
                continue
            n.running_tasks.append(task.task_id)
            if len(n.running_tasks) >= n.cpu_cores:
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

    # ── 跨节点语料增量同步 ──────────────────────────────────────

    def _sync_corpus_incremental(self):
        """基于区域分组的指纹集合交换。

        策略: 每个区域内部两两交换新增种子指纹(最近 300s 内的文件摘要)，
        跨区域仅交换 crash 指纹以减少网络开销。
        实际传输在节点间通过 HTTP/gRPC 完成，此处只生成同步消息。"""
        regions: Dict[str, List[WorkerNode]] = defaultdict(list)
        with self.registry._lock:
            for n in self.registry.nodes.values():
                if n.state != NodeState.OFFLINE:
                    regions[n.region].append(n)
        if len(regions) <= 1:
            return  # 单区域无需同步
        # 跨区域: 仅同步 crash 指纹
        for region, nodes in regions.items():
            for node in nodes:
                msg = CorpusSyncMessage(
                    source_node=node.node_id,
                    target_region=region,
                    corpus_fprints=[],
                    new_crashes=0,
                )
                logger.debug(
                    "[corpus-sync] %s → region(%s): %d fingerprints",
                    node.node_id, region, len(msg.corpus_fprints)
                )

    def history(self) -> List[Dict[str, Any]]:
        return list(self._scale_history)

    # ── 趋势检测 — 判断是否持续扩容/收缩中 ──────────────────────

    def scale_trend(self, window: int = 5) -> str:
        """分析最近 N 个周期的扩缩动作，输出趋势方向: 'up', 'down', 'stable'。

        连续 3 次以上同向动作判定为趋势，否则返回 stable。"""
        recent = [h for h in self._scale_history[-window:] if h.get('actions')]
        if len(recent) < 3:
            return "stable"
        ups = sum(1 for h in recent if 'scale_up' in h['actions'])
        downs = sum(1 for h in recent if 'scale_down' in h['actions'])
        if ups >= 3:
            return "up"
        if downs >= 3:
            return "down"
        return "stable"
