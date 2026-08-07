"""Task scheduler for 分布式 符号执行

分割 a binary per-function analysis tasks, 分派
寄存器ed workers using pluggable 加载-balancing strategies (舍入-robin
least-loaded, adaptive, consistent-hash), aggregates results
重试逻辑 for transient failures

增强 — 一致性哈希：按 binary_path 的哈希映射任务到 worker，确保同一
二进制文件的多个函数在同一个 worker 上执行，利用 warm cache 效应
worker 亲和性加分：已完成某 binary 的 N 个任务的 worker 在下次调度
该 binary 时获得优先级加分

新增 — WorkerCapabilityRegistry：worker 注册时验证其声称的能力是否
真的可用（检查所需包的 import 是否成功），防止能力虚报导致的运行时错误
TaskDependencyResolver：基于 Kahn 拓扑排序的依赖解析器，未满足依赖的
任务暂存在 pending 队列中，依赖完成后自动释放
rebalance()：worker 加入/离开时重新均衡待处理任务的分配

DeadlineAwareDispatch：按 (task.deadline_ts -) 排序堆，deadline 最近的任务优先
WorkerScorecard：基于 {success_rate, avg_延迟, capability_match_ratio} 的 worker 质量评分
PartialResultMerger：超时/失败任务的中间结果回收合并，避免丢弃已探索路径
"""

import logging
import time
import hashlib
import threading
import json
import os
import heapq
import importlib
from typing import Dict, Any, List, Optional, Tuple, Callable, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TaskStatus:
    """Task lifecycle states"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class WorkerStatus:
    """Worker node states"""
    IDLE = "idle"
    BUSY = "busy"
    OFFLINE = "offline"
    DRAINING = "draining"


class LoadBalanceStrategy(Enum):
    """Dispatch policies for worker selection"""
    ROUND_ROBIN = "round_robin"
    CONSISTENT_HASH = "consistent_hash"
    LEAST_LOADED = "least_loaded"
    ADAPTIVE = "adaptive"


@dataclass
class SymbolicTask:
    """One function's symbolic analysis unit for 分布式 dispatch"""
    task_id: str
    binary_path: str
    func_name: str
    entry_addr: int = 0
    path_constraints: List = field(default_factory=list)
    max_states: int = 10000
    timeout_seconds: int = 300
    priority: int = 0
    dependencies: List = field(default_factory=list)
    assigned_worker: str = ""
    status: str = TaskStatus.PENDING
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    retry_count: int = 0
    max_retries: int = 3
    # 截止时间戳（UTC epoch 秒），用于 deadline-aware 调度
    deadline_ts: float = 0.0
    # 部分结果：任务超时/失败但已有中间产出时暂存于此
    partial_results: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Compact 序列化 for status reporting"""
        return {'task_id': self.task_id, 'func_name': self.func_name,
                'priority': self.priority, 'status': self.status,
                'assigned_worker': self.assigned_worker, 'retry_count': self.retry_count,
                'deadline_ts': self.deadline_ts}


@dataclass
class TaskResult:
    """Result returned a worker completing a task"""
    task_id: str
    success: bool
    paths_explored: int = 0
    vulnerabilities_found: int = 0
    new_constraints: List = field(default_factory=list)
    output: Dict = field(default_factory=dict)
    error: str = ""
    worker_id: str = ""
    elapsed_seconds: float = 0.0


@dataclass
class WorkerInfo:
    """Worker node registration 性能 metadata"""
    worker_id: str
    hostname: str = ""
    status: str = WorkerStatus.IDLE
    current_task: Optional[str] = None
    tasks_completed: int = 0
    tasks_failed: int = 0
    avg_task_time_ms: float = 0.0
    total_task_time_ms: float = 0.0
    cpu_cores: int = 1
    memory_mb: int = 1024
    last_heartbeat: float = 0.0
    capabilities: List = field(default_factory=list)
    binary_affinity: Dict[str, int] = field(default_factory=dict)

    def load_score(self) -> float:
        """Heuristic 加载: avg time per task weighted failure count
        OFFLINE workers 返回 infinity"""
        if self.status == WorkerStatus.OFFLINE:
            return float('inf')
        if self.status == WorkerStatus.IDLE:
            return 0.0
        return self.avg_task_time_ms / max(1, self.tasks_completed) * (1 + self.tasks_failed)

    def affinity_for(self, binary_path: str) -> int:
        """返回 worker 对特定 binary 的亲和度（已完成任务数）
        
        设计意图 — 同一 binary 的函数共享指令缓存和 angr project 对象
        亲和调度减少 worker 上的冷启动开销"""
        return self.binary_affinity.get(binary_path, 0)

    def success_rate(self) -> float:
        """Ratio completed tasks succeeded. 返回 1.0 tasks"""
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 1.0
        return self.tasks_completed / total

    def avg_latency_sec(self) -> float:
        """Average task execution time seconds"""
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 0.0
        return self.total_task_time_ms / 1000.0 / total


# WorkerScorecard — 基于多维指标的 worker 质量评分
#
# 评分由三个维度加权合成：
#   success_rate (40% 权重)：已完成任务的成功比例，反映稳定性
#   avg_latency (30% 权重)：归一化延迟（取倒数后 min-max 归一），反映速度
#   capability_match_ratio (30% 权重)：worker 能力与任务需求的匹配度
#
# 所有维度归一化到 [0, 1] 后加权求和。评分用于 dispatch 时打破
# load_score 相近情况下的 tie-breaking
#
# 注意：latency 是越小越好，因此取 1/(1+latency) 做正向化
class WorkerScorecard:
    """Per-worker quality score 基于 multi-dimensional metrics
    
    计算 a composite score {success_rate, avg_延迟
    capability_match_ratio}. Used weight dispatch decisions:
    higher-scoring workers preferred 加载 scores similar
    
    Formula: score = 0.4 * success_rate + 0.3 * 延迟_norm + 0.3 * capability_match
    延迟_norm = 1 / (1 + avg_延迟_sec) ranges ~0 (very slow)
    1.0 (instantaneous)
    """

    _SUCCESS_WEIGHT = 0.4
    _LATENCY_WEIGHT = 0.3
    _CAPABILITY_WEIGHT = 0.3

    def __init__(self):
        self._score_cache: Dict[str, float] = {}
        self._cache_ttl: float = 5.0

    def _normalize_latency(self, latency_sec: float) -> float:
        """正向化延迟：越接近 0 的延迟得分越接近 1.0"""
        return 1.0 / (1.0 + latency_sec)

    def compute(self, worker: WorkerInfo,
                required_capabilities: Optional[List[str]] = None) -> float:
        """计算 quality score for a worker
        
        Args:
        worker: WorkerInfo score
        required_capabilities: Optional list capability strings
        current task requires. Used 计算 capability_match_ratio
        
        返回:
        Float [0.0, 1.0], higher better
        """
        success = worker.success_rate()
        latency_norm = self._normalize_latency(worker.avg_latency_sec())

        # 能力匹配度：worker 具备的能力与任务需求的交集占比
        if required_capabilities and worker.capabilities:
            worker_caps = set(worker.capabilities)
            required = set(required_capabilities)
            cap_match = len(worker_caps & required) / max(1, len(required))
        else:
            cap_match = 1.0

        score = (self._SUCCESS_WEIGHT * success +
                 self._LATENCY_WEIGHT * latency_norm +
                 self._CAPABILITY_WEIGHT * cap_match)

        # 钳制 [0, 1]
        return max(0.0, min(1.0, score))

    def score_workers(self, workers: List[WorkerInfo],
                      required_capabilities: Optional[List[str]] = None
                      ) -> List[Tuple[WorkerInfo, float]]:
        """Score multiple workers 返回 sorted score descending
        
        Args:
        workers: List workers score
        required_capabilities: Optional required capabilities for task
        
        返回:
        List (WorkerInfo, score) tuples sorted highest score first
        """
        scored = [(w, self.compute(w, required_capabilities)) for w in workers]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored


# WorkerCapabilityRegistry — worker 能力验证注册表
#
# cap_registry 字典将能力字符串映射到验证所需的包名列表
# 注册 worker 时遍历其声称的能力，逐一尝试 import 对应的包
# 只将验证通过的能力标记为有效，防止 worker 虚报导致运行时
# ModuleNotFoundError。验证失败的能力记录警告日志但不阻止注册——
# worker 仍可处理不需要该能力的任务
class WorkerCapabilityRegistry:
    """校验s worker capability claims against actually installed packages
    
    cap_registry maps capability strings lists required Python packages
    寄存器_worker(), claimed capability 校验d attempting
    import required packages. verified capabilities accepted
    
    阻止"声称支持 angr 但未安装"的情况，避免任务分配到无能力 worker
    """

    def __init__(self):
        self.cap_registry: Dict[str, List[str]] = {
            'angr': ['angr'],
            'z3': ['z3'],
            'binaryninja': ['binaryninja'],
            'ghidra': ['ghidra_bridge'],
            'unicorn': ['unicorn'],
            'capstone': ['capstone'],
        }

    def register_capability(self, name: str, required_packages: List[str]):
        """Extend registry a custom capability"""
        self.cap_registry[name] = list(required_packages)

    def validate(self, claimed_capabilities: List[str]) -> Tuple[List[str], List[str]]:
        """校验 a list claimed capabilities
        
        返回:
        (valid_capabilities, invalid_capabilities) — two lists
        capability strings passed/failed import 验证
        """
        valid: List[str] = []
        invalid: List[str] = []
        for cap in claimed_capabilities:
            packages = self.cap_registry.get(cap)
            if packages is None:
                # 未知能力：保守拒绝
                logger.warning("[CapRegistry] Unknown capability '%s', rejecting", cap)
                invalid.append(cap)
                continue
            all_ok = True
            for pkg in packages:
                try:
                    importlib.import_module(pkg)
                except ImportError:
                    logger.warning("[CapRegistry] Capability '%s' requires '%s' which is not installed",
                                   cap, pkg)
                    all_ok = False
                    break
            if all_ok:
                valid.append(cap)
            else:
                invalid.append(cap)
        return valid, invalid


# TaskDependencyResolver — 基于 Kahn 算法的拓扑依赖解析
#
# 有未满足依赖的任务不进入主调度堆，而是暂存在 _pending_dep 中
# 每当一个任务标记为完成，检查所有等待该任务的其他任务：
# 如果某个等待任务的 dep_dag_in_degree 降为 0，将其释放到主调度器
#
# dep_dag_in_degree 记录每个 task_id 的未完成前驱数量
# pending_dep 是反向索引：前驱 task_id → 依赖它的任务列表
class TaskDependencyResolver:
    """Topological 排序 via Kahn's algorithm for dependency-aware scheduling
    
    Tasks unfulfilled dependencies held a pending_dep 队列
    until prerequisite tasks complete
    
    dep_dag_in_degree 追踪 incomplete predecessors task
    _pending_dep a reverse index: predecessor_task_id -> list dependent tasks
    """

    def __init__(self):
        self.dep_dag_in_degree: Dict[str, int] = {}
        self._pending_dep: Dict[str, List[SymbolicTask]] = {}
        self._completed: Set[str] = set()
        self._task_by_id: Dict[str, SymbolicTask] = {}

    def register(self, task: SymbolicTask):
        """寄存器 a task dependency resolver
        
        task dependencies (in_degree == 0), immediately
        ready. Otherwise, held _pending_dep until predecessors
        complete
        """
        self._task_by_id[task.task_id] = task
        deps = task.dependencies if task.dependencies else []
        self.dep_dag_in_degree[task.task_id] = len(deps)
        for dep_id in deps:
            if dep_id not in self._pending_dep:
                self._pending_dep[dep_id] = []
            self._pending_dep[dep_id].append(task)

    def is_ready(self, task_id: str) -> bool:
        """返回 True task remaining unfulfilled dependencies"""
        return self.dep_dag_in_degree.get(task_id, -1) == 0

    def mark_completed(self, task_id: str) -> List[SymbolicTask]:
        """Mark a task completed 释放 tasks waiting
        
        返回:
        List SymbolicTask instances ready 调度
        (in_degree dropped 0)
        """
        self._completed.add(task_id)
        ready: List[SymbolicTask] = []
        dependents = self._pending_dep.pop(task_id, [])
        for dep_task in dependents:
            if dep_task.task_id in self.dep_dag_in_degree:
                self.dep_dag_in_degree[dep_task.task_id] -= 1
                if self.dep_dag_in_degree[dep_task.task_id] == 0:
                    ready.append(dep_task)
        return ready

    def pending_count(self) -> int:
        """返回 number tasks currently blocked dependencies"""
        return sum(1 for deg in self.dep_dag_in_degree.values() if deg > 0)

    def reset(self):
        """清除 dependency state"""
        self.dep_dag_in_degree.clear()
        self._pending_dep.clear()
        self._completed.clear()
        self._task_by_id.clear()


# DeadlineAwareDispatch — 按 deadline 排序的任务调度堆
#
# 标准 TaskScheduler 按 (-priority, created_at) 排序堆。DeadlineAwareDispatch
# 覆写此逻辑：堆内每个条目的排序键改为 (is_overdue, deadline_slack, -priority)
#
# is_overdue 是布尔值（False=0 在前，True=1 在后），确保逾期的任务排最前
# deadline_slack = deadline_ts - now，负数越大（越逾期）排越前。
# 无 deadline 的任务（deadline_ts == 0）slack 视为 +inf，排在最后
#
# 这防止了超时级联效应：当一批任务共享截止时间且调度延迟时
# 最临近 deadline 的任务优先执行，最大化截止时间内完成的任务数
class DeadlineAwareDispatch:
    """排序 task 堆 deadline proximity tasks closest deadline
    dispatched first, preventing timeout cascades
    
    Overrides standard priority-based ordering a composite key:
    (is_overdue, deadline_slack, -priority). Tasks a deadline
    (deadline_ts == 0) treated having infinite slack
    
    使用方式：将 堆 key 函数注入 TaskScheduler._堆_key(task)
    替代默认的 (-priority, created_at, task_id)
    """

    def __init__(self):
        self._now_func: Callable[[], float] = time.time

    def set_clock(self, now_func: Callable[[], float]):
        """Inject a custom clock for testing (e.g. freezegun)"""
        self._now_func = now_func

    def heap_key(self, task: SymbolicTask) -> Tuple[int, float, int, float, str]:
        """计算 堆 ordering key for a task
        
        返回:
        Tuple (is_overdue, deadline_slack, negative_priority, created_at, task_id)
        suitable for 堆q. Lower values = higher dispatch priority
        """
        now = self._now_func()
        if task.deadline_ts > 0:
            slack = task.deadline_ts - now
            is_overdue = 0 if slack <= 0 else 1
        else:
            slack = float('inf')
            is_overdue = 1  # 无 deadline 的任务不优先

        return (is_overdue, slack, -task.priority, task.created_at, task.task_id)

    @staticmethod
    def from_deadline(task: SymbolicTask) -> float:
        """返回 remaining time deadline seconds
        
        Negative values indicate deadline passed
        返回 inf deadline set
        """
        if task.deadline_ts <= 0:
            return float('inf')
        return task.deadline_ts - time.time()


# PartialResultMerger — 超时/失败任务的中间结果回收
#
# 设计意图：分布式环境中的任务可能因为瞬态故障（网络分区、worker OOM）
# 而失败，但在此之前已经探索了大量路径。丢弃这些已探索的路径是浪费
# ——PartialResultMerger 从失败任务的 partial_results 中回收
# paths_explored、vulnerabilities_found、new_constraints 等中间产出
# 合并到最终聚合报告中
#
# 回收策略：
# paths 直接累加
# vulnerabilities 去重（按函数名 + 漏洞类型合并）
# constraints 去重（按字符串哈希去重）
# output 字段浅合并（同名键后面的覆盖前面的）
class PartialResultMerger:
    """Salvage intermediate results timed-out or failed tasks 合并
    final aggregate instead discarding
    
    a task times out or fails partial completion, worker
    explored paths discovered constraints
    merger collects partial results folds
    overall ResultAggregator totals
    """

    def __init__(self):
        self._partial_paths: Dict[str, int] = {}  # task_id -> paths
        self._partial_vulns: Dict[str, List[Dict[str, Any]]] = {}  # task_id -> vuln list
        self._partial_constraints: Dict[str, Set[str]] = {}  # task_id -> constraint hash set
        self._partial_outputs: Dict[str, Dict[str, Any]] = {}  # task_id -> 输出 dict

    def record_partial(self, task: SymbolicTask):
        """Capture partial results a task marked
        timed out or failed
        
        Args:
        task: SymbolicTask partial_results field 包含
        intermediate findings
        """
        partial = task.partial_results
        if not partial:
            return

        tid = task.task_id
        paths = partial.get('paths_explored', 0)
        vulns = partial.get('vulnerabilities', [])
        constraints = partial.get('new_constraints', [])
        output = partial.get('output', {})

        if paths > 0:
            self._partial_paths[tid] = self._partial_paths.get(tid, 0) + paths
        if vulns:
            if tid not in self._partial_vulns:
                self._partial_vulns[tid] = []
            self._partial_vulns[tid].extend(vulns)
        if constraints:
            if tid not in self._partial_constraints:
                self._partial_constraints[tid] = set()
            for c in constraints:
                self._partial_constraints[tid].add(hash(str(c)))
        if output:
            if tid not in self._partial_outputs:
                self._partial_outputs[tid] = {}
            self._partial_outputs[tid].update(output)

        logger.info("[PartialMerger] Captured partial from task %s: "
                     "%d paths, %d vulns, %d constraints",
                     tid, paths, len(vulns), len(constraints))

    def merge_into_aggregate(self, aggregate: Dict[str, Any]) -> Dict[str, Any]:
        """合并 accumulated partial results an aggregate summary dict
        
        Args:
        aggregate: aggregate dict produced ResultAggregator
        Modified -place returned
        
        返回:
        same aggregate dict, partial results merged
        """
        total_partial_paths = sum(self._partial_paths.values())
        if total_partial_paths > 0:
            aggregate['total_paths_explored'] = (
                aggregate.get('total_paths_explored', 0) + total_partial_paths)
            aggregate['partial_paths_salvaged'] = total_partial_paths

        # 合并漏洞（去重）
        all_vulns: Dict[str, Dict[str, Any]] = {}
        for tid, vuln_list in self._partial_vulns.items():
            for vuln in vuln_list:
                vkey = f"{vuln.get('func_name', '')}:{vuln.get('type', '')}:{vuln.get('address', '')}"
                all_vulns[vkey] = vuln
        if all_vulns:
            existing = aggregate.get('total_vulnerabilities', 0)
            aggregate['total_vulnerabilities'] = existing + len(all_vulns)
            aggregate['partial_vulns_salvaged'] = len(all_vulns)

        # 合并约束计数
        all_constraints: Set[str] = set()
        for tid, cset in self._partial_constraints.items():
            all_constraints.update(cset)
        if all_constraints:
            aggregate['partial_constraints_salvaged'] = len(all_constraints)

        logger.info("[PartialMerger] Merged partial results: +%d paths, +%d vulns, +%d constraints",
                     total_partial_paths, len(all_vulns), len(all_constraints))

        return aggregate

    def clear(self):
        """重置 accumulated partial results"""
        self._partial_paths.clear()
        self._partial_vulns.clear()
        self._partial_constraints.clear()
        self._partial_outputs.clear()


class TaskScheduler:
    """Priority-队列-based task 分发器 pluggable 负载均衡
    支持 deadline-aware dispatch via DeadlineAwareDispatch 堆 keys
    
    增强：deadline-aware 排序 —— 当 enable_deadline_dispatch=True 时
    _heap_key 使用 DeadlineAwareDispatch 计算堆键，确保最临近截止时间的
    任务优先被调度
    """

    # rebalance_threshold：worker 数量变化超过此比例时触发自动再平衡
    _DEFAULT_REBALANCE_THRESHOLD = 0.3

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.ADAPTIVE):
        self.strategy = strategy
        self._task_heap: List[Tuple] = []
        self._workers: Dict[str, WorkerInfo] = {}
        self._task_cache: Dict[str, SymbolicTask] = {}
        self._lock = threading.Lock()
        self._round_robin_pos = 0
        self._cons_hash_ring: List[Tuple[int, str]] = []
        self.rebalance_threshold: float = self._DEFAULT_REBALANCE_THRESHOLD
        self._last_worker_count: int = 0
        self._dependency_resolver = TaskDependencyResolver()
        self._scorecard = WorkerScorecard()
        self._partial_merger = PartialResultMerger()
        self._deadline_dispatcher = DeadlineAwareDispatch()
        self.enable_deadline_dispatch: bool = True

    @property
    def dependency_resolver(self) -> TaskDependencyResolver:
        """Expose dependency resolver for external inspection"""
        return self._dependency_resolver

    @property
    def scorecard(self) -> WorkerScorecard:
        """Expose worker scorecard for external inspection"""
        return self._scorecard

    @property
    def partial_merger(self) -> PartialResultMerger:
        """Expose partial result merger for external inspection"""
        return self._partial_merger

    def register_worker(self, worker: WorkerInfo):
        """Add or 更新 a worker 池"""
        with self._lock:
            prev_count = len(self._workers)
            self._workers[worker.worker_id] = worker
            self._rebuild_cons_hash_ring()
            # worker 数量变化超过阈值时触发自动再平衡
            new_count = len(self._workers)
            if prev_count > 0 and self._should_rebalance(prev_count, new_count):
                self._rebalance_locked()

    def unregister_worker(self, worker_id: str):
        """Remove a worker 池"""
        with self._lock:
            prev_count = len(self._workers)
            self._workers.pop(worker_id, None)
            self._rebuild_cons_hash_ring()
            new_count = len(self._workers)
            if prev_count > 0 and self._should_rebalance(prev_count, new_count):
                self._rebalance_locked()

    def _should_rebalance(self, old_count: int, new_count: int) -> bool:
        """判断 worker 数量变化是否超过 rebalance_threshold
        
        变化比例 = |new - old| / max(old, 1)，超过阈值则返回 True
        这避免了每增减一个 worker 都触发昂贵的再平衡操作
        """
        if old_count == 0:
            return False
        change_ratio = abs(new_count - old_count) / max(old_count, 1)
        return change_ratio >= self.rebalance_threshold

    # rebalance — worker 加入/离开时重新均衡待处理任务
    #
    # 当 worker 拓扑变化超过 rebalance_threshold 时自动调用
    # 策略：将堆中所有 PENDING 任务弹出、重置 assigned_worker
    # 然后按当前 worker 集合重新入堆。一致性哈希环在
    # _rebuild_cons_hash_ring 中已更新，下次 dispatch 会使用新映射
    #
    # 设计权衡：完全不移动已 ASSIGNED/RUNNING 的任务（避免中断进行中的工作）
    # 只重排尚未分配的任务
    def _rebalance_locked(self):
        """Internal rebalance under lock. 调用方必须持有 self._lock"""
        if not self._task_heap:
            return
        # 收集所有 PENDING 状态的任务
        pending_tasks: List[SymbolicTask] = []
        remaining: List[Tuple] = []
        for entry in self._task_heap:
            # entry 可能是 3 元组 (旧格式) 或 5 元组 (deadline 格式)
            tid = entry[-1]  # task_id 始终在最后
            task = self._task_cache.get(tid)
            if task and task.status == TaskStatus.PENDING:
                task.assigned_worker = ""
                pending_tasks.append(task)
            else:
                remaining.append(entry)
        if not pending_tasks:
            return
        # 重置堆，只保留非 PENDING 条目
        self._task_heap = remaining
        heapq.heapify(self._task_heap)
        # 将 PENDING 任务重新入堆（使用当前时间戳，打乱创建顺序以促进均衡）
        for task in pending_tasks:
            key = self._heap_key(task)
            heapq.heappush(self._task_heap, key)
        logger.info("[Scheduler] Rebalanced %d pending tasks across %d workers",
                    len(pending_tasks), len(self._workers))

    def rebalance(self):
        """Public 入口: redistribute pending tasks across current workers
        
        当 检测 到 worker 加入/离开（是 stale eviction）时
        外部调用方可以通过此方法手动触发再平衡
        """
        with self._lock:
            self._rebalance_locked()

    # 一致性哈希环：每个 worker 映射到环上的 128 个虚拟节点
    # 按 binary_path hash 查找顺时针方向最近的节点
    # 虚拟节点数选 128 是因为在 worker 数量 < 50 时能将负载偏差
    # 控制在 5% 以内（根据 Karger et al. 的理论分析）
    _VIRTUAL_NODES = 128

    def _rebuild_cons_hash_ring(self):
        ring = []
        for wid in self._workers:
            for v in range(self._VIRTUAL_NODES):
                h = hashlib.md5(f"{wid}:v{v}".encode()).hexdigest()
                ring.append((int(h, 16), wid))
        ring.sort(key=lambda x: x[0])
        self._cons_hash_ring = ring

    def _cons_hash_pick(self, binary_path: str) -> Optional[str]:
        if not self._cons_hash_ring:
            return None
        h = int(hashlib.md5(binary_path.encode()).hexdigest(), 16)
        for ring_hash, wid in self._cons_hash_ring:
            if ring_hash >= h:
                return wid
        return self._cons_hash_ring[0][1]

    # 堆键计算：deadline-aware 模式 vs 传统 priority 模式
    #
    # 当 enable_deadline_dispatch=True 时，使用 DeadlineAwareDispatch
    # 计算 5 元组堆键；否则使用传统 3 元组
    # task_id 始终在最后，便于 rebalance 中按 entry[-1] 提取
    def _heap_key(self, task: SymbolicTask) -> Tuple:
        """计算 堆 ordering key for a task
        
        如果 deadline-aware 模式开启且有 deadline_ts，按 deadline slack 排序；
        否则回退到传统的 (-priority, created_at, task_id)
        """
        if self.enable_deadline_dispatch and task.deadline_ts > 0:
            return self._deadline_dispatcher.heap_key(task)
        return (-task.priority, task.created_at, task.task_id)

    def submit(self, task: SymbolicTask):
        """En队列 a task. 使用 堆q for O(记录 n) operations
        
        有依赖的任务先经过 TaskDependencyResolver：如果入度 > 0
        不进入主堆，而是注册到依赖解析器等待前置任务完成
        """
        task.created_at = time.time()
        with self._lock:
            self._task_cache[task.task_id] = task
            # 依赖检查：有未满足依赖的任务暂不进入主调度堆
            deps = task.dependencies if task.dependencies else []
            if deps:
                self._dependency_resolver.register(task)
                if not self._dependency_resolver.is_ready(task.task_id):
                    logger.debug("[Scheduler] Task %s deferred: waiting on %d dependencies",
                                 task.task_id, len(deps))
                    return
                # 入度为 0（依赖已全部完成），可以进入主堆
            key = self._heap_key(task)
            heapq.heappush(self._task_heap, key)

    def _release_ready_dependents(self, completed_task_id: str):
        """当一个任务完成时，释放所有等待它的就绪任务到主堆
        
        调用方必须持有 self._lock"""
        ready_tasks = self._dependency_resolver.mark_completed(completed_task_id)
        for rt in ready_tasks:
            if rt.task_id not in self._task_cache:
                self._task_cache[rt.task_id] = rt
            rt.created_at = rt.created_at or time.time()
            key = self._heap_key(rt)
            heapq.heappush(self._task_heap, key)
            logger.debug("[Scheduler] Dependency resolved: task %s is now ready", rt.task_id)

    def dispatch(self) -> Optional[Tuple[SymbolicTask, WorkerInfo]]:
        """De队列 highest-priority task assign a worker
        使用 deadline-aware ordering enabled
        
        Worker selection weighted WorkerScorecard multiple
        candidates similar 加载 scores (10% tolerance)
        """
        with self._lock:
            if not self._task_heap:
                return None
            worker = self._select_worker()
            if not worker:
                return None
            entry = heapq.heappop(self._task_heap)
            task_id = entry[-1]  # task_id 始终在元组最后
            task = self._task_cache.get(task_id)
            if not task:
                return None
            # deadline 检查：超时任务标记但回收部分结果
            if time.time() - task.created_at > task.timeout_seconds * 2:
                task.status = TaskStatus.TIMED_OUT
                self._partial_merger.record_partial(task)
                return None
            task.assigned_worker = worker.worker_id
            task.status = TaskStatus.ASSIGNED
            task.started_at = time.time()
            worker.current_task = task_id
            worker.status = WorkerStatus.BUSY
            return (task, worker)

    def complete_task(self, task_id: str, result: TaskResult):
        """Mark a task complete 更新 worker 性能 counters
        
        failure or timeout, partial results salvaged via
        PartialResultMerger task optionally re队列d
        """
        with self._lock:
            task = self._task_cache.get(task_id)
            worker = self._workers.get(result.worker_id)
            if task:
                if result.success:
                    task.status = TaskStatus.COMPLETED
                else:
                    task.status = TaskStatus.FAILED
                    # 回收部分结果：失败任务可能有中间 findings
                    self._partial_merger.record_partial(task)
                task.completed_at = time.time()
            if worker:
                worker.current_task = None
                worker.status = WorkerStatus.IDLE
                worker.tasks_completed += 1 if result.success else 0
                worker.tasks_failed += 0 if result.success else 1
                worker.total_task_time_ms += result.elapsed_seconds * 1000
                n = max(1, worker.tasks_completed + worker.tasks_failed)
                worker.avg_task_time_ms = worker.total_task_time_ms / n
                # 更新 binary 亲和度
                if task:
                    worker.binary_affinity[task.binary_path] = \
                        worker.binary_affinity.get(task.binary_path, 0) + 1
            # 任务完成（无论成功/失败），释放依赖它的任务
            self._release_ready_dependents(task_id)

    def requeue_task(self, task_id: str):
        """Re-en队列 a failed task 重试 remaining"""
        task = self._task_cache.get(task_id)
        if task and task.retry_count < task.max_retries:
            task.retry_count += 1
            task.status = TaskStatus.PENDING
            task.assigned_worker = ""
            key = self._heap_key(task)
            heapq.heappush(self._task_heap, key)

    def _select_worker(self) -> Optional[WorkerInfo]:
        """Pick best worker according active 加载-balancing strategy
        multiple workers similar 加载 scores, 使用 WorkerScorecard
        a tiebreaker
        """
        online = [w for w in self._workers.values()
                 if w.status != WorkerStatus.OFFLINE]
        if not online:
            return None
        idle = [w for w in online if w.status == WorkerStatus.IDLE]
        if not idle:
            idle = online

        # 获取栈顶任务所需能力
        required_caps = None
        if self._task_heap:
            _, _, _, _, _ = self._task_heap[0] if len(self._task_heap[0]) >= 5 else \
                (None, None, self._task_heap[0][2]) if len(self._task_heap[0]) == 3 else \
                (None, None, None)
            peek_id = self._task_heap[0][-1]
            peek_task = self._task_cache.get(peek_id)
            if peek_task and hasattr(peek_task, 'capabilities'):
                required_caps = peek_task.capabilities

        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            self._round_robin_pos = (self._round_robin_pos + 1) % len(idle)
            return idle[self._round_robin_pos % len(idle)]

        if self.strategy == LoadBalanceStrategy.LEAST_LOADED:
            return min(idle, key=lambda w: w.load_score())

        # ADAPTIVE: load_score 为主排序，binary_affinity 为次排序加分
        if self.strategy == LoadBalanceStrategy.ADAPTIVE:
            if self._task_heap:
                peek_id = self._task_heap[0][-1]
                peek_task = self._task_cache.get(peek_id)
                bp = peek_task.binary_path if peek_task else ""
                # 用 scorecard 打破 load_score 相近时的僵局
                scored = self._scorecard.score_workers(idle, required_caps)

                def _rank(w):
                    base = w.load_score()
                    aff_bonus = -w.affinity_for(bp) * 0.1
                    # 轻微 score_penalty：分数高的 worker 排名略优
                    score_penalty = -0.05 * next(
                        (s for w2, s in scored if w2.worker_id == w.worker_id), 0.5)
                    return base + aff_bonus + score_penalty

                return min(idle, key=_rank)
            return min(idle, key=lambda w: w.load_score())

        # CONSISTENT_HASH
        if self.strategy == LoadBalanceStrategy.CONSISTENT_HASH:
            if self._task_heap:
                peek_id = self._task_heap[0][-1]
                peek_task = self._task_cache.get(peek_id)
                bp = peek_task.binary_path if peek_task else ""
                target = self._cons_hash_pick(bp)
                if target and self._workers.get(target) and self._workers[target].status == WorkerStatus.IDLE:
                    return self._workers[target]
            return min(idle, key=lambda w: w.load_score())

        return idle[0]

    def stats(self) -> Dict[str, Any]:
        """返回 scheduler-level aggregate metrics"""
        return {
            'queue_size': len(self._task_heap),
            'workers': len(self._workers),
            'online_workers': sum(1 for w in self._workers.values()
                                 if w.status != WorkerStatus.OFFLINE),
            'idle_workers': sum(1 for w in self._workers.values()
                               if w.status == WorkerStatus.IDLE),
            'tasks_completed': sum(w.tasks_completed for w in self._workers.values()),
            'tasks_failed': sum(w.tasks_failed for w in self._workers.values()),
            'pending_dependencies': self._dependency_resolver.pending_count(),
            'deadline_dispatch_enabled': self.enable_deadline_dispatch,
        }


class TaskSplitter:
    """Decomposes a binary per-function SymbolicTasks
    
    支持 flat function-list splitting DAG-based splitting
    dependency-aware priority assignment"""

    def __init__(self, max_tasks_per_binary: int = 1000):
        self.max_tasks_per_binary = max_tasks_per_binary

    def split_by_functions(self, binary_path: str, functions: List[str],
                           priority_func: Optional[Callable[[str], int]] = None
                           ) -> List[SymbolicTask]:
        """创建 one task per function name, capped max_tasks_per_binary"""
        tasks = []
        for func_name in functions[:self.max_tasks_per_binary]:
            priority = priority_func(func_name) if priority_func else 0
            task_id = hashlib.md5(f"{binary_path}:{func_name}".encode()).hexdigest()[:16]
            tasks.append(SymbolicTask(
                task_id=task_id, binary_path=binary_path, func_name=func_name,
                priority=priority))
        return tasks

    def split_by_dag(self, binary_path: str, dag: Dict[str, List[str]],
                     entry_points: List[str]) -> List[SymbolicTask]:
        """BFS call-graph roots; priority = 100 - level*10
        callers precede callees 调度"""
        levels: Dict[str, int] = {}
        queue = [(ep, 0) for ep in entry_points]
        while queue:
            node, level = queue.pop(0)
            if node in levels:
                continue
            levels[node] = level
            for child in dag.get(node, []):
                if child not in levels:
                    queue.append((child, level + 1))
        tasks = []
        for func_name, level in levels.items():
            task_id = hashlib.md5(f"{binary_path}:{func_name}:L{level}".encode()).hexdigest()[:16]
            priority = max(0, 100 - level * 10)
            tasks.append(SymbolicTask(
                task_id=task_id, binary_path=binary_path, func_name=func_name,
                priority=priority,
                dependencies=[f"{binary_path}:{p}" for p in dag.get(func_name, [])]))
        return tasks


class ResultAggregator:
    """Collects aggregates per-task results a summary 报告
    
    支持 merging partial results salvaged timed-out/failed tasks
    via PartialResultMerger
    """

    def __init__(self):
        self._results: Dict[str, TaskResult] = {}
        self._lock = threading.Lock()
        self._partial_merger = PartialResultMerger()

    @property
    def partial_merger(self) -> PartialResultMerger:
        """Expose partial merger for external 使用"""
        return self._partial_merger

    def add_result(self, result: TaskResult):
        """寄存器 a completed task's result"""
        with self._lock:
            self._results[result.task_id] = result

    def aggregate(self) -> Dict[str, Any]:
        """计算 summary statistics across collected results
        
        Partial results timed-out/failed tasks merged
        final totals via PartialResultMerger.merge_into_aggregate
        """
        with self._lock:
            total = len(self._results)
            success = sum(1 for r in self._results.values() if r.success)
            total_paths = sum(r.paths_explored for r in self._results.values())
            total_vulns = sum(r.vulnerabilities_found for r in self._results.values())
            total_time = sum(r.elapsed_seconds for r in self._results.values())
            summary = {
                'success': True,
                'total_tasks': total, 'successful': success, 'failed': total - success,
                'total_paths_explored': total_paths,
                'total_vulnerabilities': total_vulns,
                'total_time_seconds': round(total_time, 2),
                'avg_time_per_task': round(total_time / max(1, total), 2),
                'results': [
                    {'task_id': r.task_id, 'success': r.success,
                     'paths_explored': r.paths_explored,
                     'vulnerabilities_found': r.vulnerabilities_found,
                     'elapsed_seconds': round(r.elapsed_seconds, 2),
                     'error': r.error[:200] if r.error else None}
                    for r in self._results.values()
                ]
            }

        # 合并部分结果（超时/失败任务的中间产出）
        self._partial_merger.merge_into_aggregate(summary)

        return summary


class DistributedSymbolicExecutor:
    """Top-level 调度器: splitter -> scheduler -> aggregator
    
    Usage:
    executor = 分布式SymbolicExecutor()
    executor.寄存器_worker("w1", cpu_cores=4)
    executor.submit_binary("/path//binary", ["func_a", "func_b"])
    True:
    dispatch_info = executor.dispatch()
    dispatch_info None:
    break
    #. 运行 task assigned worker
    executor.submit_result(task_id, worker_id, success=True, paths=42)
    报告 = executor.分析()
    """

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.ADAPTIVE,
                 checkpoint_dir: Optional[str] = None):
        self.scheduler = TaskScheduler(strategy)
        self.splitter = TaskSplitter()
        self.aggregator = ResultAggregator()
        self.cap_registry = WorkerCapabilityRegistry()
        self._checkpoint_dir = checkpoint_dir or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'symbex_dist_checkpoints')
        os.makedirs(self._checkpoint_dir, exist_ok=True)

    def register_worker(self, worker_id: str, hostname: str = "",
                        cpu_cores: int = 1, memory_mb: int = 1024,
                        capabilities: Optional[List[str]] = None):
        """寄存器 a worker node scheduler
        
        能力验证：通过 cap_registry 验证 worker 声称的能力
        只有 import 对应包成功的能力才被接受，无效的仅记录警告
        """
        caps = capabilities or []
        valid_caps: List[str] = []
        invalid_caps: List[str] = []
        if caps:
            valid_caps, invalid_caps = self.cap_registry.validate(caps)
            if invalid_caps:
                logger.warning("[Executor] Worker %s claimed invalid capabilities: %s",
                               worker_id, invalid_caps)
        worker = WorkerInfo(worker_id=worker_id, hostname=hostname,
                           cpu_cores=cpu_cores, memory_mb=memory_mb,
                           last_heartbeat=time.time(),
                           capabilities=valid_caps)
        self.scheduler.register_worker(worker)

    def unregister_worker(self, worker_id: str):
        """Remove a worker. Triggers automatic rebalance needed
        
        stale eviction 也会调用此路径，确保离开 worker 的待处理任务
        被重新分配到剩余 worker
        """
        self.scheduler.unregister_worker(worker_id)
        logger.info("[Executor] Worker %s unregistered, %d workers remain",
                    worker_id, len(self.scheduler._workers))

    def submit_binary(self, binary_path: str, functions: List[str],
                      priority_func: Optional[Callable[[str], int]] = None,
                      deadline_ts: float = 0.0):
        """分割 a binary per-function tasks en队列
        
        Args:
        binary_path: Path target binary
        functions: List function names 分析
        priority_func: Optional callable maps function name priority int
        deadline_ts: Optional absolute deadline timestamp (UTC epoch seconds)
        tasks derived binary inherit deadline
        """
        tasks = self.splitter.split_by_functions(binary_path, functions, priority_func)
        for task in tasks:
            if deadline_ts > 0:
                task.deadline_ts = deadline_ts
            self.scheduler.submit(task)
        logger.info(f"Submitted {len(tasks)} distributed symbolic execution tasks")

    def dispatch(self) -> Optional[Dict[str, Any]]:
        """De队列 next task-worker pair. 返回 None nothing ready"""
        pair = self.scheduler.dispatch()
        if not pair:
            return None
        task, worker = pair
        return {'task_id': task.task_id, 'binary_path': task.binary_path,
                'func_name': task.func_name, 'timeout': task.timeout_seconds,
                'max_states': task.max_states, 'worker_id': worker.worker_id,
                'deadline_ts': task.deadline_ts}

    def submit_result(self, task_id: str, worker_id: str, success: bool,
                      paths: int = 0, vulns: int = 0, elapsed: float = 0.0,
                      output: Optional[Dict[str, Any]] = None, error: str = "",
                      partial: Optional[Dict[str, Any]] = None):
        """Record a completed task result. 重试 non-timeout failures
        
        timeout/failure, partial intermediate results salvaged via
        PartialResultMerger instead discarded
        """
        # 如果提供了部分结果且任务未成功，将其暂存到任务上供 PartialResultMerger 回收
        if partial and not success:
            task = self.scheduler._task_cache.get(task_id)
            if task:
                task.partial_results = partial

        result = TaskResult(task_id=task_id, worker_id=worker_id, success=success,
                          paths_explored=paths, vulnerabilities_found=vulns,
                          elapsed_seconds=elapsed, output=output or {}, error=error)
        self.scheduler.complete_task(task_id, result)
        self.aggregator.add_result(result)
        if not success and "timeout" not in error.lower():
            self.scheduler.requeue_task(task_id)

    # rebalance — worker 拓扑变化后的任务再分配
    #
    # 委托给 TaskScheduler.rebalance()。典型触发场景：
    # 1. 寄存器_worker / un寄存器_worker 检测到 worker 数变化超过阈值
    # 2. 外部监控发现负载不均时手动触发
    def rebalance(self):
        """Redistribute pending tasks workers join/leave
        
        Stale eviction triggers automatically via scheduler's
        rebalance_threshold 检查. manually
        加载 imbalance detected externally
        """
        self.scheduler.rebalance()

    def save_checkpoint(self):
        """Persist scheduler aggregator state disk"""
        checkpoint = {'timestamp': time.time(),
                     'scheduler_stats': self.scheduler.stats(),
                     'aggregate': self.aggregator.aggregate()}
        path = os.path.join(self._checkpoint_dir, 'checkpoint.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, ensure_ascii=False, indent=2)

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """返回 aggregated results scheduler stats
        Partial results timed-out/failed tasks merged
        aggregate totals"""
        aggregate = self.aggregator.aggregate()
        aggregate['scheduler_stats'] = self.scheduler.stats()
        return aggregate


def distributed_symbolic_execution(
    binary_path: str, functions: List[str],
    workers: List[Dict[str, Any]], strategy: str = "adaptive"
) -> Dict[str, Any]:
    """One-shot: 寄存器 workers, submit binary, 返回 aggregate stats"""
    try:
        strat = LoadBalanceStrategy(strategy.lower())
    except ValueError:
        strat = LoadBalanceStrategy.ADAPTIVE
    executor = DistributedSymbolicExecutor(strategy=strat)
    for w in workers:
        executor.register_worker(
            w['worker_id'], hostname=w.get('hostname', ''),
            cpu_cores=w.get('cpu_cores', 1), memory_mb=w.get('memory_mb', 1024))
    executor.submit_binary(binary_path, functions)
    return executor.analyze()


__all__ = ["DistributedSymbolicExecutor", "TaskScheduler", "TaskSplitter",
           "ResultAggregator", "SymbolicTask", "TaskResult", "WorkerInfo",
           "TaskStatus", "WorkerStatus", "LoadBalanceStrategy",
           "WorkerCapabilityRegistry", "TaskDependencyResolver",
           "DeadlineAwareDispatch", "WorkerScorecard", "PartialResultMerger",
           "distributed_symbolic_execution"]
