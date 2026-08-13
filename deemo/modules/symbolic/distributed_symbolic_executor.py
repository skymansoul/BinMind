"""Task scheduler for distributed symbolic execution.

Splits a binary into per-function analysis tasks, dispatches them to
registered workers using pluggable load-balancing strategies (round-robin,
least-loaded, adaptive), and aggregates results with retry logic for
transient failures.
"""

import logging
import time
import hashlib
import threading
import json
import os
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from queue import PriorityQueue

logger = logging.getLogger(__name__)


class TaskStatus:
    """Task lifecycle states."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class WorkerStatus:
    """Worker node states."""
    IDLE = "idle"
    BUSY = "busy"
    OFFLINE = "offline"
    DRAINING = "draining"


class LoadBalanceStrategy(Enum):
    """Dispatch policies for worker selection."""
    ROUND_ROBIN = "round_robin"
    CONSISTENT_HASH = "consistent_hash"
    LEAST_LOADED = "least_loaded"
    ADAPTIVE = "adaptive"


@dataclass
class SymbolicTask:
    """One function's symbolic analysis unit for distributed dispatch."""
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

    def to_dict(self) -> Dict[str, Any]:
        """Compact serialization for status reporting."""
        return {'task_id': self.task_id, 'func_name': self.func_name,
                'priority': self.priority, 'status': self.status,
                'assigned_worker': self.assigned_worker, 'retry_count': self.retry_count}


@dataclass
class TaskResult:
    """Result returned by a worker after completing a task."""
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
    """Worker node registration and performance metadata."""
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

    def load_score(self) -> float:
        """Heuristic load: avg time per task weighted by failure count.
        OFFLINE workers return infinity."""
        if self.status == WorkerStatus.OFFLINE:
            return float('inf')
        if self.status == WorkerStatus.IDLE:
            return 0.0
        return self.avg_task_time_ms / max(1, self.tasks_completed) * (1 + self.tasks_failed)


class TaskScheduler:
    """Priority-queue-based task dispatcher with pluggable load balancing."""

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.ADAPTIVE):
        self.strategy = strategy
        self._task_queue: PriorityQueue = PriorityQueue()
        self._workers: Dict[str, WorkerInfo] = {}
        self._task_cache: Dict[str, SymbolicTask] = {}
        self._lock = threading.Lock()

    def register_worker(self, worker: WorkerInfo):
        """Add or update a worker in the pool."""
        with self._lock:
            self._workers[worker.worker_id] = worker

    def unregister_worker(self, worker_id: str):
        """Remove a worker from the pool."""
        with self._lock:
            self._workers.pop(worker_id, None)

    def submit(self, task: SymbolicTask):
        """Enqueue a task. Priority queue orders by (-priority, created_at)."""
        task.created_at = time.time()
        with self._lock:
            self._task_cache[task.task_id] = task
            self._task_queue.put((-task.priority, task.created_at, task.task_id))

    def dispatch(self) -> Optional[Tuple[SymbolicTask, WorkerInfo]]:
        """Dequeue the highest-priority task and assign it to a worker."""
        with self._lock:
            if self._task_queue.empty():
                return None
            worker = self._select_worker()
            if not worker:
                return None
            _, _, task_id = self._task_queue.get()
            task = self._task_cache.get(task_id)
            if not task:
                return None
            task.assigned_worker = worker.worker_id
            task.status = TaskStatus.ASSIGNED
            worker.current_task = task_id
            worker.status = WorkerStatus.BUSY
            return (task, worker)

    def complete_task(self, task_id: str, result: TaskResult):
        """Mark a task complete and update worker performance counters."""
        with self._lock:
            task = self._task_cache.get(task_id)
            worker = self._workers.get(result.worker_id)
            if task:
                task.status = TaskStatus.COMPLETED if result.success else TaskStatus.FAILED
                task.completed_at = time.time()
            if worker:
                worker.current_task = None
                worker.status = WorkerStatus.IDLE
                worker.tasks_completed += 1 if result.success else 0
                worker.tasks_failed += 0 if result.success else 1
                worker.total_task_time_ms += result.elapsed_seconds * 1000
                n = max(1, worker.tasks_completed + worker.tasks_failed)
                worker.avg_task_time_ms = worker.total_task_time_ms / n

    def requeue_task(self, task_id: str):
        """Re-enqueue a failed task if it has retries remaining."""
        task = self._task_cache.get(task_id)
        if task and task.retry_count < task.max_retries:
            task.retry_count += 1
            task.status = TaskStatus.PENDING
            task.assigned_worker = ""
            self._task_queue.put((-task.priority, time.time(), task_id))

    def _select_worker(self) -> Optional[WorkerInfo]:
        """Pick the best worker according to the active load-balancing strategy."""
        online = [w for w in self._workers.values()
                 if w.status != WorkerStatus.OFFLINE]
        if not online:
            return None
        idle = [w for w in online if w.status == WorkerStatus.IDLE]
        if not idle:
            idle = online
        if self.strategy == LoadBalanceStrategy.LEAST_LOADED:
            return min(idle, key=lambda w: w.load_score())
        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            return min(idle, key=lambda w: w.tasks_completed)
        return min(idle, key=lambda w: (w.load_score(), w.avg_task_time_ms))

    def stats(self) -> Dict[str, Any]:
        """Return scheduler-level aggregate metrics."""
        return {
            'queue_size': self._task_queue.qsize(),
            'workers': len(self._workers),
            'online_workers': sum(1 for w in self._workers.values()
                                 if w.status != WorkerStatus.OFFLINE),
            'idle_workers': sum(1 for w in self._workers.values()
                               if w.status == WorkerStatus.IDLE),
            'tasks_completed': sum(w.tasks_completed for w in self._workers.values()),
            'tasks_failed': sum(w.tasks_failed for w in self._workers.values()),
        }


class TaskSplitter:
    """Decomposes a binary into per-function SymbolicTasks.

    Supports flat function-list splitting and DAG-based splitting with
    dependency-aware priority assignment."""

    def __init__(self, max_tasks_per_binary: int = 1000):
        self.max_tasks_per_binary = max_tasks_per_binary

    def split_by_functions(self, binary_path: str, functions: List[str],
                           priority_func: Optional[Callable[[str], int]] = None
                           ) -> List[SymbolicTask]:
        """Create one task per function name, capped at max_tasks_per_binary."""
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
        """BFS from call-graph roots; priority = 100 − level×10 so
        callers precede callees in the schedule."""
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
    """Collects and aggregates per-task results into a summary report."""

    def __init__(self):
        self._results: Dict[str, TaskResult] = {}
        self._lock = threading.Lock()

    def add_result(self, result: TaskResult):
        """Register a completed task's result."""
        with self._lock:
            self._results[result.task_id] = result

    def aggregate(self) -> Dict[str, Any]:
        """Compute summary statistics across all collected results."""
        with self._lock:
            total = len(self._results)
            success = sum(1 for r in self._results.values() if r.success)
            total_paths = sum(r.paths_explored for r in self._results.values())
            total_vulns = sum(r.vulnerabilities_found for r in self._results.values())
            total_time = sum(r.elapsed_seconds for r in self._results.values())
            return {
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


class DistributedSymbolicExecutor:
    """Top-level orchestrator: splitter → scheduler → aggregator.

    Usage:
        executor = DistributedSymbolicExecutor()
        executor.register_worker("w1", cpu_cores=4)
        executor.submit_binary("/path/to/binary", ["func_a", "func_b"])
        while True:
            dispatch_info = executor.dispatch()
            if dispatch_info is None:
                break
            # ... run the task on the assigned worker ...
            executor.submit_result(task_id, worker_id, success=True, paths=42)
        report = executor.analyze()
    """

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.ADAPTIVE,
                 checkpoint_dir: Optional[str] = None):
        self.scheduler = TaskScheduler(strategy)
        self.splitter = TaskSplitter()
        self.aggregator = ResultAggregator()
        self._checkpoint_dir = checkpoint_dir or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'symbex_dist_checkpoints')
        os.makedirs(self._checkpoint_dir, exist_ok=True)

    def register_worker(self, worker_id: str, hostname: str = "",
                        cpu_cores: int = 1, memory_mb: int = 1024):
        """Register a worker node in the scheduler."""
        worker = WorkerInfo(worker_id=worker_id, hostname=hostname,
                           cpu_cores=cpu_cores, memory_mb=memory_mb,
                           last_heartbeat=time.time())
        self.scheduler.register_worker(worker)

    def submit_binary(self, binary_path: str, functions: List[str],
                      priority_func: Optional[Callable[[str], int]] = None):
        """Split a binary into per-function tasks and enqueue them."""
        tasks = self.splitter.split_by_functions(binary_path, functions, priority_func)
        for task in tasks:
            self.scheduler.submit(task)
        logger.info(f"Submitted {len(tasks)} distributed symbolic execution tasks")

    def dispatch(self) -> Optional[Dict[str, Any]]:
        """Dequeue the next task-worker pair. Returns None if nothing is ready."""
        pair = self.scheduler.dispatch()
        if not pair:
            return None
        task, worker = pair
        return {'task_id': task.task_id, 'binary_path': task.binary_path,
                'func_name': task.func_name, 'timeout': task.timeout_seconds,
                'max_states': task.max_states, 'worker_id': worker.worker_id}

    def submit_result(self, task_id: str, worker_id: str, success: bool,
                      paths: int = 0, vulns: int = 0, elapsed: float = 0.0,
                      output: Optional[Dict[str, Any]] = None, error: str = ""):
        """Record a completed task result. Retries on non-timeout failures."""
        result = TaskResult(task_id=task_id, worker_id=worker_id, success=success,
                          paths_explored=paths, vulnerabilities_found=vulns,
                          elapsed_seconds=elapsed, output=output or {}, error=error)
        self.scheduler.complete_task(task_id, result)
        self.aggregator.add_result(result)
        if not success and "timeout" not in error.lower():
            self.scheduler.requeue_task(task_id)

    def save_checkpoint(self):
        """Persist scheduler and aggregator state to disk."""
        checkpoint = {'timestamp': time.time(),
                     'scheduler_stats': self.scheduler.stats(),
                     'aggregate': self.aggregator.aggregate()}
        path = os.path.join(self._checkpoint_dir, 'checkpoint.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, ensure_ascii=False, indent=2)

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Return aggregated results and scheduler stats."""
        aggregate = self.aggregator.aggregate()
        aggregate['scheduler_stats'] = self.scheduler.stats()
        return aggregate


def distributed_symbolic_execution(
    binary_path: str, functions: List[str],
    workers: List[Dict[str, Any]], strategy: str = "adaptive"
) -> Dict[str, Any]:
    """One-shot: register workers, submit binary, return aggregate stats."""
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
           "distributed_symbolic_execution"]
