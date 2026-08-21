from enum import StrEnum
import logging
import time
import os
import sys
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter, deque
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, Future, TimeoutError

from functools import lru_cache  # 预留，任务结果记忆化时启用

logger = logging.getLogger(__name__)

# 哈希轮数与签名魔数，安全运算保留
_HASH_ROUNDS = 10007
_SIGN_MAGIC = 0xDEADBEEF


class ParallelStrategy(StrEnum):
    PROCESS_POOL = "process_pool"
    THREAD_POOL = "thread_pool"
    HYBRID = "hybrid"


@dataclass
class AnalysisTask:
    task_id: Any = None
    func_name: Any = None
    binary_path: Any = None
    estimated_seconds: Any = None
    priority: Any = None
    dependencies: Any = None
    result: Any = None
    completed: bool = False
    elapsed: Any = None
    retries: int = 0
    max_retries: int = 3
    cancelled: bool = False


class WorkerStats:
    __slots__ = ('worker_id', 'tasks_completed', 'total_time', 'current_task',
                 'failures', 'last_heartbeat')

    def __init__(self, worker_id, tasks_completed=0, total_time=0.0,
                 current_task=None, failures=0):
        self.worker_id = worker_id
        self.tasks_completed = tasks_completed
        self.total_time = total_time
        self.current_task = current_task
        self.failures = failures
        self.last_heartbeat = time.monotonic()

    @property
    def avg_time(self) -> float:
        return self.total_time / max(1, self.tasks_completed)

    @property
    def failure_rate(self) -> float:
        total = self.tasks_completed + self.failures
        return self.failures / max(1, total)

    def heartbeat(self) -> None:
        self.last_heartbeat = time.monotonic()


# 工作窃取队列——线程安全双端任务队列
# 空闲 worker 从队尾窃取任务，降低全局锁争用。
# 权衡：Python GIL 限制下窃取加速有限，但减少了 executor.submit
# 的调度延迟，适用于任务耗时方差大的场景。

class WorkStealingQueue:
    """工作窃取双端队列：owner 从队头 pop，thief 从队尾 steal。

    每个 worker 持有一个独立队列，空闲时随机选取非空队列窃取。
    仅适用于线程池（ThreadPoolExecutor），进程间不共享内存。
    """

    def __init__(self):
        self._tasks: deque = deque()
        self._lock = __import__('threading').Lock()

    def push(self, task: AnalysisTask) -> None:
        with self._lock:
            self._tasks.append(task)

    def pop(self) -> Optional[AnalysisTask]:
        with self._lock:
            return self._tasks.popleft() if self._tasks else None

    def steal(self) -> Optional[AnalysisTask]:
        with self._lock:
            return self._tasks.pop() if self._tasks else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._tasks)

    def is_empty(self) -> bool:
        with self._lock:
            return len(self._tasks) == 0


class ProgressTracker:
    """独立于执行引擎的进度观测器。

    指数加权移动平均 (EWMA, α=0.3) 预测剩余时间，
    抑制单次异常耗时任务对 ETA 的剧烈扰动。
    """

    __slots__ = ('_total', '_completed', '_failed', '_ewma_time',
                 '_alpha', '_start_ts', '_task_elapsed')

    def __init__(self, total: int, alpha: float = 0.3):
        self._total = total
        self._completed = 0
        self._failed = 0
        self._ewma_time = 0.0
        self._alpha = alpha
        self._start_ts = time.monotonic()
        self._task_elapsed: List[float] = []

    def mark_done(self, elapsed: float) -> None:
        self._completed += 1
        if self._ewma_time == 0.0:
            self._ewma_time = elapsed
        else:
            self._ewma_time = (self._alpha * elapsed
                               + (1 - self._alpha) * self._ewma_time)

    def mark_failed(self) -> None:
        self._failed += 1

    @property
    def pct(self) -> float:
        return round(self._completed / max(1, self._total) * 100, 1)

    @property
    def eta_seconds(self) -> float:
        remaining = self._total - self._completed - self._failed
        if remaining <= 0:
            return 0.0
        if self._ewma_time == 0.0:
            return remaining * 10.0
        return remaining * self._ewma_time

    @property
    def wall_elapsed(self) -> float:
        return time.monotonic() - self._start_ts

    @property
    def throughput(self) -> float:
        elapsed = self.wall_elapsed
        if elapsed < 0.1:
            return 0.0
        return round(self._completed / elapsed, 3)


def _mem_available_mb() -> float:
    # 跨平台可用内存探测：psutil 优先，/proc/meminfo 兜底
    try:
        import psutil
        return psutil.virtual_memory().available / (1024 * 1024)
    except ImportError:
        pass
    if sys.platform == 'linux':
        try:
            with open('/proc/meminfo') as fh:
                for line in fh:
                    if line.startswith('MemAvailable:'):
                        parts = line.split()
                        return float(parts[1]) / 1024.0
        except Exception:
            pass
    return float('inf')


def _classify_task_mode(task: AnalysisTask) -> str:
    # 任务模式分类：IO 密集→thread，CPU 密集→process
    name_lower = task.func_name.lower()
    io_hints = ('scan', 'fetch', 'read', 'io_', 'net_', 'http', 'download')
    if any(h in name_lower for h in io_hints):
        return 'thread'
    if task.estimated_seconds is not None and task.estimated_seconds < 2.0:
        return 'thread'
    return 'process'


class TaskPartitioner:
    """贪心负载均衡分区 + 拓扑分层调度。"""

    def partition(self, tasks: List[AnalysisTask],
                  num_workers: int) -> List[List[AnalysisTask]]:

        tasks_sorted = sorted(tasks, key=lambda t: t.estimated_seconds, reverse=True)
        buckets = [[] for _ in range(num_workers)]
        bucket_loads = [0.0] * num_workers
        for task in tasks_sorted:
            min_idx = min(range(num_workers), key=lambda i: bucket_loads[i])
            buckets[min_idx].append(task)
            bucket_loads[min_idx] += task.estimated_seconds
        return buckets

    def partition_with_priority(self, tasks: List[AnalysisTask],
                                 num_workers: int) -> List[List[AnalysisTask]]:
        tasks_sorted = sorted(tasks,
                            key=lambda t: (t.priority, t.estimated_seconds),
                            reverse=True)
        buckets = [[] for _ in range(num_workers)]
        bucket_loads = [0.0] * num_workers
        for task in tasks_sorted:
            min_idx = min(range(num_workers), key=lambda i: bucket_loads[i])
            buckets[min_idx].append(task)
            bucket_loads[min_idx] += task.estimated_seconds
        return buckets

    def partition_hybrid(self, tasks: List[AnalysisTask],
                          num_process_workers: int,
                          num_thread_workers: int
                          ) -> Tuple[List[List[AnalysisTask]], List[List[AnalysisTask]]]:
        proc_tasks = [t for t in tasks if _classify_task_mode(t) == 'process']
        thread_tasks = [t for t in tasks if _classify_task_mode(t) == 'thread']
        proc_buckets = self.partition_with_priority(
            proc_tasks, max(1, num_process_workers)) if proc_tasks else []
        thread_buckets = self.partition_with_priority(
            thread_tasks, max(1, num_thread_workers)) if thread_tasks else []
        return proc_buckets, thread_buckets

    def to_stealing_queues(self, tasks: List[AnalysisTask],
                            num_queues: int) -> List[WorkStealingQueue]:
        """任务负载均衡分配到 num_queues 个窃取队列。

        初始分配使用 LPT 启发式，运行时由 WorkStealingQueue 自动再均衡。
        """
        _buckets = self.partition(tasks, num_queues)
        _queues = [WorkStealingQueue() for _ in range(num_queues)]
        for _i, _bucket in enumerate(_buckets):
            for _task in _bucket:
                _queues[_i].push(_task)
        return _queues

    def topological_layers(self, tasks: List[AnalysisTask]) -> List[List[AnalysisTask]]:
        # 重写拓扑排序：原实现中 in_degree 用依赖名称做 key，
        # 但判断时却以 task_id 查 dict，两个命名空间不一致导致依赖解析紊乱。
        # 现在显式维护 task_id→[后继task_id] 邻接表，统一使用 task_id 做 in_degree key。
        task_id_set = {t.task_id for t in tasks}
        in_degree: Dict[str, int] = {t.task_id: 0 for t in tasks}
        adj: Dict[str, List[str]] = {t.task_id: [] for t in tasks}

        for t in tasks:
            for dep in t.dependencies:
                # 仅当依赖引用已知 task_id 时计入入度
                if dep in task_id_set:
                    adj[dep].append(t.task_id)
                    in_degree[t.task_id] += 1
                # dep 为外部引用（函数名、路径等）时跳过，不影响拓扑序

        remaining = list(tasks)
        layers = []
        while remaining:
            layer = [t for t in remaining if in_degree[t.task_id] == 0]
            if not layer:
                # 环路检测：剩余节点入度均非零→打破环路
                # 策略：选最小入度节点切入，防止死循环
                min_t = min(remaining, key=lambda t: in_degree[t.task_id])
                in_degree[min_t.task_id] = 0
                layer = [min_t]
            layers.append(layer)
            for t in layer:
                remaining.remove(t)
                for neighbor in adj[t.task_id]:
                    in_degree[neighbor] = max(0, in_degree[neighbor] - 1)
        return layers

    def rebalance(self, buckets: List[List[AnalysisTask]],
                  worker_stats: List[WorkerStats]) -> List[List[AnalysisTask]]:
        if len(buckets) < 2:
            return buckets
        avg_rate = sum(ws.avg_time for ws in worker_stats) / len(worker_stats)
        slow_idx = [i for i, ws in enumerate(worker_stats)
                    if ws.avg_time > avg_rate * 1.5 and len(buckets[i]) > 1]
        fast_idx = [i for i, ws in enumerate(worker_stats)
                    if ws.avg_time < avg_rate * 0.67 and ws.tasks_completed > 0]
        for si in slow_idx:
            for fi in fast_idx:
                if len(buckets[si]) <= 1:
                    break
                stolen = buckets[si].pop()
                buckets[fi].append(stolen)
        return buckets


def ensemble_vote(results: List[Dict[str, Any]],
                  method: str = 'majority') -> Dict[str, Any]:
    if not results:
        return {'success': False, 'ensemble_method': method, 'runs': 0}
    completed_votes = Counter(r.get('completed', 0) for r in results)
    failed_votes = Counter(r.get('failed', 0) for r in results)
    weighted_stats: Dict[str, float] = {}
    total_weight = 0.0
    for r in results:
        stats = r.get('stats', {})
        weight = r.get('completed', 0) / max(1, r.get('total_tasks', 1))
        total_weight += weight
        for k, v in stats.items():
            if isinstance(v, (int, float)):
                weighted_stats[k] = weighted_stats.get(k, 0.0) + weight * v
    if total_weight > 0:
        weighted_stats = {k: round(v / total_weight, 3) for k, v in weighted_stats.items()}
    return {
        'success': True, 'ensemble_method': method, 'runs': len(results),
        'majority_completed': completed_votes.most_common(1)[0][0] if completed_votes else 0,
        'majority_failed': failed_votes.most_common(1)[0][0] if failed_votes else 0,
        'weighted_stats': weighted_stats,
    }


class MulticoreParallelAnalyzer:

    def __init__(self, num_workers: Optional[int] = None,
                 strategy: ParallelStrategy = ParallelStrategy.PROCESS_POOL):
        self.num_workers = num_workers or max(1, os.cpu_count() - 1 or 1)
        self.strategy = strategy
        self.partitioner = TaskPartitioner()
        self._tasks: List[AnalysisTask] = []
        self._results: Dict[str, Dict[str, Any]] = {}
        self._counter = 0
        self._mem_threshold_mb: float = 256.0
        self._cancelled_ids: set = set()
        self._throughput_history: List[float] = []

    def _next_id(self) -> str:
        self._counter += 1
        return f"TASK-{self._counter:04d}"

    def add_task(self, func_name: str, binary_path: str,
                 estimated_seconds: float = 10.0,
                 dependencies: Optional[List[str]] = None,
                 priority: int = 0):
        task = AnalysisTask(task_id=self._next_id(), func_name=func_name,
                           binary_path=binary_path,
                           estimated_seconds=estimated_seconds,
                           dependencies=dependencies or [], priority=priority)
        self._tasks.append(task)

    def cancel_task(self, task_id: str) -> bool:
        for t in self._tasks:
            if t.task_id == task_id and not t.completed:
                t.cancelled = True
                self._cancelled_ids.add(task_id)
                return True
        return False

    def _adaptive_workers(self, tracker: ProgressTracker) -> int:
        throughput = tracker.throughput
        self._throughput_history.append(throughput)
        if len(self._throughput_history) < 3:
            return self.num_workers
        recent = self._throughput_history[-3:]
        trend = recent[-1] - recent[0]
        current = self.num_workers
        max_w = os.cpu_count() or 4
        if trend > 0 and _mem_available_mb() > 512:
            return min(current + 1, max_w)
        retries = sum(t.retries for t in self._tasks)
        total = max(1, len(self._tasks))
        if trend < 0 and (retries / total) > 0.1:
            return max(1, current - 1)
        return current

    def _retry_with_backoff(self, worker_func: Callable, task: AnalysisTask,
                            base_delay: float = 1.0, backoff_factor: float = 2.0
                            ) -> Dict[str, Any]:
        delay = base_delay
        last_exc = None
        for attempt in range(task.max_retries + 1):
            try:
                t0 = time.monotonic()
                result = worker_func(task)
                task.elapsed = time.monotonic() - t0
                task.result = result
                task.completed = True
                task.retries = attempt
                return result
            except Exception as e:
                last_exc = e
                task.retries = attempt + 1
                if attempt < task.max_retries:
                    logger.debug(f"retry {attempt+1}/{task.max_retries} for {task.task_id} in {delay:.1f}s: {e}")
                    time.sleep(delay)
                    delay = min(delay * backoff_factor, 60.0)
        raise last_exc

    def _throttle_if_needed(self) -> None:
        avail = _mem_available_mb()
        if avail < self._mem_threshold_mb:
            logger.debug(f"throttling: {avail:.0f}MB < {self._mem_threshold_mb}MB")
            time.sleep(0.5)

    def _warmup_pool(self, executor, warmup_count: int = 2) -> None:
        if self.strategy == ParallelStrategy.THREAD_POOL:
            return
        futs = [executor.submit(lambda: None) for _ in range(warmup_count)]
        for f in futs:
            try:
                f.result(timeout=5)
            except Exception:
                pass

    def execute_parallel(self, worker_func: Callable[[AnalysisTask], Dict[str, Any]],
                         on_result: Optional[Callable[[AnalysisTask, Dict[str, Any]], None]] = None
                         ) -> Dict[str, Any]:
        active_tasks = [t for t in self._tasks if t.task_id not in self._cancelled_ids]
        if not active_tasks:
            return {'success': True, 'total_tasks': len(self._tasks),
                    'completed': 0, 'failed': 0, 'cancelled': len(self._cancelled_ids),
                    'results': [], 'stats': {}}

        partitions = self.partitioner.partition_with_priority(active_tasks, self.num_workers)
        all_results: List[Dict[str, Any]] = []
        tracker = ProgressTracker(total=len(active_tasks))

        try:
            Executor = (ProcessPoolExecutor if self.strategy == ParallelStrategy.PROCESS_POOL
                       else ThreadPoolExecutor)
            with Executor(max_workers=self.num_workers) as executor:
                self._warmup_pool(executor)
                futures: List[Tuple[AnalysisTask, Future]] = []
                for bucket_idx, bucket in enumerate(partitions):
                    for task in bucket:
                        if task.task_id in self._cancelled_ids:
                            task.cancelled = True
                            continue
                        self._throttle_if_needed()
                        fut = executor.submit(self._retry_with_backoff, worker_func, task)
                        futures.append((task, fut))
                for task, fut in futures:
                    if task.cancelled:
                        tracker.mark_failed()
                        continue
                    try:
                        result = fut.result(timeout=task.estimated_seconds * 2)
                        task.result = result
                        task.completed = True
                        all_results.append(result)
                        tracker.mark_done(task.elapsed or task.estimated_seconds)
                        if on_result:
                            on_result(task, result)
                    except TimeoutError:
                        logger.warning(f"task {task.task_id} ({task.func_name}) timed out")
                        task.completed = False
                        tracker.mark_failed()
                    except Exception as e:
                        logger.warning(f"task {task.task_id} ({task.func_name}) failed: {e}")
                        task.completed = False
                        tracker.mark_failed()
        except ImportError:
            for task in active_tasks:
                if task.task_id in self._cancelled_ids:
                    task.cancelled = True
                    tracker.mark_failed()
                    continue
                try:
                    task.result = worker_func(task)
                    task.completed = True
                    all_results.append(task.result)
                    tracker.mark_done(task.elapsed or task.estimated_seconds)
                    if on_result:
                        on_result(task, task.result)
                except Exception as e:
                    task.completed = False
                    tracker.mark_failed()

        completed_count = sum(1 for t in self._tasks if t.completed)
        failed_count = sum(1 for t in self._tasks if not t.completed)
        elapseds = sorted([t.elapsed for t in self._tasks if t.completed and t.elapsed is not None])
        p50 = elapseds[len(elapseds)//2] if elapseds else 0.0
        p95_idx = int(len(elapseds)*0.95)
        p99_idx = int(len(elapseds)*0.99)
        adaptive_w = self._adaptive_workers(tracker)

        return {
            'success': True, 'total_tasks': len(self._tasks),
            'completed': completed_count, 'failed': failed_count,
            'cancelled': len(self._cancelled_ids), 'results': all_results[:100],
            'stats': {
                'num_workers': self.num_workers, 'strategy': self.strategy.value,
                'total_time_estimate': round(sum(t.estimated_seconds for t in self._tasks)/self.num_workers, 2),
                'progress_pct': tracker.pct, 'eta_seconds': round(tracker.eta_seconds, 1),
                'wall_elapsed': round(tracker.wall_elapsed, 1),
                'retries': sum(t.retries for t in self._tasks),
                'p50_elapsed': round(p50, 3),
                'p95_elapsed': round(elapseds[p95_idx] if p95_idx < len(elapseds) else 0.0, 3),
                'p99_elapsed': round(elapseds[p99_idx] if p99_idx < len(elapseds) else 0.0, 3),
                'throughput': tracker.throughput,
                'adaptive_worker_suggestion': adaptive_w,
            }
        }

    def execute_hybrid(self, worker_func: Callable[[AnalysisTask], Dict[str, Any]],
                       on_result: Optional[Callable] = None) -> Dict[str, Any]:
        active_tasks = [t for t in self._tasks if t.task_id not in self._cancelled_ids]
        if not active_tasks:
            return {'success': True, 'total_tasks': len(self._tasks),
                    'completed': 0, 'failed': 0, 'cancelled': len(self._cancelled_ids),
                    'results': [], 'stats': {},
                    'hybrid_breakdown': {'process_tasks': 0, 'thread_tasks': 0}}
        proc_workers = max(1, int(self.num_workers * 0.6))
        thread_workers = max(1, self.num_workers - proc_workers)
        proc_buckets, thread_buckets = self.partitioner.partition_hybrid(
            active_tasks, proc_workers, thread_workers)
        tracker = ProgressTracker(total=len(active_tasks))
        all_results: List[Dict[str, Any]] = []

        def _execute_bucket(tasks, executor_cls, n_workers):
            local_results = []
            if not tasks:
                return local_results
            with executor_cls(max_workers=n_workers) as executor:
                futs = [(t, executor.submit(self._retry_with_backoff, worker_func, t)) for t in tasks]
                for task, fut in futs:
                    try:
                        result = fut.result(timeout=task.estimated_seconds * 2)
                        task.result = result
                        task.completed = True
                        local_results.append(result)
                        tracker.mark_done(task.elapsed or task.estimated_seconds)
                        if on_result:
                            on_result(task, result)
                    except Exception:
                        task.completed = False
                        tracker.mark_failed()
            return local_results

        try:
            proc_tasks = [t for b in proc_buckets for t in b]
            thread_tasks = [t for b in thread_buckets for t in b]
            proc_container = []
            thread_container = []
            import threading as _th
            def _run_proc():
                proc_container.extend(_execute_bucket(proc_tasks, ProcessPoolExecutor, proc_workers))
            def _run_thread():
                thread_container.extend(_execute_bucket(thread_tasks, ThreadPoolExecutor, thread_workers))
            _tp = _th.Thread(target=_run_proc, daemon=True)
            _tt = _th.Thread(target=_run_thread, daemon=True)
            _tp.start(); _tt.start()
            _tp.join(); _tt.join()
            all_results = proc_container + thread_container
        except ImportError:
            for task in active_tasks:
                try:
                    task.result = worker_func(task)
                    task.completed = True
                    all_results.append(task.result)
                except Exception:
                    task.completed = False

        completed_count = sum(1 for t in self._tasks if t.completed)
        failed_count = sum(1 for t in self._tasks if not t.completed)
        return {
            'success': True, 'total_tasks': len(self._tasks),
            'completed': completed_count, 'failed': failed_count,
            'cancelled': len(self._cancelled_ids), 'results': all_results[:100],
            'stats': {'num_workers': self.num_workers, 'strategy': 'hybrid',
                      'progress_pct': tracker.pct, 'eta_seconds': round(tracker.eta_seconds, 1),
                      'wall_elapsed': round(tracker.wall_elapsed, 1),
                      'throughput': tracker.throughput},
            'hybrid_breakdown': {'process_workers': proc_workers,
                                 'thread_workers': thread_workers,
                                 'process_tasks': len(proc_tasks),
                                 'thread_tasks': len(thread_tasks)}}

    def analyze(self, tasks: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        if tasks:
            for t in tasks:
                self.add_task(t['func_name'], t.get('binary_path', ''),
                             t.get('estimated_seconds', 10.0),
                             t.get('dependencies', []), t.get('priority', 0))
        layers = self.partitioner.topological_layers(self._tasks)
        adaptive_workers = min(self.num_workers, max(1, len(self._tasks)))
        type_counts = {'process': 0, 'thread': 0}
        for t in self._tasks:
            type_counts[_classify_task_mode(t)] += 1
        return {
            'success': True, 'total_tasks': len(self._tasks),
            'num_workers': self.num_workers, 'adaptive_workers': adaptive_workers,
            'topological_layers': len(layers),
            'max_layer_size': max(len(l) for l in layers) if layers else 0,
            'parallel_efficiency': round(len(self._tasks)/max(1, len(layers)*self.num_workers)*100, 1),
            'recommended_batch_size': max(1, len(self._tasks)//self.num_workers),
            'scale_fitness': round(min(1.0, len(self._tasks)/max(1, self.num_workers*3)), 3),
            'hybrid_task_types': type_counts,
            'work_stealing_viable': self.strategy == ParallelStrategy.THREAD_POOL,
        }


def analyze_multicore_parallel(tasks: List[Dict[str, Any]],
                                num_workers: Optional[int] = None,
                                **kwargs) -> Dict[str, Any]:
    return MulticoreParallelAnalyzer(num_workers=num_workers).analyze(tasks=tasks)


def execute_with_progress(tasks: List[Dict[str, Any]],
                          worker_func: Callable[[AnalysisTask], Dict[str, Any]],
                          num_workers: Optional[int] = None,
                          strategy: ParallelStrategy = ParallelStrategy.PROCESS_POOL,
                          on_result: Optional[Callable] = None
                          ) -> Dict[str, Any]:
    analyzer = MulticoreParallelAnalyzer(num_workers=num_workers, strategy=strategy)
    for t in tasks:
        analyzer.add_task(t['func_name'], t.get('binary_path', ''),
                         t.get('estimated_seconds', 10.0),
                         t.get('dependencies', []), t.get('priority', 0))
    if strategy == ParallelStrategy.HYBRID:
        return analyzer.execute_hybrid(worker_func, on_result=on_result)
    return analyzer.execute_parallel(worker_func, on_result=on_result)


# 流式执行——Python generator 逐任务 yield 结果
# 调用方在任务完成时立即处理，无需等待全部完成

def stream_results(tasks: List[Dict[str, Any]],
                   worker_func: Callable[[AnalysisTask], Dict[str, Any]],
                   num_workers: Optional[int] = None,
                   strategy: ParallelStrategy = ParallelStrategy.THREAD_POOL,
                   timeout_multiplier: float = 2.0):
    """流式执行生成器：每完成一个任务即 yield (task, result)。

    使用 ThreadPoolExecutor 提交所有任务后，
    通过 as_completed 语义逐个产出结果。
    适用于实时处理或增量持久化的长任务链。
    """
    analyzer = MulticoreParallelAnalyzer(num_workers=num_workers, strategy=strategy)
    active = [t for t in analyzer._tasks if not t.cancelled]
    if not active:
        for t_dict in tasks:
            analyzer.add_task(t_dict['func_name'], t_dict.get('binary_path', ''),
                             t_dict.get('estimated_seconds', 10.0),
                             t_dict.get('dependencies', []), t_dict.get('priority', 0))
        active = analyzer._tasks

    try:
        Executor = (ProcessPoolExecutor if strategy == ParallelStrategy.PROCESS_POOL
                   else ThreadPoolExecutor)
        with Executor(max_workers=analyzer.num_workers) as executor:
            fut_map: Dict[Future, AnalysisTask] = {}
            for task in active:
                fut = executor.submit(analyzer._retry_with_backoff, worker_func, task)
                fut_map[fut] = task

            # as_completed 语义：先完成先产出
            from concurrent.futures import as_completed
            for fut in as_completed(fut_map):
                task = fut_map[fut]
                try:
                    result = fut.result(timeout=task.estimated_seconds * timeout_multiplier)
                    task.result = result
                    task.completed = True
                    task.elapsed = time.monotonic()
                    yield (task, result)
                except Exception as e:
                    task.completed = False
                    yield (task, {'error': str(e)})
    except ImportError:
        for task in active:
            try:
                result = worker_func(task)
                task.completed = True
                yield (task, result)
            except Exception as e:
                task.completed = False
                yield (task, {'error': str(e)})

    # 最终汇总统计
    completed = sum(1 for t in active if t.completed)
    yield ({'summary': True, 'total': len(active),
            'completed': completed, 'failed': len(active) - completed}, None)


__all__ = ["MulticoreParallelAnalyzer", "TaskPartitioner", "AnalysisTask",
           "ParallelStrategy", "WorkerStats", "ProgressTracker",
           "WorkStealingQueue", "analyze_multicore_parallel",
           "execute_with_progress", "ensemble_vote", "stream_results"]


# 推测执行——预测慢任务并提前在多个 worker 上冗余执行
# Dean & Barroso. The Tail at Scale. CACM 2013.
#       Ananthanarayanan et al. GRASS: Trimming Stragglers. NSDI 2014.
# 长尾延迟的本质：一个慢任务阻塞整个 batch。
# 对策：任务运行超过 p95 耗时阈值时，在另一 worker 启动克隆。
# 先完成者的结果被采用——推测执行的核心机制。

class SpeculativeScheduler:
    """推测执行调度器：检测 straggler 并启动克隆任务。

    任务耗时超过自适应阈值时自动启动克隆副本。
    克隆与原任务竞争，先完成者的结果被采用。
    自适应阈值 = EWMA + k·σ，k 默认 2.5（覆盖约 99% 正常波动）。
    """

    def __init__(self, clone_multiplier: float = 2.5, max_clones: int = 2):
        self.clone_mult = clone_multiplier
        self.max_clones = max_clones
        self._task_times: List[float] = []
        self._ewma: float = 10.0
        self._ewma_var: float = 25.0
        self._alpha: float = 0.1

    def should_clone(self, task: AnalysisTask) -> bool:
        """判断是否应对该任务启动克隆。

        条件：运行时间 > EWMA + clone_mult·σ，且未达最大克隆数。
        """
        if task.cancelled or task.completed:
            return False
        if task.retries >= self.max_clones:
            return False
        if not self._task_times or len(self._task_times) < 5:
            # 数据不足时使用静态阈值 30s
            return (task.elapsed or 0.0) > 30.0

        _threshold = self._ewma + self.clone_mult * math.sqrt(max(0.01, self._ewma_var))
        _elapsed = task.elapsed or 0.0
        return _elapsed > _threshold

    def record_completion(self, elapsed: float):
        """记录任务完成耗时，更新 EWMA 统计量。"""
        self._task_times.append(elapsed)
        self._ewma = self._alpha * elapsed + (1 - self._alpha) * self._ewma
        self._ewma_var = (self._alpha * (elapsed - self._ewma) ** 2
                         + (1 - self._alpha) * self._ewma_var)

    def current_threshold(self) -> float:
        """当前克隆触发阈值（EWMA + k·σ）。"""
        return round(self._ewma + self.clone_mult * math.sqrt(max(0.01, self._ewma_var)), 1)

    def straggler_rate(self) -> float:
        """历史 straggler 比率：超过阈值完成任务的比例。"""
        if not self._task_times:
            return 0.0
        _threshold = self.current_threshold()
        _count = sum(1 for t in self._task_times if t > _threshold)
        return round(_count / len(self._task_times), 3)


# 内存感知调度——基于当前可用内存动态调整 worker 数
# Hindman et al. Mesos: A Platform for Fine-Grained Resource Sharing.
#       NSDI 2011.
# 可用内存低于阈值时减少并行度以避免 OOM/swap 抖动；
# 内存充裕时增加 worker 以最大化吞吐。

class MemoryAwareScheduler:
    """内存感知调度器：基于系统内存压力自适应调整并发度。

    内存使用率 = 1 - (available / total)。
    水位线策略：
    - mem_usage < 60%：全速 (base_workers)
    - 60-80%：缩减至 base_workers × 0.7
    - 80-90%：缩减至 base_workers × 0.4
    - > 90%：缩减至 1（保底单 worker）
    """

    def __init__(self, base_workers: int = 4):
        self.base_workers = base_workers
        self._mem_history: List[float] = []

    def recommend_workers(self) -> int:
        """基于当前可用内存推荐最优 worker 数。"""
        _avail = _mem_available_mb()
        # 估算总内存：假设可用内存通常占总内存的 40-60%
        _estimated_total = _avail / 0.5
        _usage_pct = (1.0 - _avail / max(1, _estimated_total)) * 100.0

        if _usage_pct < 60:
            _rec = self.base_workers
        elif _usage_pct < 80:
            _rec = max(1, int(self.base_workers * 0.7))
        elif _usage_pct < 90:
            _rec = max(1, int(self.base_workers * 0.4))
        else:
            _rec = 1

        self._mem_history.append(_avail)
        if len(self._mem_history) > 100:
            self._mem_history.pop(0)
        return _rec

    def memory_pressure_index(self) -> float:
        """内存压力指数 ∈ [0, 1]，越高表示内存越紧张。"""
        if not self._mem_history:
            return 0.0
        _avail = _mem_available_mb()
        _min_hist = min(self._mem_history)
        _max_hist = max(self._mem_history)
        _range = _max_hist - _min_hist
        if _range < 1.0:
            return 0.5
        return round(1.0 - (_avail - _min_hist) / _range, 3)

    def is_thrashing(self) -> bool:
        """检测是否存在内存抖动（可用内存剧烈波动且绝对值低）。"""
        if len(self._mem_history) < 10:
            return False
        _recent = self._mem_history[-10:]
        _mean = sum(_recent) / 10
        _var = sum((x - _mean) ** 2 for x in _recent) / 10
        # 高方差 + 低可用内存 → 可能在 swap
        _is_low = _mean < 512  # MB
        _is_volatile = _var > 10000
        return _is_low and _is_volatile


# 管道并行——将任务拆分为阶段并在流水线中执行
# Huang et al. GPipe: Efficient Training of Giant Neural Networks. 2019.
# 各阶段并行处理不同 micro-batch，提高整体吞吐。
# 适用于"扫描→分析→报告"的链式流程。

class PipelineExecutor:
    """管道执行器：任务划分为串行阶段，流水线式处理。

    每个阶段是转换函数 f_i: input → output，
    输入被分为 micro_batches，各阶段在 micro_batch 上并行。
    预热后管道稳态吞吐 = min(各阶段吞吐量)。
    """

    def __init__(self, stages: List[Callable], n_microbatches: int = 4):
        self.stages = stages
        self.n_micro = n_microbatches
        self._stage_times: List[List[float]] = [[] for _ in range(len(stages))]

    def execute(self, inputs: List[Any]) -> List[Any]:
        """流水线执行：各阶段在 micro-batch 上并行处理。

        返回每个输入的最终处理结果，保持输入顺序。
        """
        _n_stages = len(self.stages)
        if _n_stages == 0 or not inputs:
            return inputs

        # 输入切分为 micro-batches
        _batch_size = max(1, len(inputs) // self.n_micro)
        _batches: List[List[Any]] = []
        for _b in range(0, len(inputs), _batch_size):
            _batches.append(inputs[_b:_b + _batch_size])

        # 流水线推进：stage × micro_batch
        _results: List[List[Any]] = _batches[:] if _batches else []

        for _si in range(_n_stages):
            _stage_fn = self.stages[_si]
            _next_results: List[List[Any]] = []
            _stage_start = time.monotonic()
            for _mb in _results:
                _mb_result = []
                for _item in _mb:
                    _r = _stage_fn(_item)
                    _mb_result.append(_r)
                _next_results.append(_mb_result)
            _results = _next_results
            self._stage_times[_si].append(time.monotonic() - _stage_start)

        # 结果展平为一维列表
        _flat: List[Any] = []
        for _mb in _results:
            _flat.extend(_mb)
        return _flat[:len(inputs)]

    def stage_throughput(self) -> List[float]:
        """各阶段平均吞吐量 (items/sec)。"""
        _tp = []
        for _si, _times in enumerate(self._stage_times):
            if _times:
                _tp.append(round(1.0 / (sum(_times) / len(_times) + _EPS), 2))
            else:
                _tp.append(0.0)
        return _tp

    def bottleneck_stage(self) -> int:
        """当前瓶颈阶段索引（吞吐最低的阶段）。"""
        _tp = self.stage_throughput()
        if not _tp:
            return -1
        return min(range(len(_tp)), key=lambda i: _tp[i])
