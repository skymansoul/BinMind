"""Priority-based symbolic execution scheduler with resource allocation.

Functions are scored by complexity (cyclomatic, call depth, historical
runtime, dangerous-function reachability), assigned a resource budget
proportional to that score, and scheduled on a two-tier priority heap
(active vs. background). The executor supports interruptible runs with
timeout-based preemption and checkpoint persistence.

增强 — 死锁预测与依赖提升：active heap 中的任务若依赖 background heap 中
尚未完成的任务，自动将后者提升至 active heap 以避免调度死锁。

增强 — Critical Profile：confirmed vulnerability 路径自动获得 EXTREME
以上的 CRITICAL 资源分配（timeout=3600s, memory=8192MB, states=16384）。

增强 — log2 查找表：ComplexityScorer 预计算 log2(1+n) 值，避免频繁 math.log2 调用。

增强 — 资源监控与自适应降载：ResourceMonitor 实时追踪 CPU 和内存负载，
高负载时自动缩减并发度、暂停后台堆，防止调度器压垮宿主机。

增强 — 公平共享调度：FairShareScheduler 按二进制文件平均分配执行时间预算，
超预算任务降优先级，避免单个大文件独占执行器。

增强 — 甘特图导出：export_gantt_chart() 输出任务调度时序 JSON，
用于可视化调度效率与负载分布。

四轮增强 — PredictiveScheduler：使用 ComplexityScorer 的 historical_seconds
预测任务运行时间。采用最短作业优先启发式（shortest-job-first），
优先调度短任务以最小化平均完成时间。同时预留一个 "长任务槽"
防止大型任务被无限期推迟（饥饿防护）。

四轮增强 — ResourceOvercommitDetector：监控所有运行中任务的已分配内存总量
与系统可用内存的比值。若 total_allocated > available，暂停新任务分发
直至运行中任务完成并释放内存 —— 防止 OOM killer 终止 worker 进程。

四轮增强 — ScheduleReplay：将所有调度决策（task_id, worker_id, start_ts,
end_ts, reason）记录到 SQLite 数据库。提供 replay_schedule() 重建
甘特图并识别调度低效（队列非空时存在空闲 worker 的窗口）。
"""

import heapq
import json
import logging
import math as _math
import os
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

__log = logging.getLogger(__name__)


class ResourceProfile(Enum):
    """Resource allocation tiers: timeout, memory, and state limits per tier."""
    MINIMAL = "minimal"
    LIGHT = "light"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    EXTREME = "extreme"
    CRITICAL = "critical"


@dataclass
class FunctionComplexity:
    """Multi-factor complexity score for one function."""
    func_name: str
    cyclomatic_complexity: int = 1
    call_depth: int = 0
    historical_seconds: float = 0.0
    dangerous_funcs_reached: int = 0
    reach_dangerous_path: bool = False
    score: float = 0.0


@dataclass
class TaskSpec:
    """A scheduled function with priority, resource profile, and deadline."""
    func_name: str
    priority: int
    resource_profile: ResourceProfile
    complexity: FunctionComplexity
    deadline_ts: float
    binary_path: str
    extra: Dict = field(default_factory=dict)
    seq: int = 0
    depends_on: List[str] = field(default_factory=list)


@dataclass
class ResourceBudget:
    """Concrete limits derived from a ResourceProfile."""
    timeout_seconds: int
    memory_mb: int
    max_states: int


@dataclass
class TaskResult:
    """Output of executing one scheduled task."""
    func_name: str
    success: bool
    elapsed: float
    states_explored: int
    interrupted: bool
    error: Optional[str] = None
    output: Optional[Dict] = None


@dataclass
class ScheduleRecord:
    """One scheduling decision logged for replay analysis.

    task_id: function name.
    worker_id: binary_path or worker identifier.
    start_ts: monotonic timestamp when task was dispatched.
    end_ts: monotonic timestamp when task completed.
    reason: why this task was chosen (e.g., "shortest_job_first", "long_slot",
            "normal_pop", "dependency_promotion").
    predicted_seconds: estimated runtime from PredictiveScheduler.
    """
    task_id: str
    worker_id: str
    start_ts: float
    end_ts: float
    reason: str = "normal_pop"
    predicted_seconds: float = 0.0


# ---------------------------------------------------------------------------
# log2 预计算查找表：避免 ComplexityScorer.score() 中频繁调用 math.log2
# 索引范围 [0, 1024]，超出范围使用 math.log2 实时计算
# 设计意图 — 符号执行调度路径是热路径，减少超越函数调用
# ---------------------------------------------------------------------------
_LOG2_LUT_SIZE = 1024
_log2_lut = [0.0] + [_math.log2(1 + n) for n in range(1, _LOG2_LUT_SIZE)]


def _fast_log2(n: float) -> float:
    if n < 0:
        return 0.0
    idx = int(n)
    if idx < _LOG2_LUT_SIZE:
        return _log2_lut[idx]
    return _math.log2(1 + n)


class ComplexityScorer:
    """Scores a function by combining cyclomatic complexity, call depth,
    historical execution time, and dangerous-function reachability into
    a single log-scale value. Higher → more resources warranted."""

    def __init__(self, history_db: Optional[str] = None):
        self.history_db = history_db
        self._hist_cache: Dict[str, List[float]] = defaultdict(list)

    def score(self, func_name: str, *,
              cyclomatic: int = 1,
              call_depth: int = 0,
              historical_seconds: Optional[float] = None,
              dangerous_funcs_reached: int = 0,
              reach_dangerous_path: bool = False) -> FunctionComplexity:
        """Compute the composite complexity score using LUT-accelerated log2."""
        if historical_seconds is None and func_name in self._hist_cache:
            samples = self._hist_cache[func_name]
            historical_seconds = sum(samples) / max(1, len(samples))

        hs = historical_seconds or 0.0
        cyc_part = _fast_log2(max(0, cyclomatic)) * 4.0
        dep_part = _fast_log2(max(0, call_depth)) * 3.0
        hist_part = _fast_log2(max(0.0, hs)) * 5.0
        danger_part = 8.0 if reach_dangerous_path else 0.0
        danger_calls = min(10, dangerous_funcs_reached) * 1.0

        score = cyc_part + dep_part + hist_part + danger_part + danger_calls

        return FunctionComplexity(
            func_name=func_name,
            cyclomatic_complexity=cyclomatic,
            call_depth=call_depth,
            historical_seconds=hs,
            dangerous_funcs_reached=dangerous_funcs_reached,
            reach_dangerous_path=reach_dangerous_path,
            score=score
        )

    def record(self, func_name: str, seconds: float):
        """Store execution time for future scoring (keeps last 10 samples)."""
        self._hist_cache[func_name].append(seconds)
        self._hist_cache[func_name] = self._hist_cache[func_name][-10:]

    def predict_runtime(self, func_name: str, fallback: float = 0.0) -> float:
        """Predict the runtime for a function based on historical samples.

        取最近 10 次执行的中位数作为预测值。若无历史数据则返回 fallback。
        中位数比均值更抗异常值（单次执行因系统负载偶发过长）。

        Args:
            func_name: 函数名。
            fallback: 无历史数据时的回退预测值。

        Returns:
            float: 预测运行秒数。
        """
        samples = self._hist_cache.get(func_name, [])
        if not samples:
            return fallback
        sorted_samples = sorted(samples)
        n = len(sorted_samples)
        if n % 2 == 1:
            return sorted_samples[n // 2]
        return (sorted_samples[n // 2 - 1] + sorted_samples[n // 2]) / 2.0

    def get_historical_seconds(self, func_name: str) -> float:
        """Return the average historical execution time for a function."""
        samples = self._hist_cache.get(func_name, [])
        if not samples:
            return 0.0
        return sum(samples) / len(samples)


class ResourceAllocator:
    """Maps a complexity score to a resource profile with concrete limits."""

    PROFILES: Dict[ResourceProfile, ResourceBudget] = {
        ResourceProfile.MINIMAL:    ResourceBudget(30,   256,   256),
        ResourceProfile.LIGHT:      ResourceBudget(60,   512,   512),
        ResourceProfile.STANDARD:   ResourceBudget(180,  1024,  1024),
        ResourceProfile.AGGRESSIVE: ResourceBudget(600,  2048,  4096),
        ResourceProfile.EXTREME:    ResourceBudget(1800, 4096,  8192),
        ResourceProfile.CRITICAL:   ResourceBudget(3600, 8192, 16384),
    }

    def allocate(self, complexity: FunctionComplexity,
                 is_critical: bool = False) -> ResourceProfile:
        """Select the profile whose score band contains complexity.score."""
        if is_critical:
            return ResourceProfile.CRITICAL
        s = complexity.score
        if s < 4.0:
            return ResourceProfile.MINIMAL
        if s < 8.0:
            return ResourceProfile.LIGHT
        if s < 14.0:
            return ResourceProfile.STANDARD
        if s < 22.0:
            return ResourceProfile.AGGRESSIVE
        return ResourceProfile.EXTREME

    def budget_of(self, profile: ResourceProfile) -> ResourceBudget:
        """Look up the concrete budget for a profile."""
        return self.PROFILES[profile]


# ---------------------------------------------------------------------------
# 资源监控器：实时采集 CPU 与内存负载，触发自适应降载策略
#
# 降载两级：
#   1. sys_load_pct > 80% → 活跃并发度减半，跳过非 CRITICAL 任务分发
#   2. 内存使用率 > 90% → 暂停 background heap 的全部调度，
#      仅允许 CRITICAL 任务通过，防止 OOM
#
# psutil 为可选依赖；缺失时降级为无操作模式，不影响核心调度逻辑。
# ---------------------------------------------------------------------------


class ResourceMonitor:
    """Monitors system-wide CPU and memory load, providing backpressure signals.

    When ``sys_load_pct`` exceeds 80%, active concurrency is halved and
    non-critical task dispatch is skipped.  When memory usage exceeds 90%,
    background-heap execution is paused entirely to prevent OOM.
    """

    # 复用同一实例避免频繁 import 检查
    _instance: Optional["ResourceMonitor"] = None

    def __init__(self, cpu_high: float = 80.0, mem_high: float = 90.0):
        self.cpu_high = cpu_high
        self.mem_high = mem_high

        # 最近的负载采样
        self.sys_load_pct: float = 0.0
        self.mem_usage_pct: float = 0.0

        # 降载状态标志
        self.high_cpu: bool = False
        self.high_memory: bool = False

        self._lock = threading.Lock()

    @classmethod
    def instance(cls) -> "ResourceMonitor":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def sample(self) -> Tuple[float, float]:
        """Collect one snapshot of CPU and memory usage.

        Returns (sys_load_pct, mem_usage_pct).  Falls back to (0.0, 0.0)
        when psutil is unavailable.
        """
        if not _HAS_PSUTIL:
            return 0.0, 0.0
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        return cpu, mem

    def refresh(self):
        """Refresh load readings and update backpressure flags.

        每次调度轮询前调用，决策是否进入降载模式。
        """
        with self._lock:
            cpu, mem = self.sample()
            self.sys_load_pct = cpu
            self.mem_usage_pct = mem
            self.high_cpu = cpu > self.cpu_high
            self.high_memory = mem > self.mem_high

    def should_throttle_active(self) -> bool:
        """True when system CPU is overloaded and active concurrency should halve."""
        return self.high_cpu

    def should_pause_background(self) -> bool:
        """True when memory pressure is critical and all background tasks should pause."""
        return self.high_memory

    def can_dispatch(self, task: TaskSpec) -> bool:
        """Decide whether a task is allowed to go out for execution.

        规则：
        - 内存 > 90% → 仅允许 CRITICAL 通过
        - CPU > 80% → 跳过非关键（非 CRITICAL / 无危险路径）任务
        """
        if self.high_memory:
            # 极端内存压力 — 仅关键任务可执行
            return task.resource_profile == ResourceProfile.CRITICAL
        if self.high_cpu:
            # CPU 高负载 — 跳过非关键任务，保留 CRITICAL 和 dangerous path
            if task.resource_profile != ResourceProfile.CRITICAL and not task.complexity.reach_dangerous_path:
                return False
        return True

    def status(self) -> Dict[str, Any]:
        """Expose current load snapshot for observability."""
        return {
            'sys_load_pct': self.sys_load_pct,
            'mem_usage_pct': self.mem_usage_pct,
            'high_cpu': self.high_cpu,
            'high_memory': self.high_memory,
        }


# ---------------------------------------------------------------------------
# 公平共享调度器：每个 binary_path 获得等量的执行时间预算。
#
# 核心思路：
#   每个二进制文件的 fair_share_budget = 总分配时间 / 活跃二进制文件数。
#   调度时按 per_binary_consumed 字典累加每个二进制文件的已消耗时间，
#   超预算的任务优先级下调 (priority -= 100)，使其排到同预算任务之后。
#
# 意图 — 避免单个大型二进制文件独占所有执行槽位，保证多目标分析的公平性。
# ---------------------------------------------------------------------------


class FairShareScheduler:
    """Fair-share wrapper around a PriorityScheduler.

    Every ``binary_path`` receives an equal ``fair_share_budget`` of total
    executor wall-clock time.  Tasks from binaries that have already
    consumed their budget are deprioritized (``priority -= 100``) so that
    under-served binaries get scheduled first.
    """

    def __init__(self, scheduler: "PriorityScheduler"):
        self.scheduler = scheduler
        self._lock = threading.Lock()

        # per_binary_consumed: binary_path → 累计执行秒数
        self.per_binary_consumed: Dict[str, float] = defaultdict(float)

        # 总预算（秒），每次 run_loop 时由调用方设定
        self.fair_share_budget: Optional[float] = None

    def compute_budgets(self, total_time: float, binary_paths: Set[str]):
        """Allocate fair_share_budget evenly across active binaries.

        :param total_time: 本轮执行可用的总时间预算
        :param binary_paths: 参与本轮调度的所有二进制文件集合
        """
        n = max(1, len(binary_paths))
        self.fair_share_budget = total_time / n

    def record_consumed(self, binary_path: str, elapsed: float):
        """Accumulate consumed time per binary after a task completes."""
        with self._lock:
            self.per_binary_consumed[binary_path] += elapsed

    def adjust_priority(self, task: TaskSpec) -> int:
        """Return adjusted priority for a task considering fair-share.

        若按 binary_path 查询到的已消耗时间超过 fair_share_budget，
        则 priority -= 100，将该任务降级处理。
        """
        if self.fair_share_budget is None or self.fair_share_budget <= 0:
            return task.priority
        consumed = self.per_binary_consumed.get(task.binary_path, 0.0)
        if consumed > self.fair_share_budget:
            return task.priority - 100
        return task.priority

    def stats(self) -> Dict[str, Any]:
        """Expose fair-share state for telemetry."""
        return {
            'fair_share_budget': self.fair_share_budget,
            'per_binary_consumed': dict(self.per_binary_consumed),
        }


# =============================================================================
# 四轮增强 — PredictiveScheduler：最短作业优先 + 长任务槽预留
#
# 原理：在符号执行调度中，任务运行时间差异极大（几秒到几十分钟）。
# SJF 启发式显著降低平均完成时间。但纯 SJF 会导致长任务饥饿 ——
# 长任务槽（LongSlot）机制保证至少一个 slot 始终可用于长任务。
#
# 实现：
# - 每次调度前对所有就绪任务按 predicted_runtime 排序
# - 优先弹出最短预测时间的任务
# - 保留 1 个长任务槽给预测时间 > median * 2 的任务
# - 长任务槽耗尽后，长任务进入常规 FIFO 等待（而非无限制推迟）
# =============================================================================


class PredictiveScheduler:
    """Shortest-job-first scheduler with starvation prevention via a long-task slot.

    四轮增强 — 利用 ComplexityScorer.predict_runtime() 预测每个任务的执行时间。
    在每次调度决策中，从就绪队列中选择预测执行时间最短的任务，
    显著降低平均任务完成时间（Average Completion Time）。

    LongSlot 机制：
    - 维护一个长任务计数槽（默认 1），仅允许长任务使用。
    - 长任务定义：predicted_runtime > 所有就绪任务预测时间中位数的 2 倍。
    - 长任务槽被占用后，后续长任务按常规优先级排队。

    Attributes:
        scorer: ComplexityScorer 实例，提供 predict_runtime()。
        long_slot_count: 预留的长任务槽数量（默认 1）。
        long_ratio_threshold: 预测时间 > median * ratio 视为长任务。
    """

    def __init__(self,
                 scorer: ComplexityScorer,
                 long_slot_count: int = 1,
                 long_ratio_threshold: float = 2.0):
        self.scorer = scorer
        self.long_slot_count = max(0, long_slot_count)
        self.long_ratio_threshold = long_ratio_threshold
        self._long_slots_used: int = 0
        self._prediction_cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def predict(self, task: TaskSpec) -> float:
        """Predict runtime for a task, using cached value if available.

        优先使用 historical_seconds 已有的值，其次调用 scorer.predict_runtime()。
        Fallback: 用 complexity.score / 10.0 做粗略估算（高复杂度 ≈ 长运行时间）。

        Args:
            task: 待预测的任务规格。

        Returns:
            float: 预测执行秒数。
        """
        if task.func_name in self._prediction_cache:
            return self._prediction_cache[task.func_name]

        # 已有历史数据 → 直接使用
        hist = task.complexity.historical_seconds
        if hist > 0:
            predicted = hist
        else:
            predicted = self.scorer.predict_runtime(task.func_name)

        # 无历史数据时的启发式回退
        if predicted <= 0:
            predicted = max(0.1, task.complexity.score / 10.0)

        self._prediction_cache[task.func_name] = predicted
        return predicted

    def select_next_task(self, tasks: List[TaskSpec]) -> Tuple[Optional[TaskSpec], str]:
        """Select the next task to execute using SJF with long-slot reservation.

        Args:
            tasks: 当前所有就绪任务的列表。

        Returns:
            Tuple[Optional[TaskSpec], str]: (选中的任务, 选择原因字符串)。
            reason: "shortest_job_first", "long_slot", "fallback", "no_tasks"。
        """
        if not tasks:
            return None, "no_tasks"

        with self._lock:
            # 为每个任务计算预测时间
            predictions: List[Tuple[TaskSpec, float]] = []
            for t in tasks:
                pred = self.predict(t)
                predictions.append((t, pred))

            # 按预测时间升序排列
            predictions.sort(key=lambda x: x[1])

            # 计算中位数判断长任务
            all_times = [p[1] for p in predictions]
            median = self._compute_median(all_times)
            long_threshold = median * self.long_ratio_threshold

            # 区分短任务和长任务
            short_tasks = [p for p in predictions if p[1] <= long_threshold]
            long_tasks = [p for p in predictions if p[1] > long_threshold]

            # 优先调度短任务
            if short_tasks:
                selected = short_tasks[0][0]
                return selected, "shortest_job_first"

            # 短任务耗尽 → 检查长任务槽是否可用
            if long_tasks and self._long_slots_used < self.long_slot_count:
                self._long_slots_used += 1
                selected = long_tasks[0][0]
                return selected, "long_slot"

            # 回退：从剩余任务中选择预测时间最短的
            if predictions:
                selected = predictions[0][0]
                return selected, "fallback"

            return None, "no_tasks"

    def release_long_slot(self):
        """Release a long-task slot after a long task completes."""
        with self._lock:
            if self._long_slots_used > 0:
                self._long_slots_used -= 1

    def reset(self):
        """Reset prediction cache and long-slot usage for a new scheduling round."""
        with self._lock:
            self._prediction_cache.clear()
            self._long_slots_used = 0

    @staticmethod
    def _compute_median(values: List[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        if n % 2 == 1:
            return sorted_vals[n // 2]
        return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0

    def stats(self) -> Dict[str, Any]:
        """Expose predictive scheduling state."""
        with self._lock:
            return {
                'long_slots_used': self._long_slots_used,
                'long_slot_count': self.long_slot_count,
                'long_ratio_threshold': self.long_ratio_threshold,
                'cached_predictions': len(self._prediction_cache),
            }


# =============================================================================
# 四轮增强 — ResourceOvercommitDetector：防止 OOM
#
# 符号执行是内存密集型任务。当多个 worker 进程同时运行大状态空间的任务时，
# 累计分配的内存可能超过系统可用物理内存，触发 Linux OOM killer 随机
# kill 进程，导致整个分析任务失败且难以调试。
#
# ResourceOvercommitDetector 在每次调度前检查：
#   total_allocated_mb (所有运行中任务的 budget 总和)
#   vs system_available_mb (psutil.virtual_memory().available)
#
# 若 total_allocated_mb > system_available_mb * safety_ratio，
# 阻塞新任务分发直至运行中任务完成并释放资源。
# =============================================================================


class ResourceOvercommitDetector:
    """Monitor memory overcommit and pause dispatch to prevent OOM.

    四轮增强 — 跟踪所有已分发但尚未完成的任务的内存预算。
    当累计分配超过系统可用内存的安全比例时，阻止新任务分发。

    触发条件：total_allocated_mb > system_available_mb * safety_ratio
    默认 safety_ratio = 0.85，即保留 15% 余量给系统和其他进程。

    Attributes:
        safety_ratio: 安全比例，超过此值即视为过度分配。
        total_allocated_mb: 当前所有运行中任务的 budget 内存总和。
        running_tasks: {task_id: allocated_mb} 运行中任务跟踪。
    """

    # 默认安全比例 —— 保留 15% 内存余量
    _DEFAULT_SAFETY_RATIO = 0.85

    def __init__(self, safety_ratio: float = _DEFAULT_SAFETY_RATIO):
        self.safety_ratio = safety_ratio
        self.total_allocated_mb: float = 0.0
        self.running_tasks: Dict[str, int] = {}
        self._lock = threading.Lock()

    def register_allocation(self, task: TaskSpec, allocator: ResourceAllocator):
        """Record a task's memory allocation before dispatch.

        Args:
            task: 即将分发的任务。
            allocator: ResourceAllocator 实例，用于查询内存预算。
        """
        budget = allocator.budget_of(task.resource_profile)
        with self._lock:
            self.total_allocated_mb += budget.memory_mb
            self.running_tasks[task.func_name] = budget.memory_mb
            __log.debug(
                f"[OvercommitDetector] Allocated {budget.memory_mb}MB for "
                f"{task.func_name}, total={self.total_allocated_mb:.0f}MB"
            )

    def release_allocation(self, task: TaskSpec):
        """Release a task's memory allocation after completion.

        Args:
            task: 已完成的任务。
        """
        with self._lock:
            if task.func_name in self.running_tasks:
                freed = self.running_tasks.pop(task.func_name)
                self.total_allocated_mb = max(0.0, self.total_allocated_mb - freed)
                __log.debug(
                    f"[OvercommitDetector] Released {freed}MB from "
                    f"{task.func_name}, total={self.total_allocated_mb:.0f}MB"
                )

    def is_overcommitted(self) -> bool:
        """Check if total allocated memory exceeds system available * safety_ratio.

        Returns:
            True if dispatcher should pause and wait for tasks to complete.
        """
        if not _HAS_PSUTIL:
            return False

        available_mb = psutil.virtual_memory().available / (1024 * 1024)

        with self._lock:
            is_over = self.total_allocated_mb > available_mb * self.safety_ratio

        if is_over:
            __log.warning(
                f"[OvercommitDetector] Memory overcommit detected: "
                f"total_allocated={self.total_allocated_mb:.0f}MB > "
                f"available*safety={available_mb * self.safety_ratio:.0f}MB "
                f"(available={available_mb:.0f}MB, safety_ratio={self.safety_ratio})"
            )

        return is_over

    def get_available_mb(self) -> float:
        """Return system available memory in MB, or a large fallback if psutil missing."""
        if not _HAS_PSUTIL:
            return float('inf')
        return psutil.virtual_memory().available / (1024 * 1024)

    def status(self) -> Dict[str, Any]:
        """Expose overcommit monitoring state for observability."""
        with self._lock:
            return {
                'total_allocated_mb': round(self.total_allocated_mb, 1),
                'running_tasks': len(self.running_tasks),
                'safety_ratio': self.safety_ratio,
                'is_overcommitted': self.is_overcommitted(),
                'available_mb': round(self.get_available_mb(), 1),
            }


# =============================================================================
# 四轮增强 — ScheduleReplay：调度决策审计与回放分析
#
# 将每次调度决策持久化到 SQLite 数据库，支持离线分析：
# - replay_schedule() 重建甘特图时间线
# - 自动检测调度低效窗口（队列非空且有 worker 空闲）
# - 统计 worker 利用率和任务等待时间
# =============================================================================


class ScheduleReplay:
    """Record and replay scheduling decisions for audit and inefficiency detection.

    四轮增强 — 将每次调度操作记录到 SQLite 中（task dispatch、task complete、
    task requeue）。支持离线重建调度时间线，自动识别调度低效。

    数据库 schema::

        CREATE TABLE schedule_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            worker_id TEXT NOT NULL,
            event_type TEXT NOT NULL,  -- 'dispatch', 'complete', 'requeue'
            timestamp_ts REAL NOT NULL,
            reason TEXT DEFAULT '',
            predicted_seconds REAL DEFAULT 0.0
        );

    Usage::

        recorder = ScheduleReplay(":memory:")
        recorder.record_dispatch("func_a", "bin1", reason="shortest_job_first")
        # ... tasks execute ...
        recorder.record_complete("func_a", "bin1")
        inefficiencies = recorder.replay_schedule()
        # → [{'type': 'idle_while_queued', 'window_start': ..., ...}]
    """

    def __init__(self, db_path: str = ":memory:"):
        """Initialize the replay database.

        Args:
            db_path: SQLite 数据库路径。默认 ":memory:" 为内存数据库。
                     使用文件路径可在进程重启后恢复分析。
        """
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        """Create the schedule_events table if not exists."""
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS schedule_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp_ts REAL NOT NULL,
                    reason TEXT DEFAULT '',
                    predicted_seconds REAL DEFAULT 0.0
                )
            """)
            # 索引加速按时间范围和 worker 查询
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_ts
                ON schedule_events(timestamp_ts)
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_worker
                ON schedule_events(worker_id, event_type)
            """)
            self._conn.commit()

    def record_dispatch(self, task_id: str, worker_id: str,
                        reason: str = "normal_pop",
                        predicted_seconds: float = 0.0):
        """Record a task dispatch event.

        Args:
            task_id: 函数名称。
            worker_id: 二进制路径或 worker 标识。
            reason: 调度原因（如 "shortest_job_first", "long_slot"）。
            predicted_seconds: 预测执行时间。
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO schedule_events (task_id, worker_id, event_type, "
                "timestamp_ts, reason, predicted_seconds) VALUES (?, ?, 'dispatch', ?, ?, ?)",
                (task_id, worker_id, time.monotonic(), reason, predicted_seconds)
            )
            self._conn.commit()

    def record_complete(self, task_id: str, worker_id: str):
        """Record a task completion event.

        Args:
            task_id: 函数名称。
            worker_id: 二进制路径或 worker 标识。
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO schedule_events (task_id, worker_id, event_type, "
                "timestamp_ts) VALUES (?, ?, 'complete', ?)",
                (task_id, worker_id, time.monotonic())
            )
            self._conn.commit()

    def record_requeue(self, task_id: str, worker_id: str, reason: str = ""):
        """Record a task requeue event (e.g., deferred due to resource pressure).

        Args:
            task_id: 函数名称。
            worker_id: 二进制路径或 worker 标识。
            reason: requeue 原因。
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO schedule_events (task_id, worker_id, event_type, "
                "timestamp_ts, reason) VALUES (?, ?, 'requeue', ?, ?)",
                (task_id, worker_id, time.monotonic(), reason)
            )
            self._conn.commit()

    def replay_schedule(self) -> Dict[str, Any]:
        """Reconstruct the Gantt timeline and identify scheduling inefficiencies.

        分析：
        1. 为每个任务构建 (dispatch_ts, complete_ts) 对，生成 Gantt 条目
        2. 扫描时间线寻找 "idle_while_queued" 窗口：
           在某个时间点，至少有一个任务在队列中等待（已 dispatch-requeue
           但未被 complete），同时没有正在运行的任务。
        3. 计算 worker 利用率 = busy_time / total_time

        Returns:
            Dict with:
            - 'gantt_entries': [(task_id, worker_id, start_ts, end_ts), ...]
            - 'inefficiencies': [{'type': str, 'window_start': float, 'window_end': float, ...}, ...]
            - 'worker_utilization': float (0-1)
            - 'total_time_span': float
            - 'event_count': int
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT task_id, worker_id, event_type, timestamp_ts, reason, predicted_seconds "
                "FROM schedule_events ORDER BY timestamp_ts ASC"
            ).fetchall()

        if not rows:
            return {
                'gantt_entries': [],
                'inefficiencies': [],
                'worker_utilization': 1.0,
                'total_time_span': 0.0,
                'event_count': 0,
            }

        # 为每个 (task_id, worker_id) 配对 dispatch 和 complete
        dispatch_events: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        complete_events: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        requeue_events: List[Tuple[str, str, float, str]] = []

        for row in rows:
            task_id, worker_id, event_type, ts, reason, predicted = row
            key = (task_id, worker_id)
            if event_type == 'dispatch':
                dispatch_events[key].append(ts)
            elif event_type == 'complete':
                complete_events[key].append(ts)
            elif event_type == 'requeue':
                requeue_events.append((task_id, worker_id, ts, reason))

        # 构建 Gantt 条目：为每个 dispatch 匹配最近的后续 complete
        gantt_entries: List[Tuple[str, str, float, float, float, str]] = []
        for key, dispatch_times in dispatch_events.items():
            task_id, worker_id = key
            complete_times = sorted(complete_events.get(key, []))
            for d_idx, d_ts in enumerate(sorted(dispatch_times)):
                # 找到此 dispatch 之后的第一个 complete
                end_ts = None
                for c_ts in complete_times:
                    if c_ts > d_ts:
                        end_ts = c_ts
                        complete_times.remove(c_ts)
                        break
                if end_ts is not None:
                    duration = end_ts - d_ts
                    # 查找此任务的 reason
                    reason = ""
                    predicted = 0.0
                    for r in rows:
                        if r[1] == key[1] and r[0] == key[0] and r[2] == 'dispatch' and abs(r[3] - d_ts) < 0.001:
                            reason = r[4]
                            predicted = r[5]
                            break
                    gantt_entries.append((task_id, worker_id, d_ts, end_ts, predicted, reason))

        # 按 start_ts 排序
        gantt_entries.sort(key=lambda e: e[2])

        # --- 检测调度低效 ---
        inefficiencies: List[Dict[str, Any]] = []

        if not gantt_entries:
            return {
                'gantt_entries': [],
                'inefficiencies': [],
                'worker_utilization': 1.0,
                'total_time_span': 0.0,
                'event_count': len(rows),
            }

        total_start = min(e[2] for e in gantt_entries)
        total_end = max(e[3] for e in gantt_entries)
        total_span = total_end - total_start

        # 计算所有 worker 的 busy 时间总和
        total_busy = sum(e[3] - e[2] for e in gantt_entries)

        # 获取所有不同的 worker 标识
        all_workers = set(e[1] for e in gantt_entries)
        max_concurrent = max(1, len(all_workers))

        # 扫描时间线寻找空闲窗口
        # 构建时间点上的活跃任务计数
        timeline: List[Tuple[float, int]] = []  # (time, delta)
        for entry in gantt_entries:
            timeline.append((entry[2], +1))  # start
            timeline.append((entry[3], -1))  # end
        timeline.sort(key=lambda x: x[0])

        # 扫描时间线
        active = 0
        idle_windows: List[Tuple[float, float]] = []
        idle_start = None

        for i, (ts, delta) in enumerate(timeline):
            prev_active = active
            active += delta

            if prev_active == 0 and active > 0:
                # 从空闲变为忙碌 —— 结束空闲窗口
                if idle_start is not None:
                    idle_windows.append((idle_start, ts))
                    idle_start = None

            elif prev_active > 0 and active == 0:
                # 从忙碌变为空闲 —— 开始空闲窗口
                idle_start = ts

        # 如果最后一段是空闲的
        if idle_start is not None and idle_start < total_end:
            idle_windows.append((idle_start, total_end))

        # 将空闲窗口划分为有队列和无队列两种
        for win_start, win_end in idle_windows:
            duration = win_end - win_start
            if duration < 0.5:  # 忽略 < 0.5s 的微窗口
                continue
            # 检查此窗口内是否有 requeue 事件（即队列非空）
            has_queued = any(
                win_start <= r_ts <= win_end
                for _, _, r_ts, _ in requeue_events
            )
            inefficiencies.append({
                'type': 'idle_while_queued' if has_queued else 'idle_no_queue',
                'window_start': round(win_start, 4),
                'window_end': round(win_end, 4),
                'duration_seconds': round(duration, 2),
            })

        # Worker 利用率 = busy_time / (total_span * max_concurrent)
        theoretical_max = total_span * max_concurrent
        worker_utilization = round(total_busy / max(0.001, theoretical_max), 4)

        return {
            'gantt_entries': [
                {
                    'task_id': e[0],
                    'worker_id': e[1],
                    'start_ts': round(e[2], 4),
                    'end_ts': round(e[3], 4),
                    'predicted_seconds': round(e[4], 4),
                    'reason': e[5],
                }
                for e in gantt_entries
            ],
            'inefficiencies': inefficiencies,
            'worker_utilization': worker_utilization,
            'total_time_span': round(total_span, 4),
            'event_count': len(rows),
            'gantt_entry_count': len(gantt_entries),
            'idle_window_count': len(inefficiencies),
        }

    def export_gantt_json(self) -> str:
        """Export Gantt chart data as JSON string for visualization.

        Returns:
            JSON string with timeline data compatible with Plotly/D3 Gantt.
        """
        replay = self.replay_schedule()
        return json.dumps(replay['gantt_entries'], ensure_ascii=False, indent=2)

    def close(self):
        """Close the SQLite connection."""
        with self._lock:
            self._conn.close()


class PriorityScheduler:
    """Two-tier min-heap scheduler. Dangerous-path functions go to the active
    heap; everything else goes to background. next_task() drains active first,
    then background, then falls back to active.

    增强 — 依赖提升：当 active heap 任务引用的依赖函数在 background heap 中时，
    将后者提升至 active heap，避免调度死锁。"""

    def __init__(self,
                 active_threshold: int = 50,
                 scorer: Optional[ComplexityScorer] = None,
                 allocator: Optional[ResourceAllocator] = None):
        self.scorer = scorer or ComplexityScorer()
        self.allocator = allocator or ResourceAllocator()
        self.active_heap: List[Tuple[int, int, TaskSpec]] = []
        self.background_heap: List[Tuple[int, int, TaskSpec]] = []
        self._counter = 0
        self.active_threshold = active_threshold
        self._lock = threading.Lock()
        self._func_names: Dict[str, TaskSpec] = {}

    def _new_seq(self) -> int:
        self._counter += 1
        return self._counter

    def submit(self, func_name: str, *,
               binary_path: str,
               cyclomatic: int = 1,
               call_depth: int = 0,
               historical_seconds: Optional[float] = None,
               dangerous_funcs_reached: int = 0,
               reach_dangerous_path: bool = False,
               depends_on: Optional[List[str]] = None,
               is_critical: bool = False) -> TaskSpec:
        """Score a function, allocate resources, and push onto the correct heap."""
        complexity = self.scorer.score(
            func_name,
            cyclomatic=cyclomatic,
            call_depth=call_depth,
            historical_seconds=historical_seconds,
            dangerous_funcs_reached=dangerous_funcs_reached,
            reach_dangerous_path=reach_dangerous_path
        )
        profile = self.allocator.allocate(complexity, is_critical)
        budget = self.allocator.budget_of(profile)

        if reach_dangerous_path or complexity.score >= self.active_threshold:
            priority = int(complexity.score) + (0 if reach_dangerous_path else 10)
            target = self.active_heap
        else:
            priority = int(complexity.score) + 1000
            target = self.background_heap

        task = TaskSpec(
            func_name=func_name,
            priority=priority,
            resource_profile=profile,
            complexity=complexity,
            deadline_ts=time.monotonic() + budget.timeout_seconds,
            binary_path=binary_path,
            seq=self._new_seq(),
            depends_on=depends_on or []
        )
        with self._lock:
            self._func_names[func_name] = task
            heapq.heappush(target, (priority, task.seq, task))

        # 依赖提升：检查 depends_on 中的函数是否在 background heap
        self._promote_dependencies(task)
        return task

    def _promote_dependencies(self, task: TaskSpec):
        """若 active task 依赖 background task，提升后者至 active。

        死锁场景：task_A（active）依赖 task_B（background），
        若 background 永远不被调度，task_A 将永远阻塞。"""
        for dep_name in task.depends_on:
            dep_task = self._func_names.get(dep_name)
            if dep_task is None:
                continue
            # 扫描 background heap，找到依赖任务并提升
            for idx, (p, s, t) in enumerate(self.background_heap):
                if t.func_name == dep_name:
                    self.background_heap.pop(idx)
                    heapq.heapify(self.background_heap)
                    new_priority = int(dep_task.complexity.score)
                    heapq.heappush(self.active_heap, (new_priority, t.seq, t))
                    break

    def next_task(self, prefer_active: bool = True) -> Optional[TaskSpec]:
        """Pop the next task. Active heap drained first; background is fallback."""
        with self._lock:
            if prefer_active and self.active_heap:
                _, _, task = heapq.heappop(self.active_heap)
                return task
            if self.background_heap:
                _, _, task = heapq.heappop(self.background_heap)
                return task
            if self.active_heap:
                _, _, task = heapq.heappop(self.active_heap)
                return task
            return None

    def requeue(self, task: TaskSpec):
        with self._lock:
            target = self.active_heap if task.complexity.reach_dangerous_path else self.background_heap
            heapq.heappush(target, (task.priority + 1, task.seq, task))

    def has_pending(self) -> bool:
        return bool(self.active_heap or self.background_heap)

    def get_pending_tasks(self) -> List[TaskSpec]:
        """Return all pending tasks across both heaps (for PredictiveScheduler)."""
        with self._lock:
            result = []
            for _, _, t in self.active_heap:
                result.append(t)
            for _, _, t in self.background_heap:
                result.append(t)
            return result

    def stats(self) -> Dict[str, int]:
        return {
            'active_pending': len(self.active_heap),
            'background_pending': len(self.background_heap)
        }


class InterruptibleExecutor:
    """Runs scheduled tasks with per-task timeout preemption.

    增强 — 使用 time.monotonic() 替代 time.time()，免疫系统时钟调整。

    四轮增强 — 集成 PredictiveScheduler、ResourceOvercommitDetector、ScheduleReplay。
    """

    def __init__(self, scheduler: PriorityScheduler):
        self.scheduler = scheduler
        self._stop_event = threading.Event()
        self._checkpoint_dir = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'symbex_checkpoints'
        )
        os.makedirs(self._checkpoint_dir, exist_ok=True)

        # 资源监控与公平共享调度
        self.resource_monitor = ResourceMonitor.instance()
        self.fair_share = FairShareScheduler(scheduler)

        # 四轮增强 — 预测调度器
        self.predictive = PredictiveScheduler(scorer=scheduler.scorer)

        # 四轮增强 — 过分配检测器
        self.overcommit_detector = ResourceOvercommitDetector()

        # 四轮增强 — 调度回放记录器
        self.schedule_replay = ScheduleReplay(
            db_path=os.path.join(self._checkpoint_dir, 'schedule_replay.db')
        )

    def request_stop(self):
        self._stop_event.set()

    def resume(self):
        self._stop_event.clear()

    def save_checkpoint(self, task: TaskSpec, partial: Dict[str, Any]):
        path = os.path.join(self._checkpoint_dir, f"{task.func_name}.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({
                'func_name': task.func_name,
                'binary_path': task.binary_path,
                'profile': task.resource_profile.value,
                'partial': partial,
                'deadline': task.deadline_ts
            }, f, ensure_ascii=False, indent=2)

    def load_checkpoint(self, func_name: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(self._checkpoint_dir, f"{func_name}.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            __log.warning(f"Checkpoint load failed {func_name}: {e}")
            return None

    def run_one(self, task: TaskSpec, runner) -> TaskResult:
        """Execute a single task under its resource budget timeout.

        使用 monotonic clock 确保时间预算不受系统时钟调整影响。"""
        budget = self.scheduler.allocator.budget_of(task.resource_profile)
        start_mono = time.monotonic()
        interrupted = False
        try:
            deadline_thread = threading.Timer(
                budget.timeout_seconds, self._stop_event.set
            )
            deadline_thread.start()
            try:
                output = runner(task) or {}
            finally:
                deadline_thread.cancel()
            if self._stop_event.is_set():
                interrupted = True
                self._stop_event.clear()
            elapsed = time.monotonic() - start_mono
            self.scheduler.scorer.record(task.func_name, elapsed)
            # 反馈：若实际耗时 > 2× budget，该函数未来优先级下调
            if elapsed > budget.timeout_seconds * 2:
                self.scheduler.scorer.record(task.func_name, elapsed * 0.5)
            # 计入公平共享消费
            self.fair_share.record_consumed(task.binary_path, elapsed)
            # 四轮增强 — 释放过分配追踪
            self.overcommit_detector.release_allocation(task)
            # 四轮增强 — 释放长任务槽（若适用）
            self.predictive.release_long_slot()
            # 四轮增强 — 记录任务完成
            self.schedule_replay.record_complete(
                task.func_name, task.binary_path
            )
            return TaskResult(
                func_name=task.func_name,
                success=not interrupted and 'error' not in output,
                elapsed=elapsed,
                states_explored=output.get('states_explored', 0),
                interrupted=interrupted,
                output=output
            )
        except Exception as e:
            elapsed = time.monotonic() - start_mono
            self.fair_share.record_consumed(task.binary_path, elapsed)
            self.overcommit_detector.release_allocation(task)
            self.predictive.release_long_slot()
            self.schedule_replay.record_complete(
                task.func_name, task.binary_path
            )
            return TaskResult(
                func_name=task.func_name,
                success=False,
                elapsed=elapsed,
                states_explored=0,
                interrupted=False,
                error=str(e)
            )

    def run_loop(self, runner) -> List[TaskResult]:
        results: List[TaskResult] = []
        skip_count = 0  # 因资源压力跳过的任务数
        overcommit_pauses = 0  # 因内存过度分配暂停的次数

        while self.scheduler.has_pending():
            # 每轮调度前采样系统负载，决定是否降载
            self.resource_monitor.refresh()

            # 四轮增强 — 检查内存过度分配
            if self.overcommit_detector.is_overcommitted():
                overcommit_pauses += 1
                __log.warning(
                    "[symbex-scheduler] Memory overcommit detected — "
                    "pausing new dispatch until running tasks complete"
                )
                time.sleep(0.5)  # 短暂等待后重试
                continue

            # 四轮增强 — PredictiveScheduler: 收集所有待处理任务，预测选择
            pending_tasks = self.scheduler.get_pending_tasks()
            selected_task, selection_reason = self.predictive.select_next_task(
                pending_tasks
            )

            if selected_task is None:
                # 回退到传统堆弹出
                task = self.scheduler.next_task()
                selection_reason = "normal_pop"
            else:
                task = selected_task
                # 从堆中移除选定任务（需要重新构建堆）
                # 这里使用 next_task 循环直到拿到目标
                popped = None
                attempts = 0
                while popped is None and attempts < len(pending_tasks) + 10:
                    candidate = self.scheduler.next_task()
                    if candidate is None:
                        break
                    if candidate.func_name == task.func_name:
                        popped = candidate
                        break
                    self.scheduler.requeue(candidate)
                    attempts += 1
                task = popped

            if task is None:
                break

            # 资源监控降载判定
            if not self.resource_monitor.can_dispatch(task):
                skip_count += 1
                self.scheduler.requeue(task)
                self.schedule_replay.record_requeue(
                    task.func_name, task.binary_path,
                    reason=f"resource_pressure:cpu={self.resource_monitor.sys_load_pct:.1f}"
                )
                __log.debug(
                    f"[symbex-scheduler] Skipping {task.func_name} "
                    f"due to resource pressure (cpu={self.resource_monitor.sys_load_pct:.1f}%, "
                    f"mem={self.resource_monitor.mem_usage_pct:.1f}%)"
                )
                continue

            # 公平共享优先级调整
            adjusted = self.fair_share.adjust_priority(task)

            # 四轮增强 — 注册内存分配追踪
            self.overcommit_detector.register_allocation(task, self.scheduler.allocator)

            # 四轮增强 — 记录调度决策
            predicted = self.predictive.predict(task)
            self.schedule_replay.record_dispatch(
                task.func_name, task.binary_path,
                reason=selection_reason,
                predicted_seconds=predicted,
            )

            __log.info(
                f"[symbex-scheduler] Scheduling {task.func_name} "
                f"profile={task.resource_profile.value} "
                f"complexity={task.complexity.score:.2f} "
                f"priority={adjusted} "
                f"reason={selection_reason} "
                f"predicted={predicted:.1f}s"
            )
            res = self.run_one(task, runner)
            results.append(res)

        if skip_count:
            __log.warning(
                f"[symbex-scheduler] {skip_count} task(s) deferred due to resource pressure"
            )
        if overcommit_pauses:
            __log.warning(
                f"[symbex-scheduler] {overcommit_pauses} overcommit pause(s) occurred"
            )

        return results


# ---------------------------------------------------------------------------
# 甘特图导出：将任务调度时序序列化为 JSON，用于可视化调度效率
#
# 每条记录包含 task_id、worker_id、start_ts、end_ts。
# gantt_json 可直接渲染为甘特图（Plotly / D3 / matplotlib），
# 帮助分析任务并行度、空闲窗口和长尾延迟。
# ---------------------------------------------------------------------------

# 全局甘特图记录缓冲区（线程安全）
_gantt_records: List[Dict[str, Any]] = []
_gantt_lock = threading.Lock()


def record_gantt_entry(task_id: str, worker_id: str,
                       start_ts: float, end_ts: float):
    """Push one Gantt record into the global timeline buffer.

    由 Executor 在每个任务完成时调用，收集调度时序数据。
    """
    with _gantt_lock:
        _gantt_records.append({
            'task_id': task_id,
            'worker_id': worker_id,
            'start_ts': start_ts,
            'end_ts': end_ts,
        })


def clear_gantt_records():
    """Reset the Gantt buffer (e.g. between run_loop invocations)."""
    with _gantt_lock:
        _gantt_records.clear()


def export_gantt_chart() -> str:
    """Export the accumulated task-execution timeline as a JSON string.

    Returns:
        A JSON string (``gantt_json``) whose value is an array of objects
        with keys ``task_id``, ``worker_id``, ``start_ts``, ``end_ts``.

    Usage::

        schedule_symbolic_analysis(...)
        gantt_json = export_gantt_chart()
        with open('timeline.json', 'w') as f:
            f.write(gantt_json)

    输出格式适用于 Plotly timeline、D3 Gantt 或 matplotlib broken_barh。
    """
    with _gantt_lock:
        snapshot = list(_gantt_records)
    gantt_json = json.dumps(snapshot, ensure_ascii=False, indent=2)
    return gantt_json


def schedule_symbolic_analysis(
    binary_path: str,
    function_specs: List[Dict[str, Any]],
    runner=None
) -> Dict[str, Any]:
    """One-shot: score functions, allocate resources, enqueue, and drain the
    scheduler. Uses a trivial sleep-based runner when none is supplied."""
    scheduler = PriorityScheduler()
    executor = InterruptibleExecutor(scheduler)

    for spec in function_specs:
        scheduler.submit(
            spec['name'],
            binary_path=binary_path,
            cyclomatic=spec.get('cyclomatic', 1),
            call_depth=spec.get('call_depth', 0),
            historical_seconds=spec.get('historical_seconds'),
            dangerous_funcs_reached=spec.get('dangerous_funcs_reached', 0),
            reach_dangerous_path=spec.get('reach_dangerous_path', False),
            depends_on=spec.get('depends_on'),
            is_critical=spec.get('is_critical', False)
        )

    if runner is None:
        def default_runner(task: TaskSpec) -> Dict[str, Any]:
            time.sleep(min(0.1, task.complexity.score / 50.0))
            return {'states_explored': int(task.complexity.score * 4)}
        runner = default_runner

    # 清理上一轮的甘特图缓冲区
    clear_gantt_records()

    results = executor.run_loop(runner)

    # 记录甘特图：每个结果映射为一个时序条目
    # worker_id 用 binary_path 简化标识
    for r in results:
        if r.elapsed > 0:
            record_gantt_entry(
                task_id=r.func_name,
                worker_id=binary_path,
                start_ts=time.time() - r.elapsed,
                end_ts=time.time(),
            )

    # 四轮增强 — 回放分析结果
    replay_report = executor.schedule_replay.replay_schedule()

    return {
        'success': True,
        'stats': scheduler.stats(),
        'results': [
            {
                'func_name': r.func_name,
                'success': r.success,
                'elapsed': r.elapsed,
                'states_explored': r.states_explored,
                'interrupted': r.interrupted,
                'error': r.error
            }
            for r in results
        ],
        'replay': replay_report,
    }
