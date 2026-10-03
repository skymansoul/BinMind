"""基于优先级的符号执行调度器与资源分配

函数按复杂度评分（圈复杂度、调用深度、历史运行时间、危险函数可达性），
分配与分数成正比的资源预算，通过两级优先堆（active vs background）调度。
执行器支持可中断运行、超时抢占与检查点持久化。

集成能力：SJF 预测调度与长任务槽防饥饿、依赖提升防调度死锁、公平共享、
CPU/内存负载监控与自适应降载、OOM 过分配检测、SQLite 调度回放与甘特图导出。
confirmed 漏洞路径自动获得 CRITICAL 级资源分配（timeout=3600s, memory=8192MB, states=16384）。
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

_log = logging.getLogger(__name__)


class ResourceProfile(Enum):
    """资源分配层级: 每层的时间、内存、状态上限"""
    MINIMAL = "minimal"
    LIGHT = "light"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    EXTREME = "extreme"
    CRITICAL = "critical"


@dataclass
class FunctionComplexity:
    """单函数的多因子复杂度评分"""
    func_name: str
    cyclomatic_complexity: int = 1
    call_depth: int = 0
    historical_seconds: float = 0.0
    dangerous_funcs_reached: int = 0
    reach_dangerous_path: bool = False
    score: float = 0.0


@dataclass
class TaskSpec:
    """已调度的函数：优先级、资源档位、截止时间"""
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
    """从 ResourceProfile 派生的具体限制"""
    timeout_seconds: int
    memory_mb: int
    max_states: int


@dataclass
class TaskResult:
    """执行一个调度任务的输出"""
    func_name: str
    success: bool
    elapsed: float
    states_explored: int
    interrupted: bool
    error: Optional[str] = None
    output: Optional[Dict] = None


@dataclass
class ScheduleRecord:
    """一条调度决策记录, 用于回放分析

    task_id: 函数名
    worker_id: 二进制路径或 worker 标识
    start_ts: 任务派发的单调时间戳
    end_ts: 任务完成的单调时间戳
    reason: 任务被选中的原因 (如 "shortest_job_first", "long_slot",
    "normal_pop", "dependency_promotion")
    predicted_seconds: PredictiveScheduler 预估的运行时间
    """
    task_id: str
    worker_id: str
    start_ts: float
    end_ts: float
    reason: str = "normal_pop"
    predicted_seconds: float = 0.0


# log2 预计算查找表：索引范围 [0, 1024]，超出范围用 math.log2 实时计算，
# 避免符号执行调度热路径上频繁调用超越函数
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
    """综合圈复杂度、调用深度、历史执行时间、危险函数可达性
    对函数评分。分数越高 → 越值得分配资源"""

    def __init__(self, history_db: Optional[str] = None):
        self.history_db = history_db
        self._hist_cache: Dict[str, List[float]] = defaultdict(list)

    def score(self, func_name: str, *,
              cyclomatic: int = 1,
              call_depth: int = 0,
              historical_seconds: Optional[float] = None,
              dangerous_funcs_reached: int = 0,
              reach_dangerous_path: bool = False) -> FunctionComplexity:
        """使用 LUT 加速的 log2 计算复合复杂度评分"""
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
        """存储执行时间供后续评分使用（保留最近 10 次采样）"""
        self._hist_cache[func_name].append(seconds)
        self._hist_cache[func_name] = self._hist_cache[func_name][-10:]

    def predict_runtime(self, func_name: str, fallback: float = 0.0) -> float:
        """基于历史样本预测函数运行时间。

        取最近 10 次执行的中位数 (中位数比均值更抗异常值); 无历史
        数据时返回 fallback。返回预测运行秒数。
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
        """返回函数的平均历史执行时间"""
        samples = self._hist_cache.get(func_name, [])
        if not samples:
            return 0.0
        return sum(samples) / len(samples)


class ResourceAllocator:
    """将复杂度评分映射到资源层级的具体限制"""

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
        """按复杂度评分区间选择资源档位"""
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
        """查询指定档位的具体预算"""
        return self.PROFILES[profile]


# 资源监控器：实时采集 CPU/内存负载以触发自适应降载 — sys_load_pct>80% 时
# 活跃并发度减半并跳过非 CRITICAL 分发；内存>90% 时暂停 background heap 调度、
# 仅放行 CRITICAL 防 OOM；psutil 为可选依赖，缺失时降级为无操作模式


class ResourceMonitor:
    """监控系统级 CPU 与内存负载，提供反压信号

    sys_load_pct 超过 80% 时活跃并发度减半，非关键任务分发被跳过。
    内存使用率超过 90% 时后台堆调度完全暂停以防止 OOM。
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
        """采集一次 CPU 和内存使用率快照

        返回 (sys_load_pct, mem_usage_pct)。psutil 不可用时回退为 (0.0, 0.0)。
        """
        if not _HAS_PSUTIL:
            return 0.0, 0.0
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        return cpu, mem

    def refresh(self):
        """刷新负载数据并更新反压标志

        每次调度轮询前调用，决策是否进入降载模式
        """
        with self._lock:
            cpu, mem = self.sample()
            self.sys_load_pct = cpu
            self.mem_usage_pct = mem
            self.high_cpu = cpu > self.cpu_high
            self.high_memory = mem > self.mem_high

    def should_throttle_active(self) -> bool:
        """系统 CPU 过载时返回 True，活跃并发度减半"""
        return self.high_cpu

    def should_pause_background(self) -> bool:
        """内存压力严重时返回 True，后台任务暂停"""
        return self.high_memory

    def can_dispatch(self, task: TaskSpec) -> bool:
        """判断任务是否允许分发执行

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
        """暴露当前负载快照供可观测性使用"""
        return {
            'sys_load_pct': self.sys_load_pct,
            'mem_usage_pct': self.mem_usage_pct,
            'high_cpu': self.high_cpu,
            'high_memory': self.high_memory,
        }


# 公平共享调度器：每个 binary_path 分得 fair_share_budget = 总分配时间/活跃二进制数，
# 已消耗超预算的任务 priority -= 100 以降级排队，避免单个大二进制独占执行槽位


class FairShareScheduler:
    """公平共享封装 PriorityScheduler

    每个 binary_path 获得等量的 fair_share_budget 执行时间。
    超预算的二进制文件任务降优先级（priority -= 100），
    未充分执行的二进制文件优先调度。
    """

    def __init__(self, scheduler: "PriorityScheduler"):
        self.scheduler = scheduler
        self._lock = threading.Lock()

        # per_binary_consumed: binary_path → 累计执行秒数
        self.per_binary_consumed: Dict[str, float] = defaultdict(float)

        # 总预算（秒），每次 run_loop 时由调用方设定
        self.fair_share_budget: Optional[float] = None

    def compute_budgets(self, total_time: float, binary_paths: Set[str]):
        """在活跃二进制文件间均分公平共享预算

        :param total_time: 本轮执行可用的总时间预算
        :param binary_paths: 参与本轮调度的所有二进制文件集合
        """
        n = max(1, len(binary_paths))
        self.fair_share_budget = total_time / n

    def record_consumed(self, binary_path: str, elapsed: float):
        """任务完成后累加对应二进制文件的已消耗时间"""
        with self._lock:
            self.per_binary_consumed[binary_path] += elapsed

    def adjust_priority(self, task: TaskSpec) -> int:
        """返回考虑公平共享后的调整优先级

        若按 binary_path 查询到的已消耗时间超过 fair_share_budget
        则 priority -= 100，将该任务降级处理
        """
        if self.fair_share_budget is None or self.fair_share_budget <= 0:
            return task.priority
        consumed = self.per_binary_consumed.get(task.binary_path, 0.0)
        if consumed > self.fair_share_budget:
            return task.priority - 100
        return task.priority

    def stats(self) -> Dict[str, Any]:
        """暴露公平共享状态供遥测"""
        return {
            'fair_share_budget': self.fair_share_budget,
            'per_binary_consumed': dict(self.per_binary_consumed),
        }


# PredictiveScheduler：就绪任务按 predicted_runtime 升序调度（SJF 显著降低平均完成时间）；
# 保留 1 个长任务槽给预测时间 > median*2 的任务，槽耗尽后长任务进入常规 FIFO，
# 避免纯 SJF 导致的长任务饥饿


class PredictiveScheduler:
    """最短作业优先（SJF）调度器，通过长任务槽防止饥饿

    用 ComplexityScorer.predict_runtime() 预测每个任务的执行时间，
    每次调度选择预测执行时间最短的任务，以降低平均任务完成时间。

    LongSlot 机制：
    - 维护长任务计数槽（long_slot_count，默认 1），仅允许长任务使用
    - 长任务定义：predicted_runtime > 就绪任务预测时间中位数的 2 倍
      （long_ratio_threshold 默认 2.0）
    - 长任务槽被占用后，后续长任务按常规优先级排队
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
        """预测任务运行时间 (有缓存值时直接命中)。

        优先使用 historical_seconds 已有的值, 其次调用
        scorer.predict_runtime(); Fallback 用 complexity.score / 10.0
        粗略估算 (高复杂度 ≈ 长运行时间)。返回预测执行秒数。
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
        """用 SJF + long-slot 预留策略选择下一个执行任务。

        返回 (选中的任务, 选择原因); 原因取值
        shortest_job_first / long_slot / 回退 / no_tasks。
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
        """长任务完成后释放一个长任务槽"""
        with self._lock:
            if self._long_slots_used > 0:
                self._long_slots_used -= 1

    def reset(self):
        """重置预测缓存与长任务槽计数，用于新一轮调度"""
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
        """暴露预测调度状态"""
        with self._lock:
            return {
                'long_slots_used': self._long_slots_used,
                'long_slot_count': self.long_slot_count,
                'long_ratio_threshold': self.long_ratio_threshold,
                'cached_predictions': len(self._prediction_cache),
            }


# ResourceOvercommitDetector：符号执行内存密集，多个 worker 同时运行时累计分配可能
# 超过系统可用物理内存而触发 OOM killer。每次调度前比较 total_allocated_mb 与
# system_available_mb*safety_ratio，超过即阻塞新分发直至运行中任务完成释放内存


class ResourceOvercommitDetector:
    """监控内存过度分配，暂停分发以防止 OOM

    跟踪所有已分发但尚未完成的任务的内存预算总和（total_allocated_mb），
    当累计分配超过系统可用内存（system_available_mb）的安全比例时阻止新任务分发，
    直至运行中任务完成并释放内存。

    触发条件：total_allocated_mb > system_available_mb * safety_ratio；
    默认 safety_ratio = 0.85，即保留 15% 余量给系统和其他进程。
    """

    # 默认安全比例 —— 保留 15% 内存余量
    _DEFAULT_SAFETY_RATIO = 0.85

    def __init__(self, safety_ratio: float = _DEFAULT_SAFETY_RATIO):
        self.safety_ratio = safety_ratio
        self.total_allocated_mb: float = 0.0
        self.running_tasks: Dict[str, int] = {}
        self._lock = threading.Lock()

    def register_allocation(self, task: TaskSpec, allocator: ResourceAllocator):
        """记录一次任务内存分配分发。

        allocator 用于查询内存预算。
        """
        budget = allocator.budget_of(task.resource_profile)
        with self._lock:
            self.total_allocated_mb += budget.memory_mb
            self.running_tasks[task.func_name] = budget.memory_mb
            _log.debug(
                f"[OvercommitDetector] Allocated {budget.memory_mb}MB for "
                f"{task.func_name}, total={self.total_allocated_mb:.0f}MB"
            )

    def release_allocation(self, task: TaskSpec):
        """任务完成时释放其内存分配。"""
        with self._lock:
            if task.func_name in self.running_tasks:
                freed = self.running_tasks.pop(task.func_name)
                self.total_allocated_mb = max(0.0, self.total_allocated_mb - freed)
                _log.debug(
                    f"[OvercommitDetector] Released {freed}MB from "
                    f"{task.func_name}, total={self.total_allocated_mb:.0f}MB"
                )

    def is_overcommitted(self) -> bool:
        """检查已分配内存是否超过系统可用量 × safety_ratio。

        True 时分发器暂停等待任务完成。
        """
        if not _HAS_PSUTIL:
            return False

        available_mb = psutil.virtual_memory().available / (1024 * 1024)

        with self._lock:
            is_over = self.total_allocated_mb > available_mb * self.safety_ratio

        if is_over:
            _log.warning(
                f"[OvercommitDetector] Memory overcommit detected: "
                f"total_allocated={self.total_allocated_mb:.0f}MB > "
                f"available*safety={available_mb * self.safety_ratio:.0f}MB "
                f"(available={available_mb:.0f}MB, safety_ratio={self.safety_ratio})"
            )

        return is_over

    def get_available_mb(self) -> float:
        """返回系统可用内存（MB），psutil 缺失时返回无穷大"""
        if not _HAS_PSUTIL:
            return float('inf')
        return psutil.virtual_memory().available / (1024 * 1024)

    def status(self) -> Dict[str, Any]:
        """暴露过度分配监控状态供可观测性使用"""
        with self._lock:
            return {
                'total_allocated_mb': round(self.total_allocated_mb, 1),
                'running_tasks': len(self.running_tasks),
                'safety_ratio': self.safety_ratio,
                'is_overcommitted': self.is_overcommitted(),
                'available_mb': round(self.get_available_mb(), 1),
            }


# ScheduleReplay：调度决策持久化到 SQLite，支持离线分析 —
# replay_schedule() 重建甘特图时间线并识别调度低效窗口（队列非空而有 worker 空闲），
# 统计 worker 利用率与任务等待时间


class ScheduleReplay:
    """记录并回放调度决策，用于审计和低效检测

    将每次调度操作（dispatch / complete / requeue）写入 SQLite 的
    schedule_events 表（task_id, worker_id, event_type, timestamp_ts, reason,
    predicted_seconds；建表语句见 _init_schema()，含 timestamp_ts 与
    (worker_id, event_type) 索引）。replay_schedule() 重建甘特图时间线、
    识别调度低效窗口（队列非空而 worker 空闲）并计算 worker 利用率。
    """

    def __init__(self, db_path: str = ":memory:"):
        """初始化 replay 数据库。

        默认 ":memory:" 内存库; 文件路径可在进程重启后恢复分析。
        """
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        """创建 schedule_events 表 (不存在时)。"""
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
        """记录任务分发事件。

        reason 为调度原因 (如 shortest_job_first/long_slot)。
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO schedule_events (task_id, worker_id, event_type, "
                "timestamp_ts, reason, predicted_seconds) VALUES (?, ?, 'dispatch', ?, ?, ?)",
                (task_id, worker_id, time.monotonic(), reason, predicted_seconds)
            )
            self._conn.commit()

    def record_complete(self, task_id: str, worker_id: str):
        """记录任务完成事件。"""
        with self._lock:
            self._conn.execute(
                "INSERT INTO schedule_events (task_id, worker_id, event_type, "
                "timestamp_ts) VALUES (?, ?, 'complete', ?)",
                (task_id, worker_id, time.monotonic())
            )
            self._conn.commit()

    def record_requeue(self, task_id: str, worker_id: str, reason: str = ""):
        """记录任务重入队事件 (如资源压力导致的延迟)。"""
        with self._lock:
            self._conn.execute(
                "INSERT INTO schedule_events (task_id, worker_id, event_type, "
                "timestamp_ts, reason) VALUES (?, ?, 'requeue', ?, ?)",
                (task_id, worker_id, time.monotonic(), reason)
            )
            self._conn.commit()

    def replay_schedule(self) -> Dict[str, Any]:
        """重建 Gantt 时间线, 识别调度低效窗口。

        分析：
        1. 为每个任务构建 (dispatch_ts, complete_ts) 对，生成 Gantt 条目
        2. 扫描时间线寻找 "idle_while_queued" 窗口:
        在某个时间点, 至少有一个任务在队列中等待 (已 dispatch-requeue
        但未被 complete), 同时没有正在运行的任务
        3. 计算 worker 利用率 = busy_time / total_time

        返回 gantt_entries / inefficiencies / worker_utilization /
        total_time_span / event_count。
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
            timeline.append((entry[2], +1))  # 启动
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
        """导出甘特图数据为 JSON 字符串，供可视化使用

        返回兼容 Plotly/D3 甘特图的时间线数据 JSON 字符串
        """
        replay = self.replay_schedule()
        return json.dumps(replay['gantt_entries'], ensure_ascii=False, indent=2)

    def close(self):
        """关闭 SQLite 连接"""
        with self._lock:
            self._conn.close()


class PriorityScheduler:
    """两级最小堆调度器。危险路径函数在 active 堆，
    其余在 background 堆。next_task() 先排空 active 堆再排 background 堆，
    回退到 active 堆

    依赖提升：当 active heap 任务引用的依赖函数在 background heap 中时
    将后者提升至 active heap，避免调度死锁"""

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
        """评分函数、分配资源、推入对应堆"""
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
        """若 active task 依赖 background task，提升后者至 active

        死锁场景：task_A（active）依赖 task_B（background）
        若 background 永远不被调度，task_A 将永远阻塞"""
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
        """弹出下一个任务。优先排空 active 堆，回退到 background 堆"""
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
        """返回两个堆中所有待处理任务（供 PredictiveScheduler 使用）"""
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
    """运行调度任务，支持逐任务超时抢占

    使用 time.monotonic() 计时，免疫系统时钟调整；
    集成 PredictiveScheduler、ResourceOvercommitDetector、ScheduleReplay。
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

        # 预测调度器
        self.predictive = PredictiveScheduler(scorer=scheduler.scorer)

        # 过分配检测器
        self.overcommit_detector = ResourceOvercommitDetector()

        # 调度回放记录器
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
            _log.warning(f"Checkpoint load failed {func_name}: {e}")
            return None

    def run_one(self, task: TaskSpec, runner) -> TaskResult:
        """在资源预算超时内执行单个任务

        使用 monotonic clock 确保时间预算不受系统时钟调整影响"""
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
            # 释放过分配追踪
            self.overcommit_detector.release_allocation(task)
            # 释放长任务槽（若适用）
            self.predictive.release_long_slot()
            # 记录任务完成
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

            # 检查内存过度分配
            if self.overcommit_detector.is_overcommitted():
                overcommit_pauses += 1
                _log.warning(
                    "[symbex-scheduler] Memory overcommit detected — "
                    "pausing new dispatch until running tasks complete"
                )
                time.sleep(0.5)  # 短暂等待后重试
                continue

            # PredictiveScheduler：收集所有待处理任务并按预测时间选择
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
                _log.debug(
                    f"[symbex-scheduler] Skipping {task.func_name} "
                    f"due to resource pressure (cpu={self.resource_monitor.sys_load_pct:.1f}%, "
                    f"mem={self.resource_monitor.mem_usage_pct:.1f}%)"
                )
                continue

            # 公平共享优先级调整
            adjusted = self.fair_share.adjust_priority(task)

            # 注册内存分配追踪
            self.overcommit_detector.register_allocation(task, self.scheduler.allocator)

            # 记录调度决策
            predicted = self.predictive.predict(task)
            self.schedule_replay.record_dispatch(
                task.func_name, task.binary_path,
                reason=selection_reason,
                predicted_seconds=predicted,
            )

            _log.info(
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
            _log.warning(
                f"[symbex-scheduler] {skip_count} task(s) deferred due to resource pressure"
            )
        if overcommit_pauses:
            _log.warning(
                f"[symbex-scheduler] {overcommit_pauses} overcommit pause(s) occurred"
            )

        return results


# 甘特图导出：将任务调度时序（task_id、worker_id、start_ts、end_ts）序列化为 JSON，
# 可渲染为 Plotly/D3/matplotlib 甘特图，用于分析并行度、空闲窗口与长尾延迟

# 全局甘特图记录缓冲区（线程安全）
_gantt_records: List[Dict[str, Any]] = []
_gantt_lock = threading.Lock()


def record_gantt_entry(task_id: str, worker_id: str,
                       start_ts: float, end_ts: float):
    """将一条 Gantt 记录推入全局时间线缓冲区

    由 Executor 在每个任务完成时调用，收集调度时序数据
    """
    with _gantt_lock:
        _gantt_records.append({
            'task_id': task_id,
            'worker_id': worker_id,
            'start_ts': start_ts,
            'end_ts': end_ts,
        })


def clear_gantt_records():
    """重置甘特图缓冲区（用于多次 run_loop 调用）"""
    with _gantt_lock:
        _gantt_records.clear()


def export_gantt_chart() -> str:
    """导出累积的任务执行时间线为 JSON 字符串

    返回 gantt_json（对象数组），键为 task_id、worker_id、start_ts、end_ts。
    适用于 Plotly timeline、D3 Gantt 或 matplotlib broken_barh 可视化。
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
    """一次性接口：评分函数、分配资源、入队、排空调度器。
    未提供 runner 时使用基于 sleep 的默认 runner"""
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

    # 回放分析结果
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
