"""
符号执行调度与资源自适应分配模块

功能:
    1. 基于函数复杂度、调用深度、历史分析耗时动态分配 angr 执行时间/内存限制
    2. 优先级队列调度: 优先分析可达危险函数路径, 低优先级路径放入后台队列
    3. 支持中断/恢复, 超时自动切换至下一个任务, 避免单函数阻塞整个流水线

核心技术:
    - 复杂度评分模型 (cyclomatic / call-depth / 历史耗时)
    - 资源分配策略 (线性 / 指数 / 对数)
    - 优先级队列 (heapq) + 后台队列
    - 信号式中断 (threading.Event) 与检查点恢复
"""

import logging
import heapq
import time
import threading
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ResourceProfile(Enum):
    """资源分配档位"""
    MINIMAL = "minimal"        # < 30s, < 256MB
    LIGHT = "light"            # < 60s, < 512MB
    STANDARD = "standard"      # < 180s, < 1GB
    AGGRESSIVE = "aggressive"  # < 600s, < 2GB
    EXTREME = "extreme"        # < 1800s, < 4GB


@dataclass
class FunctionComplexity:
    """函数复杂度评估结果"""
    func_name: str
    cyclomatic_complexity: int = 1
    call_depth: int = 0
    historical_seconds: float = 0.0
    dangerous_funcs_reached: int = 0
    reach_dangerous_path: bool = False
    score: float = 0.0


@dataclass
class TaskSpec:
    """符号执行任务描述符"""
    func_name: str
    priority: int                # 数值越小,优先级越高
    resource_profile: ResourceProfile
    complexity: FunctionComplexity
    deadline_ts: float
    binary_path: str
    extra: Dict[str, Any] = field(default_factory=dict)
    seq: int = 0                 # heapq 排序稳定化字段


@dataclass
class ResourceBudget:
    """单任务资源预算"""
    timeout_seconds: int
    memory_mb: int
    max_states: int


@dataclass
class TaskResult:
    """任务执行结果"""
    func_name: str
    success: bool
    elapsed: float
    states_explored: int
    interrupted: bool
    error: Optional[str] = None
    output: Optional[Dict[str, Any]] = None


class ComplexityScorer:
    """根据函数复杂度评分"""

    def __init__(self, history_db: Optional[str] = None):
        self.history_db = history_db
        self._hist_cache: Dict[str, List[float]] = defaultdict(list)

    def score(self, func_name: str, *,
              cyclomatic: int = 1,
              call_depth: int = 0,
              historical_seconds: Optional[float] = None,
              dangerous_funcs_reached: int = 0,
              reach_dangerous_path: bool = False) -> FunctionComplexity:
        if historical_seconds is None and func_name in self._hist_cache:
            samples = self._hist_cache[func_name]
            historical_seconds = sum(samples) / max(1, len(samples))

        # 评分 = 圈复杂度权重 * log + 调用深度权重 * log + 危险函数命中权重
        import math
        cyc_part = math.log2(1 + max(0, cyclomatic)) * 4.0
        dep_part = math.log2(1 + max(0, call_depth)) * 3.0
        hist_part = math.log2(1 + max(0.0, historical_seconds)) * 5.0
        danger_part = 8.0 if reach_dangerous_path else 0.0
        danger_calls = min(10, dangerous_funcs_reached) * 1.0

        score = cyc_part + dep_part + hist_part + danger_part + danger_calls

        return FunctionComplexity(
            func_name=func_name,
            cyclomatic_complexity=cyclomatic,
            call_depth=call_depth,
            historical_seconds=historical_seconds or 0.0,
            dangerous_funcs_reached=dangerous_funcs_reached,
            reach_dangerous_path=reach_dangerous_path,
            score=score
        )

    def record(self, func_name: str, seconds: float):
        self._hist_cache[func_name].append(seconds)
        # 仅保留最近 10 次
        self._hist_cache[func_name] = self._hist_cache[func_name][-10:]


class ResourceAllocator:
    """资源分配策略"""

    PROFILES: Dict[ResourceProfile, ResourceBudget] = {
        ResourceProfile.MINIMAL:    ResourceBudget(30,   256,  256),
        ResourceProfile.LIGHT:      ResourceBudget(60,   512,  512),
        ResourceProfile.STANDARD:   ResourceBudget(180,  1024, 1024),
        ResourceProfile.AGGRESSIVE: ResourceBudget(600,  2048, 4096),
        ResourceProfile.EXTREME:    ResourceBudget(1800, 4096, 8192),
    }

    def allocate(self, complexity: FunctionComplexity) -> ResourceProfile:
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
        return self.PROFILES[profile]


class PriorityScheduler:
    """
    优先级 + 后台 调度器
    - 高优先级任务放入主队列 (active)
    - 低优先级任务放入后台队列 (background), 空闲时调度
    """

    def __init__(self,
                 active_threshold: int = 50,
                 scorer: Optional[ComplexityScorer] = None,
                 allocator: Optional[ResourceAllocator] = None):
        self.scorer = scorer or ComplexityScorer()
        self.allocator = allocator or ResourceAllocator()
        self.active_heap: List[TaskSpec] = []
        self.background_heap: List[TaskSpec] = []
        self._counter = 0
        self.active_threshold = active_threshold
        self._lock = threading.Lock()

    def _new_seq(self) -> int:
        self._counter += 1
        return self._counter

    def submit(self, func_name: str, *,
               binary_path: str,
               cyclomatic: int = 1,
               call_depth: int = 0,
               historical_seconds: Optional[float] = None,
               dangerous_funcs_reached: int = 0,
               reach_dangerous_path: bool = False) -> TaskSpec:
        complexity = self.scorer.score(
            func_name,
            cyclomatic=cyclomatic,
            call_depth=call_depth,
            historical_seconds=historical_seconds,
            dangerous_funcs_reached=dangerous_funcs_reached,
            reach_dangerous_path=reach_dangerous_path
        )
        profile = self.allocator.allocate(complexity)
        budget = self.allocator.budget_of(profile)

        # 主队列基于 dangerous_path 优先, 否则按复杂度降序; 后台队列按复杂度升序
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
            deadline_ts=time.time() + budget.timeout_seconds,
            binary_path=binary_path,
            seq=self._new_seq()
        )
        with self._lock:
            heapq.heappush(target, (priority, task.seq, task))
        return task

    def next_task(self, prefer_active: bool = True) -> Optional[TaskSpec]:
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

    def stats(self) -> Dict[str, int]:
        return {
            'active_pending': len(self.active_heap),
            'background_pending': len(self.background_heap)
        }


class InterruptibleExecutor:
    """支持中断/恢复的符号执行包装"""

    def __init__(self, scheduler: PriorityScheduler):
        self.scheduler = scheduler
        self._stop_event = threading.Event()
        self._checkpoint_dir = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'symbex_checkpoints'
        )
        os.makedirs(self._checkpoint_dir, exist_ok=True)

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
            logger.warning(f"加载检查点失败 {func_name}: {e}")
            return None

    def run_one(self, task: TaskSpec, runner) -> TaskResult:
        """
        调度单个任务, runner 为执行函数签名: (task) -> dict
        超时/中断自动切换, 结果返回 TaskResult
        """
        budget = self.scheduler.allocator.budget_of(task.resource_profile)
        start = time.time()
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
                # 超时触发
                interrupted = True
                self._stop_event.clear()
            elapsed = time.time() - start
            self.scheduler.scorer.record(task.func_name, elapsed)
            return TaskResult(
                func_name=task.func_name,
                success=not interrupted and 'error' not in output,
                elapsed=elapsed,
                states_explored=output.get('states_explored', 0),
                interrupted=interrupted,
                output=output
            )
        except Exception as e:
            return TaskResult(
                func_name=task.func_name,
                success=False,
                elapsed=time.time() - start,
                states_explored=0,
                interrupted=False,
                error=str(e)
            )

    def run_loop(self, runner) -> List[TaskResult]:
        results: List[TaskResult] = []
        while self.scheduler.has_pending():
            task = self.scheduler.next_task()
            if task is None:
                break
            logger.info(
                f"[symbex-scheduler] 调度 {task.func_name} "
                f"profile={task.resource_profile.value} "
                f"complexity={task.complexity.score:.2f}"
            )
            res = self.run_one(task, runner)
            results.append(res)
            if res.interrupted:
                logger.warning(
                    f"[symbex-scheduler] {task.func_name} 超时, 已切到下一任务"
                )
        return results


# ============ 便捷函数 ============

def schedule_symbolic_analysis(
    binary_path: str,
    function_specs: List[Dict[str, Any]],
    runner=None
) -> Dict[str, Any]:
    """
    入口函数
    function_specs: [{'name': str, 'cyclomatic': int, 'call_depth': int,
                       'historical_seconds': float, 'dangerous_funcs_reached': int,
                       'reach_dangerous_path': bool}]
    """
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
            reach_dangerous_path=spec.get('reach_dangerous_path', False)
        )

    if runner is None:
        def default_runner(task: TaskSpec) -> Dict[str, Any]:
            # 模拟执行: 在真实环境下会调用 angr
            time.sleep(min(0.1, task.complexity.score / 50.0))
            return {'states_explored': int(task.complexity.score * 4)}
        runner = default_runner

    results = executor.run_loop(runner)

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
        ]
    }
