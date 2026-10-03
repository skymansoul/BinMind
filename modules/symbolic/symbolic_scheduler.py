"""Priority-based symbolic execution scheduler with resource allocation.

Functions are scored by complexity (cyclomatic, call depth, historical
runtime, dangerous-function reachability), assigned a resource budget
proportional to that score, and scheduled on a two-tier priority heap
(active vs. background). The executor supports interruptible runs with
timeout-based preemption and checkpoint persistence.
"""

import logging
import heapq
import time
import threading
import json
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ResourceProfile(Enum):
    """Resource allocation tiers: timeout, memory, and state limits per tier."""
    MINIMAL = "minimal"
    LIGHT = "light"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    EXTREME = "extreme"


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
        """Compute the composite complexity score."""
        if historical_seconds is None and func_name in self._hist_cache:
            samples = self._hist_cache[func_name]
            historical_seconds = sum(samples) / max(1, len(samples))

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
        """Store execution time for future scoring (keeps last 10 samples)."""
        self._hist_cache[func_name].append(seconds)
        self._hist_cache[func_name] = self._hist_cache[func_name][-10:]


class ResourceAllocator:
    """Maps a complexity score to a resource profile with concrete limits."""

    PROFILES: Dict[ResourceProfile, ResourceBudget] = {
        ResourceProfile.MINIMAL:    ResourceBudget(30,   256,  256),
        ResourceProfile.LIGHT:      ResourceBudget(60,   512,  512),
        ResourceProfile.STANDARD:   ResourceBudget(180,  1024, 1024),
        ResourceProfile.AGGRESSIVE: ResourceBudget(600,  2048, 4096),
        ResourceProfile.EXTREME:    ResourceBudget(1800, 4096, 8192),
    }

    def allocate(self, complexity: FunctionComplexity) -> ResourceProfile:
        """Select the profile whose score band contains complexity.score."""
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


class PriorityScheduler:
    """Two-tier min-heap scheduler. Dangerous-path functions go to the active
    heap; everything else goes to background. next_task() drains active first,
    then background, then falls back to active."""

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
        """Monotonic sequence counter for tie-breaking in the heap."""
        self._counter += 1
        return self._counter

    def submit(self, func_name: str, *,
               binary_path: str,
               cyclomatic: int = 1,
               call_depth: int = 0,
               historical_seconds: Optional[float] = None,
               dangerous_funcs_reached: int = 0,
               reach_dangerous_path: bool = False) -> TaskSpec:
        """Score a function, allocate resources, and push onto the correct heap."""
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
        """Pop the next task. Active heap is drained first; background is the
        fallback. If both are empty, returns None."""
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
        """Push a task back with incremented priority (lower urgency)."""
        with self._lock:
            target = self.active_heap if task.complexity.reach_dangerous_path else self.background_heap
            heapq.heappush(target, (task.priority + 1, task.seq, task))

    def has_pending(self) -> bool:
        """True if either heap has work remaining."""
        return bool(self.active_heap or self.background_heap)

    def stats(self) -> Dict[str, int]:
        """Pending counts per heap."""
        return {
            'active_pending': len(self.active_heap),
            'background_pending': len(self.background_heap)
        }


class InterruptibleExecutor:
    """Runs scheduled tasks with per-task timeout preemption.

    Each task gets a deadline timer; if the timer fires, the task is
    interrupted and its partial output can be checkpointed. Completed
    execution times are fed back into the ComplexityScorer for future
    scheduling decisions."""

    def __init__(self, scheduler: PriorityScheduler):
        self.scheduler = scheduler
        self._stop_event = threading.Event()
        self._checkpoint_dir = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'symbex_checkpoints'
        )
        os.makedirs(self._checkpoint_dir, exist_ok=True)

    def request_stop(self):
        """Signal the executor to stop after the current task."""
        self._stop_event.set()

    def resume(self):
        """Clear the stop signal."""
        self._stop_event.clear()

    def save_checkpoint(self, task: TaskSpec, partial: Dict[str, Any]):
        """Write partial task output to a JSON checkpoint file."""
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
        """Restore a previously saved checkpoint. Returns None if absent."""
        path = os.path.join(self._checkpoint_dir, f"{func_name}.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Checkpoint load failed {func_name}: {e}")
            return None

    def run_one(self, task: TaskSpec, runner) -> TaskResult:
        """Execute a single task under its resource budget timeout."""
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
        """Drain the scheduler's task queues, executing each task via runner."""
        results: List[TaskResult] = []
        while self.scheduler.has_pending():
            task = self.scheduler.next_task()
            if task is None:
                break
            logger.info(
                f"[symbex-scheduler] Scheduling {task.func_name} "
                f"profile={task.resource_profile.value} "
                f"complexity={task.complexity.score:.2f}"
            )
            res = self.run_one(task, runner)
            results.append(res)
            if res.interrupted:
                logger.warning(
                    f"[symbex-scheduler] {task.func_name} timed out"
                )
        return results


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
            reach_dangerous_path=spec.get('reach_dangerous_path', False)
        )

    if runner is None:
        def default_runner(task: TaskSpec) -> Dict[str, Any]:
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
