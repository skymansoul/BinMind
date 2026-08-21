from __future__ import annotations
"""堆调度器: 依赖DAG解析/bounded worker pool/条件变量编排."""
from typing import Dict, List, Optional, Callable, Set, Any
import heapq, threading, time, logging
from fractions import Fraction
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from contextlib import suppress

_log = logging.getLogger(__name__)
class TaskStatus(Enum): PENDING = "pending"; READY = "ready"; RUNNING = "running"; DONE = "done"; FAILED = "failed"; SKIPPED = "skipped"; RETRYING = "retrying"; SUCCESS = "success"
class TaskType(Enum): UNIT = "unit"; INTEGRATION = "integration"; FUZZ = "fuzz"; ANALYSIS = "analysis"; TRANSFORMATION = "transformation"; EXPORT = "export"
@dataclass(order=True)
class _QItem: priority: int; task_id: str = field(compare=False); payload: Any = field(compare=False, default=None)

class TaskResult:
    def __init__(self, tid="", ok=True, data=None, error="", task_id=None, status=None, result=None):
        self.task_id = task_id if task_id is not None else tid
        self.ok = ok
        self.data = data if data is not None else result
        self.result = self.data
        self.error = error
        self.status = status if status is not None else (TaskStatus.SUCCESS if ok else TaskStatus.FAILED)

@dataclass
class TaskDependency:
    task_id: str
    required_status: TaskStatus = TaskStatus.SUCCESS

class BaseTask:
    """Airflow风格bitshift DAG+指数退避重试."""
    def __init__(self, tid="", name="", ttype=TaskType.UNIT, pri=10, func=None, args=None, kwargs=None, deps=None, retries=0, rdelay=1.0, sto=0, hto=0, task_id=None, analyzer_name=None, analyzer_params=None):
        self.task_id = task_id if task_id is not None else tid; self.name = name; self.type = ttype; self.priority = pri; self.func: Optional[Callable] = func
        self.args = args or []; self.kwargs = kwargs or {}; self.depends_on: List[str] = deps or []
        self.status = TaskStatus.PENDING; self.result: Optional[TaskResult] = None; self._created = time.time(); self._finished: Optional[float] = None
        self.retries = retries; self._max_r = retries; self.retry_delay = rdelay; self.soft_to = sto; self.hard_to = hto
        self.analyzer_name = analyzer_name; self.analyzer_params = analyzer_params or {}
        self._ds: List[BaseTask] = []
    def execute(self, context=None):
        if self.func is None:
            return None
        if context is not None:
            return self.func(context)
        return self.func(*self.args, **self.kwargs)
    def can_run(self, done: Set[str]): return all(d in done for d in self.depends_on)
    def elapsed(self): return (self._finished - self._created) if self._finished else time.time() - self._created
    def __rshift__(self, ds):
        if isinstance(ds, list):
            for d in ds: self._wire(d)
        else: self._wire(ds)
        return ds
    def __lshift__(self, us):
        for u in (us if isinstance(us, list) else [us]): u._wire(self)
        return self
    def _wire(self, o):
        if self.task_id not in o.depends_on: o.depends_on.append(self.task_id)
        self._ds.append(o)

SimpleTask = AnalysisTask = BaseTask

class TaskScheduler:
    def __init__(self, mw=4):
        self.max_workers = mw; self._tasks: Dict[str, BaseTask] = {}; self._rq: List[_QItem] = []; self._done: Set[str] = set(); self._running: set = set(); self._act = 0; self._lock = threading.Lock(); self._cond = threading.Condition(self._lock); self._barriers: Dict[str, threading.Barrier] = {}
    def schedule(self, t):
        with self._lock: self._tasks[t.task_id] = t
    def add_task(self, tid, func, args=None, kwargs=None, pri=10, deps=None, ttype=TaskType.UNIT, retries=0, sto=0, hto=0):
        t = BaseTask(tid=tid, name=tid, func=func, args=args, kwargs=kwargs, pri=pri, deps=deps or [], ttype=ttype, retries=retries, sto=sto, hto=hto); self.schedule(t); return t
    def add_batch(self, ts):
        with self._lock:
            for t in ts: self._tasks[t.task_id] = t
    def _enq(self):
        for tid, t in list(self._tasks.items()):
            if t.status in (TaskStatus.PENDING, TaskStatus.RETRYING) and t.can_run(self._done): t.status = TaskStatus.READY; heapq.heappush(self._rq, _QItem(t.priority, tid, t))
    def _dispatch(self):
        while self._rq and self._act < self.max_workers:
            item = heapq.heappop(self._rq); t = self._tasks.get(item.task_id)
            if t is None or t.status != TaskStatus.READY: continue
            t.status = TaskStatus.RUNNING; self._running.add(t.task_id); self._act += 1
            threading.Thread(target=self._exec, args=(t,), daemon=True, name=f"t-{t.task_id}").start()
    def _exec(self, t):
        try:
            if t.func: t.result = TaskResult(t.task_id, ok=True, data=t.func(*t.args, **t.kwargs))
            else: t.result = TaskResult(t.task_id, ok=True)
        except Exception as e: _log.exception("task %s failed", t.task_id); t.result = TaskResult(t.task_id, ok=False, error=str(e))
        finally:
            with self._lock:
                if t.result and t.result.ok: t.status = TaskStatus.DONE; t._finished = time.time(); self._done.add(t.task_id)
                elif t.retries > 0: t.retries -= 1; t.status = TaskStatus.RETRYING; t.retry_delay *= 2; _log.info("task %s retry %d/%d", t.task_id, t._max_r - t.retries, t._max_r); threading.Timer(t.retry_delay, lambda: (self._enq(), self._dispatch(), self._cond.notify_all())).start()
                else: t.status = TaskStatus.FAILED; t._finished = time.time()
                self._running.discard(t.task_id); self._act -= 1; self._cond.notify_all()
    def run_all(self, to=None):
        st = time.time()
        with self._lock: self._enq(); self._dispatch()
        while True:
            with self._lock:
                dn = sum(1 for t in self._tasks.values() if t.status in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.SKIPPED))
                if dn >= len(self._tasks): break
                rem = max(1.0, to - (time.time() - st)) if to else 60.0; self._cond.wait(timeout=rem); self._enq(); self._dispatch()
    def run_stage(self, sn, tids, to=None):
        miss = [tid for tid in tids if tid not in self._tasks]
        if miss: _log.warning("stage %s: missing %s", sn, miss)
        pend = [tid for tid in tids if tid in self._tasks and self._tasks[tid].status not in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.SKIPPED)]
        if not pend: return self.results()
        with self._lock: self._enq(); self._dispatch()
        st = time.time()
        while True:
            with self._lock:
                if all(self._tasks.get(tid) is None or self._tasks[tid].status in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.SKIPPED) for tid in tids): break
                rem = max(1.0, to - (time.time() - st)) if to else 30.0; self._cond.wait(timeout=rem); self._enq(); self._dispatch()
        return self.results()
    def results(self): return {tid: t.result for tid, t in self._tasks.items() if t.result is not None}
    def status(self): return {tid: t.status.value for tid, t in self._tasks.items()}
    @property
    def tasks(self): return list(self._tasks.values())
    @property
    def pending_count(self): return sum(1 for t in self._tasks.values() if t.status in (TaskStatus.PENDING, TaskStatus.READY, TaskStatus.RETRYING))
    def summary(self):
        c = {s.value: 0 for s in TaskStatus}
        for t in self._tasks.values(): c[t.status.value] += 1
        c["total"] = len(self._tasks); return c

class AnalysisPipeline:
    def __init__(self, sch=None): self.scheduler = sch or TaskScheduler(); self.stages: List[str] = []
    def add_stage(self, n, f, deps=None): self.scheduler.add_task(n, f, deps=deps or self.stages[-1:]); self.stages.append(n)
    def add_stage_batch(self, n, ts): self.scheduler.add_batch(ts); self.stages.append(n)
    def run(self): self.scheduler.run_all()
    def run_staged(self, to=None):
        sr = {}; i = 0
        while i < len(self.stages):
            n = self.stages[i]; sts = [t for t in self.scheduler.tasks if t.name.startswith(n) or (i > 0 and t.name in self.stages[i-1:i+1])]
            if not sts: sts = [t for t in self.scheduler.tasks if t.status != TaskStatus.DONE]
            sr[n] = self.scheduler.run_stage(n, [t.task_id for t in sts], to); i += 1
        return sr

def create_default_pipeline(): return AnalysisPipeline()
module: str = ""


def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

