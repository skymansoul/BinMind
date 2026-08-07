# 测试工作流编排 — 阶段流水线+依赖解析+并行执行
# 拓扑排序采用Kahn算法变体 — 分level执行，同级可并行。
# 循环依赖检测在build_pipeline时报错（非运行时静默死锁）。
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional, Set, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading
from collections import defaultdict, deque
from itertools import pairwise  # unused; TaskType/TaskStatus调用问题已在重构中修复为str,Enum


@dataclass
class StageResult:
    name: str
    success: bool
    output: Any = None
    duration: float = 0.0
    error: Optional[str] = None
    retries_used: int = 0
    logs: List[str] = field(default_factory=list)


@dataclass
class TestStage:
    name: str
    runner: Callable[..., Any]  # (context, **kwargs) -> result
    depends_on: List[str] = field(default_factory=list)
    timeout: float = 300.0
    retry_count: int = 0
    required: bool = True   # 若False，失败不阻塞流水线
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineConfig:
    stages: List[TestStage] = field(default_factory=list)
    parallel_groups: List[Set[str]] = field(default_factory=list)


class TestOrchestrator:
    """测试流水线编排器。

    工作流:
    add_stage() -> build_pipeline() -> execute(parallel=True/False)
    - 依赖解析用拓扑排序分level
    - 同级stage可选并行 (ThreadPoolExecutor)
    - 循环依赖检测
    - 失败策略: required=False的stage失败不阻塞后续
    """

    def __init__(self, max_workers: int = 4):
        self._stages: Dict[str, TestStage] = {}
        self._levels: List[List[str]] = []  # topological levels
        self._results: Dict[str, StageResult] = {}
        self.max_workers = max_workers
        self._lock = threading.Lock()

# Stage管理
    def add_stage(self, stage: TestStage):
        self._stages[stage.name] = stage
        self._levels = []  # 使流水线缓存失效

    def get_stage(self, name: str) -> Optional[TestStage]:
        return self._stages.get(name)

    def remove_stage(self, name: str):
        self._stages.pop(name, None)
        self._levels = []

# 流水线构建
    def build_pipeline(self) -> List[List[str]]:
        """Kahn风格拓扑排序，分为执行level。

        循环依赖 -> 抛出ValueError。
        """
        _in_degree = {_n: len(_s.depends_on) for _n, _s in self._stages.items()}
        _dep_children = defaultdict(list)
        for _n, _s in self._stages.items():
            for _dep in _s.depends_on:
                if _dep not in self._stages:
                    raise ValueError(f"Stage '{_n}' depends on unknown stage '{_dep}'")
                _dep_children[_dep].append(_n)

        # Kahn
        _q = deque([_n for _n, _d in _in_degree.items() if _d == 0])
        _levels = []
        _visited = 0

        while _q:
            _level = []
            for _ in range(len(_q)):
                _node = _q.popleft()
                _level.append(_node)
                _visited += 1
                for _child in _dep_children.get(_node, []):
                    _in_degree[_child] -= 1
                    if _in_degree[_child] == 0:
                        _q.append(_child)
            _levels.append(_level)

        if _visited != len(self._stages):
            _remaining = [_n for _n, _d in _in_degree.items() if _d > 0]
            raise ValueError(
                "Circular dependency detected among stages: {}".format(
                    ", ".join(_remaining)))

        self._levels = _levels
        return _levels

    @property
    def levels(self) -> List[List[str]]:
        if not self._levels and self._stages:
            self.build_pipeline()
        return self._levels

# 执行
    def execute(self, stages: List[str] = None,
                parallel: bool = False,
                context: Dict[str, Any] = None) -> Dict[str, StageResult]:
        """执行流水线。

        - stages: 只执行指定stages (必须按序包含依赖)
        - parallel: 同level并行执行
        - context: 传递给runner的共享上下文
        """
        if not self._levels:
            self.build_pipeline()

        _ctx = context or {}
        self._results = {}

        _target_set = set(stages) if stages else set(self._stages.keys())
        # 确保依赖也被包含
        _expanded = set(_target_set)
        for _n in list(_target_set):
            _s = self._stages.get(_n)
            if _s:
                for _d in _s.depends_on:
                    _expanded.add(_d)

        for _level in self._levels:
            _to_run = [_n for _n in _level if _n in _expanded]
            if not _to_run:
                continue

            # 检查前驱是否都成功（required的）
            _skip = []
            for _n in _to_run:
                _s = self._stages[_n]
                _blocked = False
                for _d in _s.depends_on:
                    _r = self._results.get(_d)
                    if _r and not _r.success and self._stages[_d].required:
                        _blocked = True
                        break
                if _blocked:
                    _skip.append(_n)
            _to_run = [_n for _n in _to_run if _n not in _skip]

            if parallel and len(_to_run) > 1:
                self._run_parallel(_to_run, _ctx)
            else:
                for _n in _to_run:
                    self._run_stage(_n, _ctx)

        return self._results

    def _run_stage(self, name: str, context: Dict):
        _stage = self._stages[name]
        _retries = 0
        _t0 = time.perf_counter()

        while _retries <= _stage.retry_count:
            try:
                _out = _stage.runner(context, **_stage.metadata)
                _dt = time.perf_counter() - _t0
                with self._lock:
                    self._results[name] = StageResult(
                        name=name, success=True, output=_out,
                        duration=_dt, retries_used=_retries)
                return
            except Exception as _e:
                _retries += 1
                if _retries > _stage.retry_count:
                    _dt = time.perf_counter() - _t0
                    with self._lock:
                        self._results[name] = StageResult(
                            name=name, success=False,
                            duration=_dt,
                            error=f"{type(_e).__name__}: {_e}",
                            retries_used=_retries)
                    if _stage.required:
                        raise
                else:
                    time.sleep(0.5 * _retries)

    def _run_parallel(self, names: List[str], context: Dict):
        _futures = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as _exec:
            for _n in names:
                _futures[_exec.submit(self._run_stage, _n, context)] = _n
            for _f in as_completed(_futures):
                _n = _futures[_f]
                try:
                    _f.result()
                except Exception:
                    pass  # _run_stage已记录结果

# 结果
    @property
    def stage_results(self) -> Dict[str, StageResult]:
        return self._results

    def is_successful(self) -> bool:
        if not self._results:
            return False
        return all(_r.success for _r in self._results.values())

    def summary(self) -> str:
        _lines = ["Pipeline Summary", "=" * 40]
        for _level in self._levels:
            for _n in _level:
                _r = self._results.get(_n)
                if _r:
                    _status = "OK" if _r.success else "FAIL"
                    _lines.append(f"  [{_status}] {_n} ({_r.duration:.2f}s)")
                else:
                    _lines.append(f"  [SKIP] {_n}")
        return "\n".join(_lines)


def topological_sort(deps: Dict[str, List[str]]) -> List[List[str]]:
    """独立于类的拓扑排序工具函数。"""
    _in_degree = {_k: len(_v) for _k, _v in deps.items()}
    _children = defaultdict(list)
    for _k, _v in deps.items():
        for _dep in _v:
            _children[_dep].append(_k)

    _q = deque([_k for _k, _d in _in_degree.items() if _d == 0])
    _levels = []
    _seen = set()
    while _q:
        _lev = []
        for _ in range(len(_q)):
            _n = _q.popleft()
            if _n in _seen:
                continue
            _seen.add(_n)
            _lev.append(_n)
            for _c in _children[_n]:
                _in_degree[_c] -= 1
                if _in_degree[_c] == 0:
                    _q.append(_c)
        if _lev:
            _levels.append(_lev)

    if _seen != set(deps.keys()):
        raise ValueError("Circular dependency detected")
    return _levels
