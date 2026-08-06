# -*- coding: utf-8 -*-
# 创建: 2026-07-30  — 推测执行核心 + QualityScorer
# 修改: 2026-08-04  — 补齐调度器浅克隆, 支持真正的并行推测执行
"""
推测性分叉-汇合执行 — DAG 分支点处并行执行多条备选路径, 按产出质量评分
选择最优结果. 与集成方法的差异: 选择单一最优而非合并全部, 避免劣质结果稀释信噪比.

每条路径使用调度器的浅克隆实例, 消除共享状态竞态, 实现真正的并行推测.
并行度由路径数自然决定, 上限为 CPU 核数.
"""

import copy
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class SpecPath:
    name: str
    hooks: List[str]
    expected_duration_ms: float = 0.0
    weight: float = 0.5


@dataclass
class PathResult:
    path_name: str
    context: Dict[str, Any]
    quality_score: float = 0.0
    wall_ms: float = 0.0
    success: bool = True
    error_msg: str = ''


@dataclass
class SpecPlan:
    winner: PathResult
    losers: List[PathResult]
    fork_point: str
    total_wall_ms: float
    resource_saved_ms: float


class QualityScorer:
    """钩子产出质量评分 — 结构完整性×信息密度×新颖性×类型丰富度."""

    def __init__(
        self, struct_w: float = 0.25, density_w: float = 0.20,
        novelty_w: float = 0.30, type_w: float = 0.25,
    ):
        self._w = (struct_w, density_w, novelty_w, type_w)
        self._prev_keys: Set[str] = set()

    def score(self, output: Any, prev_keys: Optional[Set[str]] = None) -> float:
        if output is None:
            return 0.0
        if not isinstance(output, dict):
            return 0.15
        pk = prev_keys or self._prev_keys
        total = len(output)
        if total == 0:
            return 0.05
        non_empty = sum(1 for v in output.values()
                       if v is not None and v != [] and v != {} and v != '')
        struct = non_empty / max(1, total)
        try:
            total_len = sum(len(str(v)) for v in output.values())
        except Exception:
            total_len = 0
        import math
        density = 1.0 / (1.0 + math.exp(-(total_len - 80) / 50))
        new_keys = set(output) - pk
        novelty = len(new_keys) / max(1, total)
        type_score = 0.0
        for v in output.values():
            if isinstance(v, dict):       type_score += 0.8
            elif isinstance(v, (list, tuple)): type_score += 0.7
            elif isinstance(v, str) and len(v) > 10: type_score += 0.5
            else:                         type_score += 0.3
        type_score /= max(1, total)
        w = self._w
        return w[0]*struct + w[1]*density + w[2]*novelty + w[3]*type_score

    def set_prev_keys(self, keys: Set[str]):
        self._prev_keys = set(keys)


class SpecExecutor:
    """推测执行器 — 克隆调度器后并行执行备选路径, 按质量择优.

    调度器克隆策略: 浅拷贝任务注册表 + 重建拓扑结构.
    任务的可调用对象 (fn) 共享引用, 内部状态 (telemetry 等) 各自独立.
    """

    def __init__(self, scheduler, paths: List[SpecPath],
                 fork_point: str = '', scorer: Optional[QualityScorer] = None):
        self._sched = scheduler
        self._paths = paths
        self._fork_point = fork_point
        self._scorer = scorer or QualityScorer()

    def execute(
        self, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None,
    ) -> Tuple[Dict[str, Any], SpecPlan]:
        if context is None:
            context = {}
        if not self._paths:
            result = self._sched.execute(context) if hasattr(self._sched, 'execute') else context
            return result, SpecPlan(
                winner=PathResult('default', result, 1.0, 0, True),
                losers=[], fork_point='', total_wall_ms=0, resource_saved_ms=0)

        self._scorer.set_prev_keys(set(context))
        t0 = time.perf_counter()

        # 克隆调度器: 每条路径独立实例, 消除并行竞态
        clones = [self._clone_scheduler() for _ in self._paths]
        results: List[PathResult] = []
        workers = min(len(self._paths), max_workers or 8)

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {}
            for path, clone in zip(self._paths, clones):
                f = ex.submit(self._run_path, path, clone, dict(context))
                futures[f] = path.name
            for f in as_completed(futures):
                name = futures[f]
                try:
                    results.append(f.result(timeout=120))
                except Exception as e:
                    results.append(PathResult(
                        name, {}, 0.0, 0, False, f'{type(e).__name__}: {e}'))

        total_wall = (time.perf_counter() - t0) * 1000
        if not results:
            return context, SpecPlan(
                winner=PathResult('empty', context, 0, 0, False),
                losers=[], fork_point=self._fork_point,
                total_wall_ms=total_wall, resource_saved_ms=0)

        winner = max(results, key=lambda r: r.quality_score)
        losers = [r for r in results if r is not winner]
        serial_cost = sum(r.wall_ms for r in results if r.success)
        saved = max(0, serial_cost - total_wall)
        return winner.context, SpecPlan(
            winner=winner, losers=losers, fork_point=self._fork_point,
            total_wall_ms=total_wall, resource_saved_ms=saved)

    def _clone_scheduler(self):
        """浅克隆调度器: 复制任务注册表 + 重建拓扑, 可调用对象共享引用.

        HookDAGScheduler 的 _tasks 是 dict[str, HookTask], HookTask 的 fn 是
        不可变引用, 因此浅拷贝安全. _telemetry/_failed/_skipped 在 execute() 中
        每次重建, 无需拷贝.
        """
        src = self._sched
        # 动态导入避免循环依赖
        from modules.core.hook_dag_scheduler import HookDAGScheduler
        clone = HookDAGScheduler()
        if hasattr(src, '_tasks'):
            for name, task in src._tasks.items():
                clone.register(
                    name, task.fn, module=task.module, attr=task.attr,
                    deps=task.deps, group=task.group, condition=task.condition,
                    priority=task.priority, timeout=task.timeout,
                    mode=task.mode, consumes=task.consumes,
                    kwargs=dict(task.kwargs), on_dep_failed=task.on_dep_failed,
                    provides=task.provides, description=task.description,
                )
        clone.build()
        return clone

    def _run_path(self, path: SpecPath, sched, ctx: dict) -> PathResult:
        if not hasattr(sched, '_execute_one'):
            return PathResult(path.name, ctx, 0, 0, True)
        ctx_before = dict(ctx)
        path_set = set(path.hooks)
        orig = sched._execute_one
        t0 = time.perf_counter()

        def _path_exec(name: str, c: dict, failed: set, skipped: set) -> None:
            if name in path_set:
                orig(name, c, failed, skipped)

        sched._execute_one = _path_exec
        try:
            sched.execute(ctx)
        finally:
            sched._execute_one = orig

        wall = (time.perf_counter() - t0) * 1000
        path_output = {k: v for k, v in ctx.items() if k not in ctx_before}
        score = self._scorer.score(path_output)
        return PathResult(
            path_name=path.name, context=ctx,
            quality_score=score, wall_ms=wall, success=True)

    def summary(self, plan: SpecPlan) -> Dict[str, Any]:
        return {
            'fork_point': plan.fork_point,
            'winner': plan.winner.path_name,
            'winner_score': round(plan.winner.quality_score, 3),
            'losers': [{'name': r.path_name, 'score': round(r.quality_score, 3)}
                      for r in plan.losers],
            'total_wall_ms': round(plan.total_wall_ms, 1),
            'saved_ms': round(plan.resource_saved_ms, 1),
            'num_paths': len(self._paths),
        }
