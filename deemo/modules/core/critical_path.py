# -*- coding: utf-8 -*-
# 创建: 2026-07-31 — CriticalPathAnalyzer + BackpressureSensor
# 修改: 2026-08-01 — GracefulDegradationExecutor, 复合权重公式
"""
关键路径感知的优雅降级 — 资源受限时保护高影响力钩子.

大多数 DAG 调度器将任务视为等权重的节点. 在二进制分析管道中, 不同钩子的
产出对最终结果的影响差异显著. 计算下游影响分数 (transitive downstream consumers),
找出关键路径; 背压超阈值时跳过低影响分节点, 背压解除后自动恢复.

与 priority 字段的差异: priority 是用户静态赋值, 影响分是 DAG 拓扑导出的
结构性客观度量. 二者叠加: weight = α×influence + (1-α)×priority.
"""

import math
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# psutil 可选
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


@dataclass
class NodeInfluence:
    name: str
    direct_consumers: int = 0
    transitive_consumers: int = 0
    influence_score: float = 0.0    # [0, 1], 归一化下游影响力
    on_critical_path: bool = False
    critical_path_rank: int = -1


@dataclass
class DegradationState:
    """降级模式的运行时状态."""
    active: bool = False
    level: int = 0               # 0=正常, 1=轻度降级, 2=中度, 3=重度
    skipped_hooks: List[str] = field(default_factory=list)
    threshold_score: float = 0.0
    backpressure_value: float = 0.0
    degraded_at: float = 0.0


class CriticalPathAnalyzer:
    """DAG 关键路径分析: 反向 BFS 累积下游消费者 → 归一化影响分 → 正向追踪关键路径."""

    def __init__(self):
        self._adj: Dict[str, List[str]] = defaultdict(list)
        self._rev_adj: Dict[str, List[str]] = defaultdict(list)
        self._nodes: Set[str] = set()
        self._influences: Dict[str, NodeInfluence] = {}
        self._critical_path: List[str] = []

    def build(self, edges: Dict[str, List[str]]) -> 'CriticalPathAnalyzer':
        self._adj.clear(); self._rev_adj.clear(); self._nodes.clear()
        for src, dsts in edges.items():
            self._nodes.add(src)
            for dst in dsts:
                self._adj[src].append(dst)
                self._rev_adj[dst].append(src)
                self._nodes.add(dst)
        self._compute_influence(); self._find_critical_path()
        return self

    def build_from_scheduler(self, scheduler) -> 'CriticalPathAnalyzer':
        edges = {}
        if hasattr(scheduler, 'graph_edges'):
            edges = scheduler.graph_edges()
        elif hasattr(scheduler, '_succ'):
            edges = dict(scheduler._succ)
        return self.build(edges)

    def _compute_influence(self) -> None:
        # 反向拓扑: 从汇节点向源节点累积下游消费者
        rev_in_deg: Dict[str, int] = defaultdict(int)
        for src, dsts in self._adj.items():
            for _ in dsts:
                rev_in_deg[src] = rev_in_deg.get(src, 0)  # ensure key
        for dst, srcs in self._rev_adj.items():
            rev_in_deg[dst] = len(srcs)

        # 在反向图中, 汇节点 (原 DAG 出度=0) 的入度=0
        queue = deque()
        for node in self._nodes:
            if node not in self._adj or not self._adj[node]:
                queue.append(node)

        transitive: Dict[str, Set[str]] = defaultdict(set)

        while queue:
            node = queue.popleft()
            for pred in self._rev_adj.get(node, []):
                # pred 可达 node 及其所有下游
                transitive[pred].add(node)
                transitive[pred].update(transitive[node])
                rev_in_deg[pred] -= 1
                if rev_in_deg[pred] == 0:
                    queue.append(pred)

        max_trans = max((len(v) for v in transitive.values()), default=1)
        for node in self._nodes:
            direct = len(self._adj.get(node, []))
            trans = len(transitive.get(node, set()))
            score = trans / max(max_trans, 1)
            self._influences[node] = NodeInfluence(
                name=node, direct_consumers=direct,
                transitive_consumers=trans, influence_score=score,
            )

    def _find_critical_path(self) -> None:
        if not self._influences:
            return
        all_dsts = {d for dsts in self._adj.values() for d in dsts}
        sources = [n for n in self._nodes if n not in all_dsts] or list(self._nodes)
        best_src = max(sources, key=lambda n: self._influences[n].influence_score)
        path, cur, visited = [best_src], best_src, {best_src}
        while cur in self._adj and self._adj[cur]:
            cand = [(d, self._influences[d].influence_score) for d in self._adj[cur] if d not in visited]
            if not cand: break
            cur = max(cand, key=lambda x: x[1])[0]
            path.append(cur); visited.add(cur)
        self._critical_path = path
        for i, name in enumerate(path):
            if name in self._influences:
                self._influences[name].on_critical_path = True
                self._influences[name].critical_path_rank = i

    def influence(self, name: str) -> Optional[NodeInfluence]:
        return self._influences.get(name)

    @property
    def critical_path(self) -> List[str]:
        return list(self._critical_path)

    def sorted_by_influence(self) -> List[NodeInfluence]:
        return sorted(self._influences.values(),
                     key=lambda x: x.influence_score, reverse=True)


class BackpressureSensor:
    """背压感知器: 内存+CPU+队列深度 → 指数平滑 → 加权求和 → [0,1].

    权重偏重内存 (二进制分析为内存敏感型). CPU 权重压低 (管道可能 I/O 密集).
    """

    def __init__(
        self, memory_weight: float = 0.50, cpu_weight: float = 0.20,
        queue_weight: float = 0.30,
        memory_smooth: float = 0.5, cpu_smooth: float = 0.5,
    ):
        self._w_mem = memory_weight
        self._w_cpu = cpu_weight
        self._w_queue = queue_weight
        self._smooth_mem = memory_smooth
        self._smooth_cpu = cpu_smooth
        self._ema_mem = 0.0
        self._ema_cpu = 0.0
        self._process = None  # psutil.Process 延迟初始化

    def read(self, queue_depth: int = 0, max_workers: int = 8) -> float:
        mem_p = self._read_memory()
        cpu_p = self._read_cpu()
        queue_p = min(1.0, queue_depth / max(1, max_workers))
        self._ema_mem = self._smooth_mem * mem_p + (1 - self._smooth_mem) * self._ema_mem
        self._ema_cpu = self._smooth_cpu * cpu_p + (1 - self._smooth_cpu) * self._ema_cpu
        return self._w_mem * self._ema_mem + self._w_cpu * self._ema_cpu + self._w_queue * queue_p

    def _read_memory(self) -> float:
        if not _HAS_PSUTIL: return 0.0
        try: return 1.0 - (psutil.virtual_memory().available / max(1, psutil.virtual_memory().total))
        except Exception: return 0.0

    def _read_cpu(self) -> float:
        if not _HAS_PSUTIL: return 0.0
        try: return psutil.cpu_percent(interval=None) / 100.0
        except Exception: return 0.0


class GracefulDegradationExecutor:
    """带优雅降级的 DAG 执行器 — 包装调度器, 背压高时跳过低影响力节点."""

    def __init__(
        self, scheduler, analyzer: CriticalPathAnalyzer,
        sensor: Optional[BackpressureSensor] = None,
        alpha: float = 0.60,  # influence vs priority 的权重系数
        degrade_thresholds: Tuple[float, float, float] = (0.45, 0.60, 0.75),
    ):
        self._sched = scheduler
        self.analyzer = analyzer
        self.sensor = sensor or BackpressureSensor()
        self._alpha = alpha
        self._thresholds = degrade_thresholds
        self.state = DegradationState()

    def execute(
        self, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None,
        parallel: bool = True,
    ) -> Tuple[Dict[str, Any], DegradationState]:
        """执行管道, 背压高时自动降级."""
        if context is None:
            context = {}

        # 读取背压并判定降级级别
        bp = self.sensor.read()
        self.state.backpressure_value = bp
        self.state.skipped_hooks.clear()

        if bp < self._thresholds[0]:
            # 正常模式
            self.state.active = False
            self.state.level = 0
            self.state.threshold_score = 0.0
        elif bp < self._thresholds[1]:
            self.state.active = True
            self.state.level = 1
            self.state.threshold_score = 0.15  # 仅跳过最不重要的节点
        elif bp < self._thresholds[2]:
            self.state.active = True
            self.state.level = 2
            self.state.threshold_score = 0.35
        else:
            self.state.active = True
            self.state.level = 3
            self.state.threshold_score = 0.60  # 仅保留关键路径附近节点

        if not self.state.active:
            result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
            return result, self.state

        self.state.degraded_at = __import__('time').monotonic()
        return self._execute_degraded(context, max_workers, parallel)

    def _execute_degraded(
        self, context: Dict[str, Any],
        max_workers: Optional[int], parallel: bool,
    ) -> Tuple[Dict[str, Any], DegradationState]:
        threshold = self.state.threshold_score
        task_names = set()
        if hasattr(self._sched, '_tasks'):
            task_names = set(self._sched._tasks.keys())
        elif hasattr(self._sched, 'topological_levels'):
            for level in self._sched.topological_levels():
                task_names.update(level)

        # 复合权重: influence * α + priority * (1-α)
        scores: Dict[str, float] = {}
        for name in task_names:
            inf = self.analyzer.influence(name)
            inf_score = inf.influence_score if inf else 0.0
            pri_score = 0.5
            if hasattr(self._sched, '_tasks') and name in self._sched._tasks:
                task = self._sched._tasks[name]
                if hasattr(task, 'priority') and task.priority > 0:
                    pri_score = min(1.0, task.priority / 10.0)
            scores[name] = self._alpha * inf_score + (1 - self._alpha) * pri_score

        for name, score in scores.items():
            if score < threshold and name not in self.state.skipped_hooks:
                self.state.skipped_hooks.append(name)

        # 占位 context 使下游 on_dep_failed='continue' 可推进
        for name in self.state.skipped_hooks:
            context.setdefault(f'_skipped_{name}', True)
            context.setdefault(f'{name}_result', None)

        original_exec_one = getattr(self._sched, '_execute_one', None)
        if original_exec_one is not None:
            skipped = set(self.state.skipped_hooks)
            def _wrapped(name, ctx, failed, skip_set):
                if name in skipped:
                    skip_set.add(name)
                    return
                return original_exec_one(name, ctx, failed, skip_set)
            self._sched._execute_one = _wrapped
            try:
                result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
            finally:
                self._sched._execute_one = original_exec_one
        else:
            result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
        return result, self.state

    def skipped_summary(self) -> Dict[str, Any]:
        return {
            'level': self.state.level,
            'backpressure': round(self.state.backpressure_value, 3),
            'threshold': round(self.state.threshold_score, 3),
            'skipped': list(self.state.skipped_hooks),
            'count': len(self.state.skipped_hooks),
        }
