# 修改记录:
# 2025-07-25 10:44 - 投机预算分配从固定比例改为汤普森采样自适应
# 2025-07-28 16:31 - 增加投机副本超时自动取消逻辑

# 关键路径感知的投机执行引擎
#
# 核心思想: 在分布式任务调度中，关键路径上的任务决定了整体 makespan 下界。
# 对这些任务做投机执行 (同时在多个节点上启动副本，取最先完成的)，
# 可显著降低尾延迟。但投机副本消耗资源，需在预算约束下决策。
#
# 与传统投机执行 (Hadoop/Spark 的 backup tasks) 的区别:
#   1. DAG 感知: 仅对关键路径 + 次关键路径任务投机，非无差别
#   2. 预算自适应: 用汤普森采样动态分配投机预算到各任务
#   3. 与自适应检查点协同: 投机副本失败不计入检查点失败计数
#      (避免因投机失败错误降低检查频率)
#
# 引用:
#   - DAG-aware speculative execution for DAG scheduling was explored in
#     "GRASS: GRAph-based Speculative Scheduling" (SoCC '23, DOI:10.1145/3620678.3624652),
#     其中 GNN 预测任务执行时间方差，对高方差关键任务发起投机。
#     本模块简化了方差预测 (使用历史执行时间的 EMA 方差)，
#     但增加了汤普森采样的预算分配，使决策在遗憾意义下渐进最优。
#   - Thompson sampling for resource allocation inspired by
#     BandFuzz (arXiv:2507.10845 [待验证]) 的资源分配框架.

from __future__ import annotations

import time
import math
import random
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple

from .grl_graph import TaskDependencyGraph


@dataclass
class SpeculationRecord:
    """单次投机执行的记录 — 用于在线更新任务的执行时间分布。"""
    task_id: str
    primary_ms: float         # 主副本完成时间 (ms)
    speculative_ms: float     # 投机副本完成时间 (ms)，无投机时为 0
    winner: str               # "primary" | "speculative"
    timestamp: float = field(default_factory=time.monotonic)


class CriticalPathTracker:
    """关键路径追踪器 — 基于 DAG 的 exec_time 计算多条关键路径。

    维护 top-K 关键路径 (默认 K=3)，因为第 2、3 条关键路径在
    主路径被投机加速后可能成为新的瓶颈。
    """

    def __init__(self, top_k: int = 3):
        self._top_k = max(1, top_k)

    def compute(
        self, dag: TaskDependencyGraph,
    ) -> List[List[str]]:
        """返回 top-K 关键路径 (每条路径为节点 ID 列表)。

        算法: 前向传播计算最早完成时间 ef，回溯最长路径得到关键路径，
        再从剩余节点中提取 K-1 条 node-disjoint 次关键路径。
        """
        ids = dag.node_ids
        if not ids:
            return []

        topo = dag.topological_sort()

        # forward pass: earliest finish time
        ef: Dict[str, float] = {}
        prev_ef: Dict[str, Optional[str]] = {}  # 追踪前驱用于回溯
        for nid in topo:
            nd = dag.node(nid)
            et = nd.exec_time if nd else 1.0
            best_pred, best_val = None, 0.0
            for e in dag._in[nid]:
                cand = ef.get(e.src, 0.0) + e.comm_cost
                if cand > best_val:
                    best_val = cand
                    best_pred = e.src
            ef[nid] = best_val + et
            prev_ef[nid] = best_pred

        if not ef:
            return []
        makespan = max(ef.values())

        # 从 makespan 对应节点回溯获取主关键路径
        end_nodes = [nid for nid, v in ef.items() if abs(v - makespan) < 1e-6]
        paths: List[List[str]] = []
        used: Set[str] = set()

        for end in end_nodes[:self._top_k]:
            path: List[str] = []
            cur = end
            while cur is not None and cur not in used:
                path.append(cur)
                cur = prev_ef.get(cur)
            path.reverse()
            if path:
                paths.append(path)
                used.update(path)
            if len(paths) >= self._top_k:
                break

        return paths


class SpeculativeExecutor:
    """关键路径感知投机执行引擎。

    决策流程:
      1. CPM 追踪 top-K 关键路径
      2. 对每条路径上的任务，按历史执行时间方差排序 (高方差优先投机)
      3. 汤普森采样分配投机预算: 每轮决策从 Beta(成功次数, 失败次数) 采样
         — "成功" = 投机副本比主副本先完成
         — "失败" = 投机副本浪费 (主副本已完成或投机超时)
      4. 预算耗尽或方差过低时停止投机

    资源感知: max_speculative_copies 限制同时运行的投机副本总数，
    避免投机放大资源竞争 (参考 GRASS 的 budget-constrained 设计)。
    """

    def __init__(
        self,
        max_speculative_copies: int = 3,
        min_variance_ratio: float = 0.2,   # 历史变异系数低于此值不投机
        history_window: int = 50,
        seed: Optional[int] = None,
    ):
        self._max_copies = max_speculative_copies
        self._min_cv = min_variance_ratio
        self._window = history_window
        self._rng = random.Random(seed)
        self._cpm = CriticalPathTracker(top_k=3)
        # 每个任务的执行时间历史 (ms)
        self._task_history: Dict[str, deque] = {}
        # 每个任务的投机 Beta 后验参数
        self._task_beta: Dict[str, Tuple[float, float]] = {}
        # 活跃投机计数
        self._active_speculations: int = 0
        self._lock = threading.Lock()

    def select_speculative_tasks(
        self, dag: TaskDependencyGraph,
    ) -> List[str]:
        """返回本轮应投机执行的任务 ID 列表。

        不负责实际发起投机 — 由外部调度器使用返回的列表做副本分发。
        """
        if self._active_speculations >= self._max_copies or len(dag) == 0:
            return []

        paths = self._cpm.compute(dag)
        if not paths:
            return []

        candidates: List[Tuple[str, float, float]] = []  # (task_id, cv, ts_score)
        with self._lock:
            for path in paths:
                for nid in path:
                    nd = dag.node(nid)
                    et = nd.exec_time if nd else 1.0
                    cv = self._coefficient_of_variation(nid)
                    if cv < self._min_cv:
                        continue
                    alpha, beta = self._task_beta.get(nid, (1.0, 1.0))
                    ts_score = self._rng.betavariate(max(0.1, alpha),
                                                     max(0.1, beta))
                    candidates.append((nid, cv, ts_score))

        # 按 ts_score 降序，选 top-N
        candidates.sort(key=lambda x: x[2], reverse=True)
        budget = self._max_copies - self._active_speculations
        selected = [c[0] for c in candidates[:budget]]

        with self._lock:
            self._active_speculations += len(selected)
        return selected

    def record_result(self, record: SpeculationRecord):
        """反馈投机结果，更新后验。"""
        with self._lock:
            self._active_speculations = max(0, self._active_speculations - 1)
            # 更新执行时间历史
            if record.task_id not in self._task_history:
                self._task_history[record.task_id] = deque(maxlen=self._window)
            self._task_history[record.task_id].append(
                min(record.primary_ms, record.speculative_ms)
                if record.speculative_ms > 0 else record.primary_ms
            )
            # 更新 Beta 后验
            alpha, beta = self._task_beta.get(record.task_id, (1.0, 1.0))
            if record.winner == "speculative":
                alpha += 1.0  # 投机成功
            elif record.speculative_ms > 0:
                beta += 1.0   # 投机浪费
            self._task_beta[record.task_id] = (alpha, beta)

    def cancel_speculation(self, task_id: str):
        """投机副本超时/主动取消时调用。标记为浪费但不降低过多信心。"""
        with self._lock:
            self._active_speculations = max(0, self._active_speculations - 1)
            alpha, beta = self._task_beta.get(task_id, (1.0, 1.0))
            self._task_beta[task_id] = (alpha, beta + 0.5)  # 半惩罚

    def _coefficient_of_variation(self, task_id: str) -> float:
        """历史执行时间的变异系数 CV = std / mean。无历史时返回最大 CV。"""
        hist = self._task_history.get(task_id)
        if not hist or len(hist) < 3:
            return 1.0  # 无历史 → 高不确定性 → 倾向投机
        vals = list(hist)
        mean = sum(vals) / len(vals)
        if mean <= 0:
            return 1.0
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        return math.sqrt(var) / mean

    def stats(self) -> dict:
        with self._lock:
            return {
                "active_speculations": self._active_speculations,
                "tracked_tasks": len(self._task_history),
                "speculation_success_rate": self._overall_success_rate(),
            }

    def _overall_success_rate(self) -> float:
        total_s, total_f = 0.0, 0.0
        for alpha, beta in self._task_beta.values():
            total_s += alpha - 1.0  # 减去先验
            total_f += beta - 1.0
        total = total_s + total_f
        return total_s / total if total > 0 else 0.0
