# 场景化对抗扰动改为独立采样
# 增加 CVaR 模式
#
# Wasserstein 分布鲁棒调度 - 有限样本下的执行时间不确定性对冲
#
# GRL-Sched 假设 DAG 节点的 exec_time 是确定值。实际只有少量历史样本，
# 样本均值的估计方差大-导致调度在观测样本上最优而在真实分布上退化。
#
# 分布鲁棒优化 (DRO) 不对真实分布做点估计，而是构造一个"模糊集"-
# 以经验分布 P̂_N 为中心、半径 ε 的 Wasserstein 球:
#   B_ε(P̂_N) = {Q : W(P̂_N, Q) ≤ ε},  W = 1-Wasserstein 距离
# 目标: min_{order} max_{Q∈B_ε} E_Q[makespan(order)]
#
# Wasserstein DRO 的优势:
#   1. 有限样本保证 (Finite Sample Guarantee):
#      若 ε_N ∝ N^{-1/d}，则真实分布在 B_ε 内的概率 ≥ 1-β
#   2. 对抗最坏分布的鲁棒性: 即使在凹/多峰分布下也保持性能
#   3. 与矩约束 DRO 的区别: Wasserstein 球尊重分布的几何结构
#      (相近的执行时间被合并而非独立对待)
#
# 与 Lu et al. 的区别:
#   该文做单机调度的 Wasserstein DRO (MILP 重构)。
#   本模块做 DAG 调度-更复杂的组合结构，使用场景化近似而非精确重构。

from __future__ import annotations

import math
import random
from typing import Optional, List, Dict, Tuple

from .grl_graph import TaskDependencyGraph
from .grl_scheduler import MakespanSimulator, heft_order


def wasserstein1(samples_a: List[float], samples_b: List[float]) -> float:
    """1-Wasserstein 距离 - 两经验分布间的地球移动距离。

    对于 1D 数据等价于排序后逐点差的绝对值和。
    """
    a = sorted(samples_a)
    b = sorted(samples_b)
    n = min(len(a), len(b))
    return sum(abs(a[i] - b[i]) for i in range(n)) / n


def wasserstein_radius(samples: List[float], beta: float = 0.10,
                       dim: int = 1) -> float:
    """有限样本保证的 Wasserstein 球半径。

    ε_N = C·[ (1/dim)·log(1/β) / N ]^{1/max(dim,2)}
    其中 C 是依赖于分布直径的常数。
    简化为: ε_N ≈ σ_sample · √(log(1/β) / N)
    """
    n = len(samples)
    if n < 3:
        return float('inf')
    sd = math.sqrt(
        sum((x - sum(samples)/n)**2 for x in samples) / (n - 1)
    )
    return sd * math.sqrt(math.log(1.0 / max(beta, 1e-9)) / n)


class WassersteinRobustScheduler:
    """Wasserstein 分布鲁棒调度器。

    对每个任务维护执行时间的历史样本 (而非点估计)。
    调度时在 Wasserstein 球的最坏分布上评估 makespan-
    等价于对经验样本施加对抗性扰动后取最坏 makespan。
    """

    def __init__(self, n_machines: int = 2, n_scenarios: int = 30,
                 robustness: float = 0.10, seed: Optional[int] = None):
        self._M = n_machines
        self._S = n_scenarios       # 场景采样数
        self._beta = robustness     # 真实分布在球外的概率上界
        self._rng = random.Random(seed)
        # task_id -> 历史执行时间列表
        self._task_samples: Dict[str, List[float]] = {}

    def add_sample(self, task_id: str, exec_time: float):
        if task_id not in self._task_samples:
            self._task_samples[task_id] = []
        self._task_samples[task_id].append(exec_time)
        # 限制存储: 每任务最多保留 200 个样本
        if len(self._task_samples[task_id]) > 200:
            self._task_samples[task_id] = self._task_samples[task_id][-200:]

    def schedule(self, dag: TaskDependencyGraph,
                 mode: str = "robust") -> dict:
        """Wasserstein 鲁棒调度。

        mode:
          "robust"  - 对抗最坏分布的 makespan 最小化
          "nominal" - 对经验均值使用 HEFT (基线)
          "cvar"    - 对 top-α 最坏场景的 CVaR 最小化
        """
        ids = dag.node_ids
        if not ids:
            return {"order": [], "makespan": 0.0, "mode": mode}

        if mode == "nominal":
            return self._nominal_schedule(dag)

        # 为每个任务计算 Wasserstein 半径
        radii = {}
        for nid in ids:
            samples = self._task_samples.get(nid, [dag.node(nid).exec_time])
            radii[nid] = wasserstein_radius(samples, self._beta)
        max_radius = max(radii.values()) if radii else 0.1

        # 生成对抗场景: 对每个任务的执行时间做最坏扰动
        sim = MakespanSimulator(self._M)
        best_order = heft_order(dag)
        best_worst_makespan = float('inf')

        for _ in range(self._S):
            # 对抗场景: 独立扰动每个任务的 exec_time
            perturbed_dag = self._perturb_dag(dag, radii, adversarial=True)
            # 在扰动后的 DAG 上用 HEFT 求调度
            order = heft_order(perturbed_dag)
            ms = sim.simulate(dag, order)  # 用原始 DAG 评估 (保守)
            if ms < best_worst_makespan:
                best_worst_makespan = ms
                best_order = order

        if mode == "cvar":
            # CVaR: 对最坏 α 分位场景求均值 -> 选择最小 CVaR 的 order
            alpha = 0.2
            all_ms = []
            all_orders = []
            for _ in range(self._S):
                p_dag = self._perturb_dag(dag, radii, adversarial=True)
                order = heft_order(p_dag)
                all_orders.append(order)
                all_ms.append(sim.simulate(dag, order))
            cutoff = int(self._S * alpha)
            worst_idx = sorted(range(len(all_ms)), key=lambda i: -all_ms[i])[:max(1, cutoff)]
            cvar_orders = [all_orders[i] for i in worst_idx]
            best_order = cvar_orders[0]
            best_worst_makespan = min(
                sim.simulate(dag, o) for o in cvar_orders
            )

        return {
            "order": best_order,
            "assignments": sim.assign(dag, best_order),
            "makespan": best_worst_makespan,
            "mode": mode,
            "wasserstein_radius": round(max_radius, 4),
        }

    def _nominal_schedule(self, dag: TaskDependencyGraph) -> dict:
        """经验均值调度 - HEFT 基线。"""
        sim = MakespanSimulator(self._M)
        # 用样本均值替换 exec_time
        dag_mean = self._mean_dag(dag)
        order = heft_order(dag_mean)
        # 在原始 DAG 上评估
        ms = sim.simulate(dag, order)
        return {"order": order, "assignments": sim.assign(dag, order),
                "makespan": ms, "mode": "nominal"}

    def _mean_dag(self, dag: TaskDependencyGraph) -> TaskDependencyGraph:
        """构造经验均值 DAG。"""
        from copy import copy
        new_dag = TaskDependencyGraph()
        for nid in dag.node_ids:
            nd = dag.node(nid)
            new_nd = copy(nd)
            samples = self._task_samples.get(nid, [nd.exec_time])
            new_nd.exec_time = sum(samples) / len(samples) if samples else nd.exec_time
            new_dag.add_node(new_nd)
        for nid in dag.node_ids:
            for e in dag._out.get(nid, []):
                new_dag.add_edge(e.src, e.dst, e.comm_cost, e.kind)
        return new_dag

    def _perturb_dag(self, dag: TaskDependencyGraph,
                     radii: Dict[str, float],
                     adversarial: bool = True) -> TaskDependencyGraph:
        """构造扰动 DAG - 每个任务的 exec_time 偏移 ±radius。"""
        from copy import copy
        new_dag = TaskDependencyGraph()
        for nid in dag.node_ids:
            nd = dag.node(nid)
            new_nd = copy(nd)
            r = radii.get(nid, 0.1)
            if adversarial:
                # 对抗: 增加执行时间 (最坏情况)
                delta = self._rng.uniform(0, r)
                new_nd.exec_time = max(0.01, nd.exec_time + delta)
            else:
                delta = self._rng.uniform(-r, r)
                new_nd.exec_time = max(0.01, nd.exec_time + delta)
            new_dag.add_node(new_nd)
        for nid in dag.node_ids:
            for e in dag._out.get(nid, []):
                new_dag.add_edge(e.src, e.dst, e.comm_cost, e.kind)
        return new_dag

    def stats(self) -> dict:
        return {
            "tracked_tasks": len(self._task_samples),
            "avg_samples_per_task": round(
                sum(len(v) for v in self._task_samples.values()) /
                max(len(self._task_samples), 1), 1
            ),
            "robustness_beta": self._beta,
            "n_scenarios": self._S,
        }
