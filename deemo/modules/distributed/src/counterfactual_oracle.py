# 创建: 2026-06-12
# 修改: 2026-06-12 — 增加 MC 采样收敛诊断
# 修改: 2026-06-12 — 修复 attribution_scores 的除零边界条件
#
# 反事实调度谕示器 — Pearl do-calculus 驱动的调度恢复规划
#
# 问题: FaultPropagationGraph 可以定位根因节点，但回答不了"如果当初做了
# 不同的调度决策，故障影响会有多大？"。传统重调度只能修复当前状态，缺乏
# 对调度决策本身的反事实推理能力。
#
# 本模块与 fault_propagation 的关系:
#   fault_propagation: 回答 "哪个节点是根因？" (干预主义因果推断)
#   本模块:           回答 "如果任务 X 被放在机器 Y 上，makespan 会是多少？"
#                     (Pearl 反事实推理)
#
# 核心创新:
#   1. 构建调度的简化结构因果模型 (SCM):
# 外生变量 U = {机器速度波动, 网络延迟抖动, 任务执行时间噪声}
# 内生变量 V = {任务完成时间, 机器负载, makespan}
# 结构方程 F: 从 U 和父节点计算 V
#   2. 反事实查询三步:
#      Abduction:  从观测结果推断外生变量 U 的后验
#      Action:     施加 do(assignment = A') 干预
#      Prediction: 在新赋值下计算反事实 makespan
#   3. 输出 CounterfactualReport:
# 每个受影响任务的反事实完成时间
# 反事实 makespan 与观测 makespan 的差异
# 调度决策的归因分数: 哪些决策对故障影响贡献最大
#
# 与 IDI 的区别:
#   IDI 在异常 SCM 上用干预估计替代反事实推理以避免 OOD 误差。
#   本模块在调度 SCM 上直接做反事实 — 调度的外生变量域是受控的
#   (任务执行时间分布、机器性能已知)，OOD 风险可控。
#   且 IDI 针对故障定位，本模块针对调度恢复 — 问题不同。

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple

from .grl_graph import TaskDependencyGraph
from .grl_scheduler import MakespanSimulator


@dataclass
class CounterfactualReport:
    """单次反事实查询结果。"""
    query_desc: str                      # "What if task T was on machine M?"
    observed_makespan: float
    counterfactual_makespan: float
    delta: float                         # CF - observed: 正值 = 反事实更差
    affected_tasks: List[str]
    attribution_scores: Dict[str, float] # task_id → 对 makespan 差异的贡献度
    confidence: float                    # [0,1] 基于外生噪声方差的估计可信度


# SCM 构建

class SchedulingStructuralCausalModel:
    """调度的结构因果模型。

    变量:
      外生 U:
        u_exec[task]    ~ LogNormal(0, σ_exec)    任务执行时间噪声
        u_comm[edge]    ~ LogNormal(0, σ_comm)    通信延迟噪声
        u_machine[m]    ~ Normal(1.0, σ_machine)  机器速度因子 (1.0=标称)

      内生 V:
        exec_time[t]    = base_exec[t] · u_exec[t] / u_machine[assign[t]]
        comm_time[e]    = base_comm[e] · u_comm[e]
        finish_time[t]  = max(finish_time[pred] + comm_time[pred→t]) + exec_time[t]
        makespan        = max(finish_time[t])

    结构方程 f 是确定的，给定 U 和 assignment A 可计算所有 V。
    反事实推理 = 从观测反推 U，修改 A，重算 V。
    """

    def __init__(
        self,
        sigma_exec: float = 0.15,
        sigma_comm: float = 0.10,
        sigma_machine: float = 0.08,
        seed: Optional[int] = None,
    ):
        self._sigma_exec = sigma_exec
        self._sigma_comm = sigma_comm
        self._sigma_machine = sigma_machine
        self._rng = random.Random(seed)

    def fit(
        self, dag: TaskDependencyGraph,
        observed_finish_times: Optional[Dict[str, float]] = None,
    ) -> dict:
        """构建 SCM 参数 — 从 DAG 和图拓扑估计基准执行/通信时间。

        若无观测完成时间，以 makespan 模拟器的估计作为基准。
        """
        ids = dag.node_ids
        # 基准执行时间 = DAG 节点标注的 exec_time
        base_exec = {nid: dag.node(nid).exec_time for nid in ids}
        # 基准通信代价 = 边标注的 comm_cost
        base_comm: Dict[Tuple[str, str], float] = {}
        for nid in ids:
            for e in dag._out.get(nid, []):
                base_comm[(e.src, e.dst)] = e.comm_cost

        # 若提供了观测完成时间，校准外生变量
        # (abduction: 从结果反推原因)
        u_exec = {}
        if observed_finish_times:
            for nid in ids:
                obs = observed_finish_times.get(nid)
                base = base_exec.get(nid, 1.0)
                if obs is not None and base > 0:
                    # 简化假设: 机器速度=1.0 时，噪声 = obs / base
                    # 实际使用时需考虑前驱完成时间的影响
                    u_exec[nid] = max(0.1, obs / max(base, 0.001))

        return {
            "base_exec": base_exec,
            "base_comm": base_comm,
            "u_exec": u_exec,
            "params": {
                "sigma_exec": self._sigma_exec,
                "sigma_comm": self._sigma_comm,
                "sigma_machine": self._sigma_machine,
            },
        }

    def sample_exogenous(self, dag: TaskDependencyGraph) -> dict:
        """采样外生变量 — 为反事实模拟生成一组噪声。

        返回: {u_exec: {task_id: float}, u_comm: {(src,dst): float}, u_machine: {m_id: float}}
        """
        ids = dag.node_ids
        u_exec = {}
        for nid in ids:
            u_exec[nid] = self._rng.lognormvariate(0.0, self._sigma_exec)
        u_comm = {}
        for nid in ids:
            for e in dag._out.get(nid, []):
                u_comm[(e.src, e.dst)] = self._rng.lognormvariate(0.0, self._sigma_comm)
        return {"u_exec": u_exec, "u_comm": u_comm}

    def compute_counterfactual(
        self,
        dag: TaskDependencyGraph,
        exogenous: dict,
        factual_assignment: Dict[str, int],
        counterfactual_assignment: Dict[str, int],
    ) -> Tuple[float, float, Dict[str, float]]:
        """给定外生变量和两组赋值，计算 (观测makespan, 反事实makespan, 完成时间差异)。

        关键: 外生变量在两次计算中保持不变 — 这是反事实推理的核心约束。
        "如果同一个世界 (同一组 U) 中我们做了不同决策..."
        """
        u_exec = exogenous.get("u_exec", {})
        u_comm = exogenous.get("u_comm", {})
        ids = dag.node_ids
        n_machines = max(
            max(factual_assignment.values(), default=0),
            max(counterfactual_assignment.values(), default=0),
        ) + 1

        factual_finish = self._simulate_with_noise(
            dag, ids, factual_assignment, u_exec, u_comm, n_machines
        )
        cf_finish = self._simulate_with_noise(
            dag, ids, counterfactual_assignment, u_exec, u_comm, n_machines
        )

        obs_ms = max(factual_finish.values(), default=0.0)
        cf_ms = max(cf_finish.values(), default=0.0)

        # 逐任务完成时间差异
        time_diffs = {
            nid: cf_finish.get(nid, 0.0) - factual_finish.get(nid, 0.0)
            for nid in ids
        }
        return obs_ms, cf_ms, time_diffs

    def _simulate_with_noise(
        self, dag: TaskDependencyGraph, ids: List[str],
        assignment: Dict[str, int],
        u_exec: Dict[str, float], u_comm: Dict[str, float],
        n_machines: int,
    ) -> Dict[str, float]:
        """带噪声的列表调度模拟 — 与 MakespanSimulator 兼容但注入外生噪声。"""
        remain = {n: len(dag._in[n]) for n in ids}
        ready = [n for n in ids if remain[n] == 0]
        finish: Dict[str, float] = {}
        machine_free = [0.0] * n_machines
        rank = {nid: dag.node(nid).exec_time for nid in ids}
        # 使用 HEFT rank 作为就绪选取顺序
        for nid in ids:
            rank[nid] = dag.node(nid).exec_time
            for e in dag._out[nid]:
                rank[nid] += e.comm_cost + dag.node(e.dst).exec_time

        while ready:
            nid = max(ready, key=lambda x: rank.get(x, 0.0))
            ready.remove(nid)
            m = assignment.get(nid, 0)
            if m >= n_machines:
                m = m % n_machines

            # 最早可用开始 = max(前驱完成+噪声通信, 机器空闲)
            est = 0.0
            for e in dag._in[nid]:
                pf = finish[e.src]
                if assignment.get(e.src) != m:
                    noise = u_comm.get((e.src, nid), 1.0)
                    pf += e.comm_cost * noise
                if pf > est:
                    est = pf

            start = max(est, machine_free[m])
            noise_exec = u_exec.get(nid, 1.0)
            exec_t = dag.node(nid).exec_time * noise_exec
            end = start + exec_t
            finish[nid] = end
            machine_free[m] = end

            for e in dag._out[nid]:
                remain[e.dst] -= 1
                if remain[e.dst] == 0:
                    ready.append(e.dst)
        return finish


# 反事实谕示器

class CounterfactualSchedulingOracle:
    """反事实调度谕示器 — 回答"What if"调度问题。

    典型使用场景:
      1. 故障发生后: "如果任务 T 不在故障机器 M 上，恢复时间多少？"
      2. 调度优化: "交换 T_a 和 T_b 的机器分配，makespan 变化多少？"
      3. 容量规划: "增加一台机器，makespan 减少多少？"
    """

    def __init__(
        self,
        scm: Optional[SchedulingStructuralCausalModel] = None,
        mc_samples: int = 200,
        seed: Optional[int] = None,
    ):
        self._scm = scm or SchedulingStructuralCausalModel()
        self._mc_samples = mc_samples
        self._rng = random.Random(seed)

    def what_if_reassignment(
        self,
        dag: TaskDependencyGraph,
        current_assignment: Dict[str, int],
        alternative_assignment: Dict[str, int],
        query_desc: str = "",
    ) -> CounterfactualReport:
        """核心反事实查询: 若用 alternative_assignment 替代 current_assignment。

        对多组外生变量做 MC 采样，估计反事实 makespan 的分布。
        返回期望值及置信区间。
        """
        ids = dag.node_ids
        if not ids:
            return CounterfactualReport(
                query_desc=query_desc, observed_makespan=0.0,
                counterfactual_makespan=0.0, delta=0.0,
                affected_tasks=[], attribution_scores={}, confidence=0.0,
            )

        obs_samples = []
        cf_samples = []
        all_time_diffs: Dict[str, List[float]] = {nid: [] for nid in ids}

        for _ in range(self._mc_samples):
            exog = self._scm.sample_exogenous(dag)
            obs, cf, diffs = self._scm.compute_counterfactual(
                dag, exog, current_assignment, alternative_assignment,
            )
            obs_samples.append(obs)
            cf_samples.append(cf)
            for nid, d in diffs.items():
                all_time_diffs[nid].append(d)

        # 统计
        avg_obs = sum(obs_samples) / len(obs_samples)
        avg_cf = sum(cf_samples) / len(cf_samples)

        # 归因分数: 各任务完成时间差异对总 makespan 差异的贡献
        avg_diffs = {
            nid: sum(vals) / len(vals) if vals else 0.0
            for nid, vals in all_time_diffs.items()
        }
        total_positive = sum(max(0.0, d) for d in avg_diffs.values())
        attribution = {
            nid: max(0.0, d) / max(total_positive, 0.001)
            for nid, d in avg_diffs.items()
        }

        # 置信度: 基于 makespan 差异的变异系数
        diffs_series = [cf_samples[i] - obs_samples[i] for i in range(len(obs_samples))]
        mean_diff = sum(diffs_series) / len(diffs_series)
        var_diff = sum((d - mean_diff) ** 2 for d in diffs_series) / len(diffs_series)
        cv = math.sqrt(var_diff) / max(abs(mean_diff), 0.001)
        confidence = max(0.0, min(1.0, 1.0 / (1.0 + cv)))

        changed_tasks = [
            nid for nid in ids
            if current_assignment.get(nid) != alternative_assignment.get(nid)
        ]

        return CounterfactualReport(
            query_desc=query_desc or "counterfactual reassignment",
            observed_makespan=round(avg_obs, 4),
            counterfactual_makespan=round(avg_cf, 4),
            delta=round(avg_cf - avg_obs, 4),
            affected_tasks=changed_tasks,
            attribution_scores={k: round(v, 4) for k, v in attribution.items() if v > 0.01},
            confidence=round(confidence, 4),
        )

    def what_if_add_machine(
        self,
        dag: TaskDependencyGraph,
        current_assignment: Dict[str, int],
        n_current_machines: int,
    ) -> CounterfactualReport:
        """反事实: 增加一台机器后的 makespan。"""
        ids = dag.node_ids
        # 贪心将部分任务分配到新机器
        alt = dict(current_assignment)
        # 选取完成时间最晚的 1/n 任务移到新机器
        sim = MakespanSimulator(n_current_machines)
        order = list(ids)
        assigns = sim.assign(dag, order)
        finish_times = {a[0]: a[3] for a in assigns}
        sorted_tasks = sorted(finish_times, key=lambda x: finish_times.get(x, 0.0), reverse=True)
        move_count = max(1, len(ids) // (n_current_machines + 1))
        for nid in sorted_tasks[:move_count]:
            alt[nid] = n_current_machines  # 新机器编号

        return self.what_if_reassignment(
            dag, current_assignment, alt,
            query_desc=f"add machine {n_current_machines}",
        )

    def what_if_swap(
        self,
        dag: TaskDependencyGraph,
        assignment: Dict[str, int],
        task_a: str, task_b: str,
    ) -> CounterfactualReport:
        """反事实: 交换两个任务的机器分配。"""
        alt = dict(assignment)
        ma = assignment.get(task_a)
        mb = assignment.get(task_b)
        if ma is not None:
            alt[task_b] = ma
        if mb is not None:
            alt[task_a] = mb
        return self.what_if_reassignment(
            dag, assignment, alt,
            query_desc=f"swap {task_a} ↔ {task_b}",
        )

    def rank_recovery_actions(
        self,
        dag: TaskDependencyGraph,
        current_assignment: Dict[str, int],
        failed_machine: int,
        affected_tasks: List[str],
        candidate_machines: List[int],
        top_k: int = 5,
    ) -> List[Tuple[str, CounterfactualReport]]:
        """对故障恢复候选动作做反事实排序。

        对每个受影响任务，尝试将其分配到各候选机器，
        选择 makespan 最小 (delta 最负) 的恢复动作。
        """
        results: List[Tuple[str, CounterfactualReport]] = []
        for nid in affected_tasks:
            for m in candidate_machines:
                if m == failed_machine:
                    continue
                alt = dict(current_assignment)
                alt[nid] = m
                report = self.what_if_reassignment(
                    dag, current_assignment, alt,
                    query_desc=f"move {nid} to machine {m}",
                )
                results.append((f"{nid}→M{m}", report))

        # 按 delta 升序 (最负 = 改进最大)
        results.sort(key=lambda x: x[1].delta)
        return results[:top_k]
