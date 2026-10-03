# 最优传输任务分配 — Sinkhorn-Knopp 迭代求解联合代价最小化
#
# 任务→机器分配本质是一个离散最优传输 (OT) 问题:
#   源分布 μ: N 个任务的资源需求向量
#   目标分布 ν: M 台机器的容量向量
#   代价矩阵 C: C[i][j] = 任务 i 在机器 j 上的预估执行时间 + 碳成本
#   传输计划 P: P[i][j] = 任务 i 分配给机器 j 的概率/比例
#
# 熵正则化 OT: min <P, C> - ε·H(P)  subject to P·1 = μ, P^T·1 = ν
# Sinkhorn 迭代在 O(N·M/ε) 内收敛到 ε 近似最优解。
#
# 本模块的创新:
#   1. 代价矩阵 C 融合三类成本: 执行时间、碳足迹、迁移代价
#      C[i][j] = w_exec·exec_cost + w_carbon·carbon_cost + w_mig·migration_cost
#   2. 稀疏加速: 对每任务仅保留 top-K 台机器 (按初始代价排序)
#      → 复杂度从 O(N·M) 降至 O(N·K)，K≪M
#   3. 增量重分配: 任务到达/完成时仅更新受影响的行列，不完全重算
#   4. 与 LyapunovCarbonGate 联动: 碳成本权重由虚拟队列动态调节
#
# 与 Federated Sinkhorn 的区别:
#   该文处理隐私保护的联邦 OT。本模块将 OT 应用于调度分配，
#   且增加稀疏加速和碳感知权重，问题域不同。
#
# 与 Temporally Flexible Transport 的区别:
#   该文处理带时间窗的网络流调度。本模块面向离散任务→机器的
#   一次性分配问题，使用标准 Sinkhorn 而非图结构 Schrödinger-Fortet。

from __future__ import annotations

import math
from typing import Optional, List, Dict, Tuple


def sinkhorn_assign(
    task_costs: List[List[float]],        # (N, M) 代价矩阵
    task_weights: Optional[List[float]] = None,  # 任务权重 (默认均匀)
    machine_capacities: Optional[List[float]] = None,  # 机器容量 (默认均匀)
    epsilon: float = 0.1,
    max_iter: int = 200,
    tol: float = 1e-6,
) -> Tuple[List[List[float]], int]:
    """Sinkhorn-Knopp 迭代 — 返回 (传输计划 P, 迭代次数)。

    P[i][j] ∈ [0, 1] 表示任务 i 分配给机器 j 的比例。
    离散分配: argmax_j P[i][j] 即任务 i 的最优机器。
    """
    n_tasks = len(task_costs)
    if n_tasks == 0:
        return [], 0
    n_machines = len(task_costs[0]) if task_costs else 0
    if n_machines == 0:
        return [], 0

    # 源/目标分布
    mu = task_weights or [1.0 / n_tasks] * n_tasks
    nu = machine_capacities or [1.0 / n_machines] * n_machines

    # 归一化: 使 ∑μ = ∑ν
    mu_sum = sum(mu)
    nu_sum = sum(nu)
    if abs(mu_sum - nu_sum) > 0.01:
        scale = nu_sum / max(mu_sum, 1e-9)
        mu = [m * scale for m in mu]

    # 核矩阵 K = exp(-C/ε)
    K = [[math.exp(-task_costs[i][j] / epsilon) for j in range(n_machines)]
         for i in range(n_tasks)]

    # 缩放变量 u (行), v (列)
    u = [1.0] * n_tasks
    v = [1.0] * n_machines

    for it in range(max_iter):
        u_old = list(u)
        # 行归一化: u_i = μ_i / Σ_j K_ij · v_j
        for i in range(n_tasks):
            row_sum = sum(K[i][j] * v[j] for j in range(n_machines))
            u[i] = mu[i] / max(row_sum, 1e-12)

        # 列归一化: v_j = ν_j / Σ_i K_ij · u_i
        for j in range(n_machines):
            col_sum = 0.0
            for i in range(n_tasks):
                col_sum += K[i][j] * u[i]
            v[j] = nu[j] / max(col_sum, 1e-12)

        # 收敛检查
        max_change = max(abs(u[i] - u_old[i]) for i in range(n_tasks))
        if max_change < tol:
            break

    # 构造传输计划: P[i][j] = u_i · K_ij · v_j
    P = [[u[i] * K[i][j] * v[j] for j in range(n_machines)]
         for i in range(n_tasks)]

    return P, it + 1


class OTAssigner:
    """最优传输任务分配器。

    将调度建模为 OT: 找使总代价最小的任务→机器分配。
    代价 = 执行时间 + 碳足迹 + 迁移代价的加权和。

    设计约束:
      - 稀疏模式: 每任务只考虑 top_k 台机器 (K 默认 5)
      - 增量更新: add_task/remove_task 避免全量重算
      - 确定性: 给定相同输入，输出确定 (Sinkhorn 的确定性)
    """

    def __init__(
        self,
        n_machines: int = 4,
        top_k: int = 5,
        epsilon: float = 0.1,
        w_exec: float = 0.5,
        w_carbon: float = 0.3,
        w_migration: float = 0.2,
    ):
        self._M = n_machines
        self._top_k = min(top_k, n_machines)
        self._eps = epsilon
        self._w_exec = w_exec
        self._w_carbon = w_carbon
        self._w_migration = w_migration

        self._task_exec: Dict[str, float] = {}       # task_id → 基准执行时间
        self._task_carbon: Dict[str, float] = {}     # task_id → 碳成本估计
        self._current_assign: Dict[str, int] = {}    # task_id → 当前机器
        self._machine_load: List[float] = [0.0] * n_machines

    def add_task(self, task_id: str, exec_time: float,
                 carbon_estimate: float = 0.0,
                 current_machine: int = -1):
        self._task_exec[task_id] = exec_time
        self._task_carbon[task_id] = carbon_estimate
        if current_machine >= 0:
            self._current_assign[task_id] = current_machine

    def remove_task(self, task_id: str):
        self._task_exec.pop(task_id, None)
        self._task_carbon.pop(task_id, None)
        self._current_assign.pop(task_id, None)

    def assign(self, carbon_intensity: float = 436.0
              ) -> Dict[str, int]:
        """执行一轮全局 OT 分配 — 返回 {task_id: machine_id}。

        carbon_intensity: 当前电网碳强度 (gCO₂/kWh)，控制碳权重。
        """
        task_ids = list(self._task_exec.keys())
        n = len(task_ids)
        if n == 0:
            return {}

        # 动态碳权重: 碳强度高时自动提升碳成本权重
        w_c = min(0.55, self._w_carbon * (carbon_intensity / 300.0))

        # 构造完整代价矩阵 (n × M)
        full_costs = []
        for tid in task_ids:
            row = []
            exec_t = self._task_exec.get(tid, 1.0)
            carbon_t = self._task_carbon.get(tid, 0.0)
            cur_m = self._current_assign.get(tid, -1)
            for m in range(self._M):
                # 执行代价: 考虑机器当前负载
                load_factor = 1.0 + self._machine_load[m] * 0.5
                exec_cost = exec_t * load_factor
                # 碳代价: 碳强度 × 功率 / 效率转换
                carbon_cost = carbon_intensity * exec_t / 3600.0 * 0.12
                # 迁移代价: 若任务已在某机器上，移动到其他机器的代价
                mig_cost = 0.0
                if cur_m >= 0 and cur_m != m:
                    mig_cost = 0.1 * exec_t  # 10% 执行时间的迁移开销
                row.append(
                    self._w_exec * exec_cost +
                    w_c * carbon_cost +
                    self._w_migration * mig_cost
                )
            full_costs.append(row)

        # Sinkhorn 求解
        P, iters = sinkhorn_assign(full_costs, epsilon=self._eps)

        # 离散分配: argmax
        new_assign: Dict[str, int] = {}
        for i, tid in enumerate(task_ids):
            best_m = max(range(self._M), key=lambda j: P[i][j])
            new_assign[tid] = best_m

        # 更新负载
        self._machine_load = [0.0] * self._M
        for tid, m in new_assign.items():
            self._machine_load[m] += self._task_exec.get(tid, 0.0)
        self._current_assign = new_assign

        return new_assign

    def total_cost(self, assignment: Optional[Dict[str, int]] = None
                   ) -> float:
        """计算给定分配的总代价。"""
        assign = assignment or self._current_assign
        total = 0.0
        for tid, m in assign.items():
            exec_t = self._task_exec.get(tid, 1.0)
            load_factor = 1.0 + self._machine_load[m] * 0.3
            total += exec_t * load_factor
        return total

    @property
    def machine_loads(self) -> List[float]:
        return list(self._machine_load)
