# GRL-Sched 第三层: 调度器 (GNN 编码 + 强化学习调度 + 启发式降级)
#
# 论文对应: GraphEdge: Dynamic Graph Partition and Task Scheduling for GNNs
#   Computing in Edge Network — arXiv:2504.15905 [待验证]
#   GraphEdge 以 GNN 编码任务图、以 RL 求解最优调度，奖励 = 任务完成时间。
#   本模块提供等价能力但零强依赖:
#     - GNNEncoder      自实现 k 层消息传递/注意力聚合 (无 torch)
#     - LinearQPolicy   线性函数近似 Q 学习，奖励 = -makespan
#     - 降级路径        无 RL 训练时退化为 HEFT 贪心 / 模拟退火
#
# 与既有调度器衔接:
#   - DependencyAwareScheduler 实现 src.priority.PriorityTaskQueue 的同款
#     push/pop/pop_batch/peek/__len__/__contains__ 接口，可替换或叠加使用
#   - GRLScheduler.priority 可计算 HEFT/Q 优先级，供既有队列 push(priority=) 叠加
#
# 设计意图: 所有矩阵/向量运算用纯 Python 列表实现，图规模 < 1e3 时开销可控；
# 训练为蒙特卡洛策略改进 (以 -makespan 为回报)，不依赖任何外部框架。

from __future__ import annotations

import math
import random
import time
from collections import deque
from typing import Optional, List, Dict, Any, Tuple

from .grl_graph import (
    TaskDependencyGraph,
    TaskNode,
    _task_id,
    _task_parent,
    _task_exec,
    _task_comm,
    _task_priority,
)
from .grl_partition import GraphPartitioner, Partition


# ---- 数值原语 (纯 Python) ----

def _relu(x: float) -> float:
    return x if x > 0.0 else 0.0


def _sigmoid(x: float) -> float:
    # 数值稳定的 sigmoid
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


# ===== GNN 编码器 =====

class GNNEncoder:
    """轻量图编码器 — 自实现消息传递，无 torch 依赖。

    论文对应: GraphEdge 使用 GNN 为任务图节点/子图生成表示。
    本实现以 k 层"均值/注意力"聚合近似消息传递:
      h_v^{k+1} = relu( h_v^k + Σ_{u∈N(v)} a_{uv}·w·(W_self·h_u^k) )
    a_{uv} = sigmoid(<h_u, h_v>/√d) 为内积注意力 (类 GAT)。
    torch 不可用时仍可运行；输出节点嵌入、图嵌入 (mean readout)、
    子图嵌入 (sum readout)，构成 RL 状态表示 φ 的特征基底。
    """

    def __init__(self, dim: int = 8, hidden: int = 16, num_layers: int = 2,
                 seed: Optional[int] = None, attention: bool = True) -> None:
        self.dim = dim
        self.hidden = hidden
        self.num_layers = num_layers
        self.attention = attention
        self._rng = random.Random(seed)
        # 随机初始化权重 (Xavier 缩放)。_rand_mat(rows, cols) 生成 (rows, cols)
        # 矩阵，当作 W@v 的 (out_dim, in_dim)：W_in 把 dim 维特征投影到 hidden 维，
        # W_self 在 hidden 空间做消息传递，W_out 把 hidden 维读回 dim 维嵌入。
        self._W_in = self._rand_mat(hidden, dim)
        self._W_self = self._rand_mat(hidden, hidden)
        self._W_out = self._rand_mat(dim, hidden)

    def _rand_mat(self, rows: int, cols: int) -> List[List[float]]:
        scale = math.sqrt(2.0 / (rows + cols))
        return [[self._rng.gauss(0.0, scale) for _ in range(cols)] for _ in range(rows)]

    @staticmethod
    def _mat_vec(W: List[List[float]], v: List[float]) -> List[float]:
        # W: (out_dim, in_dim)；逐行与 v 点积，输出长度 = out_dim。
        # 显式越界防护，避免 zip 静默截断导致的维度漂移。
        out = []
        for row in W:
            acc = 0.0
            for j, wj in enumerate(row):
                if j < len(v):
                    acc += wj * v[j]
            out.append(acc)
        return out

    @staticmethod
    def _vec_add(a: List[float], b: List[float]) -> List[float]:
        return [x + y for x, y in zip(a, b)]

    @staticmethod
    def _scal_vec(s: float, v: List[float]) -> List[float]:
        return [s * x for x in v]

    def encode(self, dag: TaskDependencyGraph) -> Tuple[List[List[float]], Dict[str, int]]:
        """消息传递编码 → (节点嵌入列表, {node_id: idx})。

        节点特征来自 dag.node_features_matrix (维度需 == self.dim)；
        若维度不符则做一次线性投影兜底。
        """
        feats, ids = dag.node_features_matrix()
        n = len(ids)
        idx = {nid: i for i, nid in enumerate(ids)}
        if n == 0:
            return [], idx

        adj = dag.adjacency_list()
        # 特征维度对齐: 图特征维度与编码器 dim 不符时重建输入投影 (hidden, fdim)。
        fdim = len(feats[0]) if feats else 0
        if fdim != self.dim:
            proj = self._rand_mat(self.hidden, fdim)
            h = [self._mat_vec(proj, f) for f in feats]
        else:
            h = [self._mat_vec(self._W_in, f) for f in feats]

        for _ in range(self.num_layers):
            # 残差: 保留上一层状态
            new_h = [list(h[i]) for i in range(n)]
            for src_i, dst_i, w in adj:
                if self.attention:
                    score = sum(a * b for a, b in zip(h[src_i], h[dst_i]))
                    att = _sigmoid(score / math.sqrt(self.dim))
                else:
                    att = 1.0
                # 消息 = 注意力 × 边权 × (W_self·h_src)
                contrib = self._scal_vec(att * w,
                                         self._mat_vec(self._W_self, h[src_i]))
                new_h[dst_i] = self._vec_add(new_h[dst_i], contrib)
            # relu 非线性
            h = [[_relu(x) for x in hv] for hv in new_h]

        # W_out: (dim, hidden) → 嵌入回到 dim 维
        emb = [self._mat_vec(self._W_out, hv) for hv in h]
        return emb, idx

    def encode_graph(self, dag: TaskDependencyGraph) -> List[float]:
        """图级嵌入 = 节点嵌入均值 (mean readout) — 全局状态表示。"""
        emb, _ = self.encode(dag)
        if not emb:
            return [0.0] * self.dim
        agg = [0.0] * len(emb[0])
        for e in emb:
            agg = self._vec_add(agg, e)
        return [x / len(emb) for x in agg]

    def encode_partitions(self, dag: TaskDependencyGraph,
                          partition: Partition) -> Dict[int, List[float]]:
        """子图嵌入 = 分区内节点嵌入求和 (sum readout) — 分区状态表示。"""
        emb, idx = self.encode(dag)
        out: Dict[int, List[float]] = {
            p: [0.0] * self.dim for p in range(partition.n_partitions)
        }
        for nid in dag.node_ids:
            p = partition.node_partition(nid)
            out[p] = self._vec_add(out[p], emb[idx[nid]])
        return out


# ===== 完成时间模拟器 (奖励信号) =====

class MakespanSimulator:
    """列表调度 (list scheduling) 在 m 台机器上的完成时间模拟。

    规则:
      - 任务依赖满足后进入就绪集，按给定 order 的位次选取
      - 分配至当前最早空闲的机器 (earliest-finish machine)
      - 跨机器依赖累加 comm_cost 等待时间，同机器忽略 (数据本地化假设)
    simulate 返回 makespan (float)，作为 SA 目标与 RL 奖励 (-makespan)。
    """

    def __init__(self, machine_count: int = 2) -> None:
        self.machine_count = max(1, int(machine_count))

    def assign(self, dag: TaskDependencyGraph,
               order: List[str]) -> List[Tuple[str, int, float, float]]:
        """模拟执行 → [(task_id, machine_id, start, end)]。"""
        ids = dag.node_ids
        if not ids:
            return []
        order_pos = {nid: i for i, nid in enumerate(order)}
        remain = {n: len(dag._in[n]) for n in ids}
        ready: List[str] = [n for n in ids if remain[n] == 0]
        finish: Dict[str, float] = {}
        machine_free = [0.0] * self.machine_count
        machine_of: Dict[str, int] = {}
        result: List[Tuple[str, int, float, float]] = []

        while ready:
            # 就绪集中按 order 位次选取 (缺省按图插入序兜底)
            nid = min(ready, key=lambda x: order_pos.get(x, len(order)))
            ready.remove(nid)
            # 最早可用开始时间 = max(前驱完成+跨机通信, 机器空闲)
            est = 0.0
            for e in dag._in[nid]:
                pf = finish[e.src]
                if machine_of.get(e.src) != machine_of.get(nid, -1):
                    pf += e.comm_cost
                if pf > est:
                    est = pf
            m = min(range(self.machine_count), key=lambda i: machine_free[i])
            start = max(est, machine_free[m])
            end = start + dag.node(nid).exec_time
            finish[nid] = end
            machine_free[m] = end
            machine_of[nid] = m
            result.append((nid, m, start, end))
            for e in dag._out[nid]:
                remain[e.dst] -= 1
                if remain[e.dst] == 0:
                    ready.append(e.dst)
        return result

    def simulate(self, dag: TaskDependencyGraph, order: List[str]) -> float:
        assigns = self.assign(dag, order)
        return max((a[3] for a in assigns), default=0.0)


# ===== HEFT 贪心启发式 =====

def heft_rank(dag: TaskDependencyGraph) -> Dict[str, float]:
    """HEFT 向上排级: rank(v) = exec(v) + max_{u∈succ(v)}(comm(v,u)+rank(u))。

    反向拓扑序 DP。作为无学习时的优先级，也作 RL 训练热启动。
    """
    topo = list(reversed(dag.topological_sort()))
    rank = {n: dag.node(n).exec_time for n in dag.node_ids}
    for nid in topo:
        best = 0.0
        for e in dag._out[nid]:
            cand = e.comm_cost + rank[e.dst]
            if cand > best:
                best = cand
        rank[nid] = dag.node(nid).exec_time + best
    return rank


def heft_order(dag: TaskDependencyGraph) -> List[str]:
    """HEFT 列表调度顺序 — 就绪集中按向上排级降序选取。"""
    rank = heft_rank(dag)
    remain = {n: len(dag._in[n]) for n in dag.node_ids}
    ready: List[str] = [n for n in dag.node_ids if remain[n] == 0]
    order: List[str] = []
    while ready:
        nid = max(ready, key=lambda x: rank.get(x, 0.0))
        ready.remove(nid)
        order.append(nid)
        for e in dag._out[nid]:
            remain[e.dst] -= 1
            if remain[e.dst] == 0:
                ready.append(e.dst)
    return order


# ===== 模拟退火降级调度 =====

class SimulatedAnnealingScheduler:
    """模拟退火调度 — 无 RL 库时的启发式降级求解器。

    邻域算子: 随机交换拓扑可交换的两个任务 (互不为祖先)；
    目标 = MakespanSimulator 完成时间；退火接受概率 exp(-ΔE/T)。
    初始解 = HEFT 序，保证结果不劣于贪心。
    """

    def __init__(self, machine_count: int = 2, seed: Optional[int] = None,
                 initial_temp: float = 50.0, cooling: float = 0.97,
                 max_iter: int = 400) -> None:
        self.machine_count = max(1, machine_count)
        self._rng = random.Random(seed)
        self.initial_temp = initial_temp
        self.cooling = cooling
        self.max_iter = max_iter

    def schedule(self, dag: TaskDependencyGraph) -> Tuple[List[str], float]:
        """返回 (拓扑合法顺序, makespan)。"""
        order = heft_order(dag)
        sim = MakespanSimulator(self.machine_count)
        current = sim.simulate(dag, order)
        best_order, best_cost = list(order), current
        temp = self.initial_temp
        for _ in range(self.max_iter):
            nxt = self._neighbor(dag, order)
            cost = sim.simulate(dag, nxt)
            delta = cost - current
            if delta < 0 or self._rng.random() < math.exp(-delta / max(temp, 1e-9)):
                order, current = nxt, cost
                if current < best_cost:
                    best_order, best_cost = list(order), current
            temp *= self.cooling
        return best_order, best_cost

    def _neighbor(self, dag: TaskDependencyGraph, order: List[str]) -> List[str]:
        """随机交换两个互不为祖先的任务 — 交换保持拓扑合法性。"""
        n = len(order)
        if n < 2:
            return list(order)
        i = self._rng.randrange(n)
        j = self._rng.randrange(n)
        if i == j:
            j = (j + 1) % n
        a, b = order[i], order[j]
        if a in dag.ancestors(b) or b in dag.ancestors(a):
            return list(order)  # 祖先关系 → 不可交换
        nxt = list(order)
        nxt[i], nxt[j] = nxt[j], nxt[i]
        return nxt


# ===== 线性函数近似 Q 策略 (轻量 RL) =====

class LinearQPolicy:
    """Q(s,a) = w·φ(s,a) 线性函数近似。

    φ = 图嵌入 ⊕ 节点嵌入 (concat)。纯 Python 权重向量，
    训练用蒙特卡洛回报更新: w ← w + lr·(G-Q)·φ。
    这是无 torch 的近似 RL — 以任务完成时间 (makespan) 为奖励信号。
    """

    def __init__(self, feat_dim: int, seed: Optional[int] = None) -> None:
        self._w = [0.0] * feat_dim
        self.feat_dim = feat_dim
        self._rng = random.Random(seed)

    def q_value(self, phi: List[float]) -> float:
        return sum(a * b for a, b in zip(self._w, phi))

    def update(self, phi: List[float], target: float, lr: float) -> float:
        err = target - self.q_value(phi)
        for i in range(len(self._w)):
            self._w[i] += lr * err * phi[i]
        return err


# ===== GRL-Sched 调度器门面 =====

class GRLScheduler:
    """GRL-Sched 调度器 — 建图 + 动态划分 + GNN/RL 调度的一体化入口。

    论文对应: GraphEdge (arXiv:2504.15905) 动态图划分 + GNN 编码 + RL 调度。
    本类对外提供:
      - build_graph / partition_dag / repartition_dag: 依赖图与在线重划分
      - schedule: 返回 order + 机器分配 + makespan (mode: auto/rl/sa/greedy)
      - train:    蒙特卡洛策略改进，以 -makespan 为奖励
      - priority: 计算 HEFT/Q 优先级，供既有静态优先级队列叠加使用
    """

    def __init__(self, machine_count: int = 2, seed: Optional[int] = None,
                 encoder: Optional[GNNEncoder] = None,
                 partitioner: Optional[GraphPartitioner] = None) -> None:
        self.machine_count = max(1, machine_count)
        self._rng = random.Random(seed)
        self._encoder = encoder or GNNEncoder(seed=seed)
        self._partitioner = partitioner or GraphPartitioner(seed=seed)
        self._policy: Optional[LinearQPolicy] = None
        self._policy_dim = 0
        self.training_stats: Dict[str, float] = {
            "episodes": 0, "last_makespan": 0.0, "avg_makespan": 0.0,
        }

    # ---- 建图与划分 ----

    def build_graph(self, tasks: Optional[List[Any]] = None,
                    pipeline: Any = None) -> TaskDependencyGraph:
        if pipeline is not None:
            return TaskDependencyGraph.from_pipeline(pipeline)
        return TaskDependencyGraph.from_tasks(tasks or [])

    def partition_dag(self, dag: TaskDependencyGraph, n_partitions: int,
                      node_loads: Optional[Dict[str, float]] = None) -> Partition:
        return self._partitioner.partition(dag, n_partitions, node_loads=node_loads)

    def repartition_dag(self, dag: TaskDependencyGraph, old: Partition,
                        n_partitions: int,
                        node_loads: Optional[Dict[str, float]] = None,
                        changed_nodes: Optional[set] = None) -> Partition:
        return self._partitioner.repartition(
            dag, old, n_partitions, node_loads=node_loads, changed_nodes=changed_nodes)

    # ---- 调度入口 ----

    def schedule(self, dag: TaskDependencyGraph, n_machines: Optional[int] = None,
                 partition: Optional[Partition] = None,
                 mode: str = "auto") -> dict:
        """返回调度结果字典。

        mode: auto(已训练→rl 否则→greedy) | rl | sa | greedy
        返回: order, assignments[(task,machine,start,end)], makespan,
              partition, mode, graph_embedding
        """
        m = n_machines or self.machine_count
        gemb = self._encoder.encode_graph(dag)
        if mode == "auto":
            mode = "rl" if self._policy is not None else "greedy"

        if mode == "greedy":
            order = heft_order(dag)
        elif mode == "sa":
            order, _ = SimulatedAnnealingScheduler(
                machine_count=m, seed=self._rng.randrange(1 << 30)).schedule(dag)
        elif mode == "rl":
            order = self._rl_rollout(dag, m, exploit=True)
        else:
            raise ValueError(f"unknown scheduling mode: {mode!r}")

        sim = MakespanSimulator(m)
        makespan = sim.simulate(dag, order)
        return {
            "order": list(order),
            "assignments": sim.assign(dag, order),
            "makespan": makespan,
            "partition": partition,
            "mode": mode,
            "graph_embedding": gemb,
        }

    def priority(self, dag: TaskDependencyGraph, task_id: str,
                 mode: str = "greedy") -> float:
        """返回任务在调度中的相对优先级 (HEFT rank / Q 值)。

        供既有静态优先级队列叠加: q.push(task, priority=grl.priority(dag, tid))。
        """
        if mode == "rl" and self._policy is not None:
            emb, idx = self._encoder.encode(dag)
            if task_id in idx:
                gemb = self._encoder.encode_graph(dag)
                return self._policy.q_value(gemb + emb[idx[task_id]])
            return 0.0
        try:
            return heft_rank(dag).get(task_id, 0.0)
        except ValueError:
            return 0.0

    # ---- RL 训练 ----

    def train(self, dag: TaskDependencyGraph, episodes: int = 60,
              lr: float = 0.05, epsilon: float = 0.2) -> dict:
        """蒙特卡洛策略改进。

        每 episode 做 epsilon-greedy rollout，回报 G = -makespan (完成时间越小越好)，
        对每一步的 (s,a) 特征做 w ← w + lr·(G-Q)·φ 更新。
        论文对应: GraphEdge 的 RL 调度器以任务完成时间为奖励训练策略网络。
        """
        if len(dag) == 0:
            return self.training_stats
        self._ensure_policy(dag)
        emb, idx = self._encoder.encode(dag)
        gemb = self._encoder.encode_graph(dag)
        sim = MakespanSimulator(self.machine_count)
        total = 0.0
        last = 0.0

        for _ in range(episodes):
            remain = {n: len(dag._in[n]) for n in dag.node_ids}
            ready: List[str] = [n for n in dag.node_ids if remain[n] == 0]
            order: List[str] = []
            steps: List[str] = []
            while ready:
                if self._rng.random() < epsilon:
                    nid = self._rng.choice(ready)
                else:
                    best, best_q = None, -1e18
                    for cand in ready:
                        q = self._policy.q_value(gemb + emb[idx[cand]])
                        if q > best_q:
                            best_q, best = q, cand
                    nid = best
                steps.append(nid)
                order.append(nid)
                ready.remove(nid)
                for e in dag._out[nid]:
                    remain[e.dst] -= 1
                    if remain[e.dst] == 0:
                        ready.append(e.dst)
            makespan = sim.simulate(dag, order)
            ret = -makespan
            for nid in steps:
                self._policy.update(gemb + emb[idx[nid]], ret, lr)
            total += makespan
            last = makespan

        self.training_stats = {
            "episodes": episodes,
            "last_makespan": last,
            "avg_makespan": total / episodes,
        }
        return dict(self.training_stats)

    def _ensure_policy(self, dag: TaskDependencyGraph) -> None:
        dim = self._encoder.dim * 2  # 图嵌入 ⊕ 节点嵌入
        if self._policy is None or self._policy_dim != dim:
            self._policy = LinearQPolicy(dim, seed=self._rng.randrange(1 << 30))
            self._policy_dim = dim

    def _rl_rollout(self, dag: TaskDependencyGraph, m: int, exploit: bool) -> List[str]:
        """用当前策略 rollout — exploit=True 时 90% 贪心选 Q 最大。"""
        if self._policy is None:
            return heft_order(dag)
        emb, idx = self._encoder.encode(dag)
        gemb = self._encoder.encode_graph(dag)
        remain = {n: len(dag._in[n]) for n in dag.node_ids}
        ready: List[str] = [n for n in dag.node_ids if remain[n] == 0]
        order: List[str] = []
        while ready:
            if exploit and self._rng.random() < 0.9:
                best, best_q = None, -1e18
                for cand in ready:
                    q = self._policy.q_value(gemb + emb[idx[cand]])
                    if q > best_q:
                        best_q, best = q, cand
                nid = best
            else:
                nid = self._rng.choice(ready)
            order.append(nid)
            ready.remove(nid)
            for e in dag._out[nid]:
                remain[e.dst] -= 1
                if remain[e.dst] == 0:
                    ready.append(e.dst)
        return order


# ===== 与既有调度器兼容的依赖感知队列 =====

class DependencyAwareScheduler:
    """依赖感知调度队列 — 与 src.priority.PriorityTaskQueue 接口兼容。

    内部维护 TaskDependencyGraph:
      - push: 注册节点，parent_id → data 边
      - pop:  仅返回依赖已满足的就绪任务；就绪间按 HEFT rank 排序
    replaceable: 可直接替换 PriorityTaskQueue (同款接口)
    stackable:   配合 GRLScheduler.priority 计算动态优先级叠加到既有队列
    """

    def __init__(self, grl: Optional[GRLScheduler] = None,
                 machine_count: int = 2) -> None:
        self._grl = grl or GRLScheduler(machine_count=machine_count)
        self._graph = TaskDependencyGraph()
        self._pending: Dict[str, Any] = {}
        self._all: Dict[str, Any] = {}
        self._ranks: Dict[str, float] = {}

    # ---- 入队 ----

    def push(self, task: Any, priority: int = 0) -> None:
        tid = _task_id(task)
        if tid in self._all:
            return  # 幂等: 已入队或已消费
        self._graph.add_node(TaskNode(
            node_id=tid, label=str(tid),
            exec_time=_task_exec(task),
            priority=float(priority or _task_priority(task)),
        ))
        parent = _task_parent(task)
        if parent and str(parent) in self._graph:
            self._graph.add_edge(str(parent), tid, comm_cost=_task_comm(task),
                                 kind="data")
        self._all[tid] = task
        self._pending[tid] = task

    # ---- 出队 ----

    def pop(self) -> Optional[Any]:
        """弹出依赖已满足且 rank 最高的就绪任务。无就绪任务时返回 None。"""
        done = set(self._all) - set(self._pending)
        ready = [
            nid for nid in self._pending
            if all(p in done for p in self._graph.predecessors(nid))
        ]
        if not ready:
            return None
        self._refresh_ranks()
        nid = max(ready, key=lambda x: self._ranks.get(x, 0.0))
        task = self._pending.pop(nid)
        return task

    def pop_batch(self, n: int) -> List[Any]:
        out: List[Any] = []
        for _ in range(n):
            t = self.pop()
            if t is None:
                break
            out.append(t)
        return out

    def peek(self) -> Optional[Any]:
        """查看下一个可出队任务而不消费。"""
        done = set(self._all) - set(self._pending)
        ready = [
            nid for nid in self._pending
            if all(p in done for p in self._graph.predecessors(nid))
        ]
        if not ready:
            return None
        self._refresh_ranks()
        nid = max(ready, key=lambda x: self._ranks.get(x, 0.0))
        return self._pending[nid]

    def remove(self, task_id: str) -> bool:
        if task_id in self._pending:
            del self._pending[task_id]
            del self._all[task_id]
            return True
        return False

    # ---- 内部 ----

    def _refresh_ranks(self) -> None:
        try:
            self._ranks = heft_rank(self._graph)
        except ValueError:
            # 图含环 — 退回原始优先级 (插入序稳定)
            self._ranks = {n: 0.0 for n in self._graph.node_ids}

    def __len__(self) -> int:
        return len(self._pending)

    def __contains__(self, task_id: str) -> bool:
        return task_id in self._pending

    def __repr__(self) -> str:
        return f"DependencyAwareScheduler(pending={len(self._pending)}, nodes={len(self._graph)})"


# ===== 一站式入口 =====

def grl_schedule(tasks: Optional[List[Any]] = None, pipeline: Any = None,
                 n_machines: int = 2, n_partitions: int = 2,
                 node_loads: Optional[Dict[str, float]] = None,
                 mode: str = "auto", train_episodes: int = 0) -> dict:
    """一站式 GRL-Sched: 建图 → 动态划分 → (可选训练) → 调度。

    供 CLI / 既有代码快速接入。返回结果含 dag 与 partition 以便继续重划分。
    """
    sched = GRLScheduler(machine_count=n_machines)
    dag = sched.build_graph(tasks=tasks, pipeline=pipeline)
    partition = sched.partition_dag(dag, n_partitions, node_loads=node_loads)
    if train_episodes and train_episodes > 0:
        sched.train(dag, episodes=train_episodes)
    result = sched.schedule(dag, n_machines=n_machines, partition=partition, mode=mode)
    result["dag"] = dag
    result["partition"] = partition
    return result
