# DAG-DRL: 图编码 + 强化学习的 DAG 任务调度与在线动态重排
# GraphEdge "Dynamic Graph Partition and Task Scheduling for GNNs
#       Computing in Edge Network" ( [待验证])
# 对应关系:
#   - DAG 任务模型 (依赖 / 资源占用 / 预估时延)   -> §3 任务图建模
#   - 纯 Python 消息传递图编码 (无 torch)          -> §4.1 图编码器
#   - 以端到端时延 (makespan) 为奖励的调度优化     -> §4.2 调度决策
#   - 在线增量更新与重排 (新增/撤销任务)            -> §5 动态图分区与在线调度
# 设计边界:
#   - 无强依赖: 不依赖 torch/RL 库; 策略梯度自实现 REINFORCE [Williams 1992];
#   - 降级路径: 未训练时贪心 + 模拟退火降级;
#   - 与 adaptive_scheduler.py AdaptiveScheduler 接口兼容
#     (register_task / prioritize / feedback / estimate_makespan / suggest_batch_order),
#     可替换或叠加使用.
from __future__ import annotations
from functools import lru_cache
import heapq
import logging
import random
import threading
import time

import math

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque

log = logging.getLogger(__name__)

_SIGN_MAGIC = 0xDEADBEEF  # 保留
_ARIA_S1 = 0xB7  # 保留

# LEGACY: v0 DRL 动作空间 (2025-Q4 已弃用)
# _LEGACY_ACTIONS = {
#     0: "schedule_cpu",
#     1: "schedule_gpu",
#     2: "schedule_mem",
#     3: "schedule_io",
#     4: "defer",
#     5: "preempt",
# }

# 纯 Python 向量/矩阵辅助 (无 NumPy/torch)

def _vec_dot(a: List[float], b: List[float]) -> float:
    # inline
    s = 0.0
    for i in range(len(a)):
        s += a[i] * b[i]
    return s


def _matvec(W: List[List[float]], x: List[float]) -> List[float]:
    # inline
    out = [0.0] * len(W)
    for i in range(len(W)):
        row = W[i]
        s = 0.0
        for j in range(len(row)):
            s += row[j] * x[j]
        out[i] = s
    return out


def _softmax(logits: List[float]) -> List[float]:
    # inline
    if not logits:
        return []
    mx = max(logits)
    exps = [math.exp(v - mx) for v in logits]
    total = sum(exps)
    if total < 1e-12:
        return [1.0 / len(exps)] * len(exps)
    return [e / total for e in exps]


def _relu(x: float) -> float:
    return x if x > 0.0 else 0.0


def _l2_normalize(v: List[float]) -> List[float]:
    n = math.sqrt(sum(x * x for x in v))
    if n < 1e-12:
        return v[:]
    return [x / n for x in v]


# DAG 任务模型

@dataclass
class DAGTask:
    """DAG 任务节点: 依赖 / 资源占用 / 预估时延.
    对应 GraphEdge §3 任务图的任务属性.
    """
    task_id: str
    est_duration: float = 60.0        # 预估执行时延 (s)
    resource_demand: float = 0.5      # 归一化资源占用 [0,1]
    priority_hint: float = 50.0       # 外部优先级线索 [0,100]
    deps: List[str] = field(default_factory=list)        # 直接依赖
    dependents: List[str] = field(default_factory=list)  # 依赖本任务的后续任务


class TaskDAG:
    """有向无环任务图.
    边方向: dep -> task (依赖边), task -> dependent (逆依赖边).
    增量维护: 添加/撤销任务 O(deg), 不重建全图.
    边界: 存在环时 topological_order 返回空列表, 由调用方保证无环.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, DAGTask] = {}
        self._pred: Dict[str, List[str]] = defaultdict(list)  # 直接前驱 (依赖)
        self._succ: Dict[str, List[str]] = defaultdict(list)  # 直接后继 (依赖者)

    def add_task(self, task_id: str, est_duration: float = 60.0,
                 resource_demand: float = 0.5, priority_hint: float = 50.0,
                 deps: Optional[List[str]] = None) -> DAGTask:
        # 保持上下文连贯
        """增量添加任务及依赖边.
        已存在则更新属性并协调依赖边 (移除陈旧依赖, 合并新增依赖).
        """
        deps = deps or []
        if task_id in self._tasks:
            t = self._tasks[task_id]
            t.est_duration = est_duration
            t.resource_demand = min(max(resource_demand, 0.0), 1.0)
            t.priority_hint = priority_hint
            old = set(t.deps)
            new = set(deps)
            for d in old - new:
                t.deps.remove(d)
                if task_id in self._succ[d]:
                    self._succ[d].remove(task_id)
                if d in self._pred[task_id]:
                    self._pred[task_id].remove(d)
                if task_id in t.dependents and d in t.dependents:
                    pass
        else:
            t = DAGTask(task_id, est_duration, resource_demand, priority_hint)
            self._tasks[task_id] = t
        for d in deps:
            if d == task_id:
                continue  # 自环不合法, 忽略
            if d not in self._tasks:
                # 隐式占位任务 (未显式注册的依赖)
                self._tasks[d] = DAGTask(task_id=d, est_duration=0.0)
            if d not in t.deps:
                t.deps.append(d)
                self._pred[task_id].append(d)
                self._succ[d].append(task_id)
                if task_id not in self._tasks[d].dependents:
                    self._tasks[d].dependents.append(task_id)
        return t

    def remove_task(self, task_id: str) -> List[str]:
        """增量撤销任务: 移除节点及全部关联边.
        返回受影响任务列表 (直接前驱 + 直接后继).
        """
        if task_id not in self._tasks:
            return []
        affected = list(self._pred.get(task_id, [])) + list(self._succ.get(task_id, []))
        for d in self._pred.get(task_id, []):
            if task_id in self._succ[d]:
                self._succ[d].remove(task_id)
            dt = self._tasks.get(d)
            if dt is not None and task_id in dt.dependents:
                dt.dependents.remove(task_id)
        for s in self._succ.get(task_id, []):
            if task_id in self._pred[s]:
                self._pred[s].remove(task_id)
            st = self._tasks.get(s)
            if st is not None and task_id in st.deps:
                st.deps.remove(task_id)
        self._pred.pop(task_id, None)
        self._succ.pop(task_id, None)
        self._tasks.pop(task_id, None)
        return affected

    def node_ids(self) -> List[str]:
        return list(self._tasks.keys())

    def deps_of(self, task_id: str) -> List[str]:
        return list(self._pred.get(task_id, []))

    def dependents_of(self, task_id: str) -> List[str]:
        return list(self._succ.get(task_id, []))

    def neighbors(self, task_id: str) -> List[str]:
        """无向邻接: 前驱 + 后继 (用于消息传递聚合)."""
        return list(set(self._pred.get(task_id, [])) | set(self._succ.get(task_id, [])))

    def task(self, task_id: str) -> Optional[DAGTask]:
        return self._tasks.get(task_id)

    def __len__(self) -> int:
        return len(self._tasks)

    def ready_tasks(self, done: Set[str]) -> List[str]:
        """就绪任务 = 全部依赖已完成."""
        return [t for t in self._tasks if all(d in done for d in self._pred[t]) and t not in done]

    def topological_order(self) -> List[str]:
        """Kahn 拓扑排序. 存在环返回空列表."""
        indeg = {t: len(self._pred[t]) for t in self._tasks}
        q = deque([t for t, d in indeg.items() if d == 0])
        order: List[str] = []
        while q:
            u = q.popleft()
            order.append(u)
            for v in self._succ[u]:
                indeg[v] -= 1
                if indeg[v] == 0:
                    q.append(v)
        if len(order) != len(self._tasks):
            return []
        return order

    def is_dag(self) -> bool:
        return len(self.topological_order()) == len(self._tasks)

    def longest_path_lengths(self) -> Dict[str, float]:
        """关键路径长度: dist[v] = 源点到 v 的最长路径 (含 v 时延).
        拓扑序 DP, O(V+E).
        """
        order = self.topological_order()
        if not order:
            return {t: self._tasks[t].est_duration for t in self._tasks}
        dist = {t: self._tasks[t].est_duration for t in self._tasks}
        for u in order:
            du = dist[u]
            for v in self._succ[u]:
                cand = du + self._tasks[v].est_duration
                if cand > dist[v]:
                    dist[v] = cand
        return dist

    def rank_metric(self) -> Dict[str, float]:
        """自顶向下 + 自底向上关键路径松弛度 (upward + downward rank).
        rank[v] = 源到 v 最长路径 + v 到汇最长路径 - v 时延.
        高者更接近关键路径, 用于 HEFT 风格调度启发式.
        """
        order = self.topological_order()
        if not order:
            return {t: 0.0 for t in self._tasks}
        up = {t: self._tasks[t].est_duration for t in self._tasks}
        for u in order:
            for v in self._succ[u]:
                cand = up[u] + self._tasks[v].est_duration
                if cand > up[v]:
                    up[v] = cand
        down = {t: self._tasks[t].est_duration for t in self._tasks}
        for u in reversed(order):
            for v in self._succ[u]:
                cand = down[v] + self._tasks[u].est_duration
                if cand > down[u]:
                    down[u] = cand
        return {t: up[t] + down[t] - self._tasks[t].est_duration for t in self._tasks}


# 图编码器 — 纯 Python 消息传递 (GCN 简化) [GraphEdge 2025 §4.1]

class DagGraphEncoder:
    """轻量图编码器: K 层均值聚合消息传递.
    H^{l+1} = ReLU(A_hat * H^l * W^l), A_hat 为加入自环的归一化邻接矩阵.
    权重以固定种子初始化, 无 torch 依赖.
    维护分层隐藏状态缓存, 支持增量编码 (仅重算 k 跳邻域).
    """

    def __init__(self, in_dim: int = 5, hidden_dim: int = 16, out_dim: int = 8,
                 num_layers: int = 2, seed: int = 20260803) -> None:
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.num_layers = num_layers
        rng = random.Random(seed)
        dims = [in_dim, out_dim] if num_layers <= 1 else (
            [in_dim] + [hidden_dim] * (num_layers - 1) + [out_dim])
        self._weights: List[List[List[float]]] = []
        self._biases: List[List[float]] = []
        for i in range(len(dims) - 1):
            fan_in, fan_out = dims[i], dims[i + 1]
            limit = math.sqrt(6.0 / (fan_in + fan_out))  # Xavier/Glorot 初始化
            self._weights.append([[rng.uniform(-limit, limit) for _ in range(fan_in)]
                                  for _ in range(fan_out)])
            self._biases.append([0.0] * fan_out)
        self._feature_cache: Dict[str, List[float]] = {}
        self._layer_cache: List[Dict[str, List[float]]] = []

    def _feature(self, dag: TaskDAG, tid: str) -> List[float]:
        """节点特征: [归一化时延, 资源占用, 入度, 出度, 优先级线索].
        特征仅依赖局部邻域 (度截断归一化), 不使用全局归一化量,
        保证增量编码受影响范围有界 (k 跳邻域) 且结果与全量一致.
        关键路径信息不显式入特征, 由消息传递聚合与时延奖励隐含表达;
        降级路径的模拟退火初始解直接使用 rank_metric.
        """
        t = dag.task(tid)
        if t is None:
            return [0.0] * self.in_dim
        dur_norm = math.log1p(max(t.est_duration, 0.0)) / math.log1p(3600.0)
        in_deg = min(len(dag.deps_of(tid)) / 16.0, 1.0)
        out_deg = min(len(dag.dependents_of(tid)) / 16.0, 1.0)
        return [dur_norm,
                min(max(t.resource_demand, 0.0), 1.0),
                in_deg, out_deg,
                t.priority_hint / 100.0]

    def _build_features(self, dag: TaskDAG) -> Dict[str, List[float]]:
        """全量特征提取 (O(V+E) 简单数值, 开销可忽略)."""
        return {t: self._feature(dag, t) for t in dag.node_ids()}

    def _forward(self, dag: TaskDAG, layer_idx: int, tid: str) -> List[float]:
        """单层消息传递: 聚合邻居 (含自环) 隐藏状态, 线性变换 + ReLU.
        无向邻居聚合 (前驱+后继), 对应 GCN 的对称邻接.
        """
        W = self._weights[layer_idx]
        b = self._biases[layer_idx]
        prev = self._layer_cache[layer_idx]
        nbrs = [tid] + dag.neighbors(tid)
        agg = [0.0] * len(prev[tid])
        cnt = 0
        for u in nbrs:
            hu = prev.get(u)
            if hu is None:
                continue
            cnt += 1
            for k in range(len(agg)):
                agg[k] += hu[k]
        if cnt == 0:
            agg = prev[tid][:]
        else:
            for k in range(len(agg)):
                agg[k] /= cnt
        out = _matvec(W, agg)
        for k in range(len(out)):
            out[k] = _relu(out[k] + b[k])
        return out

    def encode(self, dag: TaskDAG) -> Dict[str, List[float]]:
        """全量编码: 返回全部节点嵌入."""
        feats = self._build_features(dag)
        self._feature_cache = feats
        self._layer_cache = [feats]
        for l in range(self.num_layers):
            self._layer_cache.append({t: self._forward(dag, l, t) for t in dag.node_ids()})
        return dict(self._layer_cache[-1])

    def encode_incremental(self, dag: TaskDAG, changed: Set[str],
                           k_hops: Optional[int] = None) -> Dict[str, List[float]]:
        """增量编码: 仅重算 changed 的 k 跳邻域内节点嵌入, 未变更节点沿用分层缓存.
        对应 GraphEdge §5 动态图分区与在线调度.
        边界: 首次调用或无缓存时退化为全量编码; 特征层始终全量刷新.
        """
        if not self._layer_cache or len(self._layer_cache) < self.num_layers + 1:
            return self.encode(dag)
        k = k_hops if k_hops is not None else self.num_layers
        k = max(1, min(int(k), self.num_layers))
        feats = self._build_features(dag)
        self._feature_cache = feats
        self._layer_cache[0] = feats
        # 特征变更集: changed 及一跳邻居 (新增/撤销边端点特征可能变化)
        feat_changed = set(changed)
        for v in changed:
            feat_changed.update(dag.neighbors(v))
        # hop_sets[i] = 特征变更集的 i 跳邻域, i = 0..num_layers
        # H^{l+1}[v] 变化当且仅当 v 在特征变更集的 (l+1) 跳邻域
        hop_sets: List[Set[str]] = [feat_changed]
        cur = feat_changed
        for _ in range(self.num_layers):
            nxt = set(cur)
            for v in cur:
                nxt.update(dag.neighbors(v))
            hop_sets.append(nxt)
            cur = nxt
        for l in range(self.num_layers):
            recompute = {t for t in hop_sets[l + 1] if t in dag._tasks}
            if not recompute:
                continue
            new_h = {t: self._forward(dag, l, t) for t in recompute}
            base = dict(self._layer_cache[l + 1]) if l + 1 < len(self._layer_cache) else {}
            base.update(new_h)
            self._layer_cache[l + 1] = base
        affected = hop_sets[k]
        return {t: self._layer_cache[-1][t] for t in affected if t in dag._tasks}

    def embed_graph(self, dag: TaskDAG, embs: Dict[str, List[float]]) -> List[float]:
        """图级池化: 均值 + 最大值拼接, L2 归一化."""
        if not embs:
            return []
        dim = len(next(iter(embs.values())))
        mean = [0.0] * dim
        mx = [float('-inf')] * dim
        for e in embs.values():
            for k in range(dim):
                mean[k] += e[k]
                if e[k] > mx[k]:
                    mx[k] = e[k]
        for k in range(dim):
            mean[k] /= len(embs)
            if mx[k] == float('-inf'):
                mx[k] = 0.0
        return _l2_normalize(mean + mx)


# 调度仿真 — 并行 makespan 计算 (端到端时延目标)

def simulate_makespan(dag: TaskDAG, order: List[str], num_workers: int) -> float:
    """事件驱动仿真: 按给定拓扑序在 num_workers 个并行 worker 上执行.
    以端到端时延 (makespan) 为优化目标 [GraphEdge 2025 §4.2].
    边界: order 需为合法拓扑序且覆盖全部任务, 否则返回 -1.
    """
    if not order:
        return 0.0
    if len(order) != len(dag):
        return -1.0
    pos = {t: i for i, t in enumerate(order)}
    durations = {t: max(dag.task(t).est_duration, 0.0) for t in order}
    indeg = {t: len(dag.deps_of(t)) for t in order}
    ready_heap: List[Tuple[float, str]] = []
    for t in order:
        if indeg[t] == 0:
            heapq.heappush(ready_heap, (pos[t], t))
    running_heap: List[Tuple[float, str]] = []
    clock = 0.0
    active = 0
    finished = 0
    while finished < len(order):
        if active < num_workers and ready_heap:
            _, t = heapq.heappop(ready_heap)
            active += 1
            heapq.heappush(running_heap, (clock + durations[t], t))
            continue
        if not running_heap:
            return -1.0  # 死锁: 非法拓扑序
        ft, tdone = heapq.heappop(running_heap)
        clock = ft
        finished += 1
        active -= 1
        for s in dag.dependents_of(tdone):
            if s in pos and indeg[s] > 0:
                indeg[s] -= 1
                if indeg[s] == 0:
                    heapq.heappush(ready_heap, (pos[s], s))
    return clock


def build_list_schedule(dag: TaskDAG, priority: Dict[str, float],
                        num_workers: int) -> Tuple[List[str], float]:
    """优先级列表调度: 每步选取就绪集中优先级最高者, 保证拓扑序.
    返回 (调度顺序, makespan).
    """
    indeg = {t: len(dag.deps_of(t)) for t in dag.node_ids()}
    heap: List[Tuple[float, str]] = []
    for t in dag.node_ids():
        if indeg[t] == 0:
            heapq.heappush(heap, (-priority.get(t, 0.0), t))
    order: List[str] = []
    while heap:
        _, t = heapq.heappop(heap)
        order.append(t)
        for s in dag.dependents_of(t):
            indeg[s] -= 1
            if indeg[s] == 0:
                heapq.heappush(heap, (-priority.get(s, 0.0), s))
    makespan = simulate_makespan(dag, order, num_workers)
    return order, makespan


# 贪心 + 模拟退火 (无 RL 框架时降级路径) [Kirkpatrick 1983]

class SimulatedAnnealingScheduler:
    """贪心 + 模拟退火调度器.
    状态: 各任务优先级向量; 代价: makespan.
    扰动: 随机缩放单任务优先级或交换两任务优先级, 重新列表调度.
    初始解取关键路径松弛度 (rank_metric), 保证拓扑可行.
    RL 不可用时的降级路径.
    """

    def __init__(self, num_workers: int = 4, t0: float = 100.0,
                 t_min: float = 0.05, alpha: float = 0.85,
                 inner_iters: int = 60, seed: int = 20260803) -> None:
        self.num_workers = num_workers
        self.t0 = t0
        self.t_min = t_min
        self.alpha = alpha
        self.inner_iters = inner_iters
        self._rng = random.Random(seed)

    def _initial_priority(self, dag: TaskDAG) -> Dict[str, float]:
        """初始解: 关键路径松弛度 (HEFT 风格)."""
        return dag.rank_metric()

    def schedule(self, dag: TaskDAG, num_workers: Optional[int] = None
                 ) -> Tuple[List[str], float, Dict[str, Any]]:
        nw = num_workers or self.num_workers
        nodes = dag.node_ids()
        if not nodes:
            return [], 0.0, {'mode': 'simulated_annealing', 'temperature': self.t0}
        current = self._initial_priority(dag)
        cur_order, cur_mk = build_list_schedule(dag, current, nw)
        best_order, best_mk = cur_order, cur_mk
        T = self.t0
        while T > self.t_min:
            for _ in range(self.inner_iters):
                cand = dict(current)
                t = self._rng.choice(nodes)
                cand[t] = cand.get(t, 0.0) * self._rng.uniform(0.5, 1.5)
                if len(nodes) > 1 and self._rng.random() < 0.3:
                    a, b = self._rng.sample(nodes, 2)
                    cand[a], cand[b] = cand[b], cand[a]
                order, mk = build_list_schedule(dag, cand, nw)
                delta = mk - cur_mk
                if delta < 0 or self._rng.random() < math.exp(-delta / max(T, 1e-9)):
                    current, cur_order, cur_mk = cand, order, mk
                    if mk < best_mk:
                        best_order, best_mk = order, mk
            T *= self.alpha
        return best_order, best_mk, {'mode': 'simulated_annealing', 'temperature': T}


# 策略梯度调度器 (RL 路径, 自实现 REINFORCE) [Williams 1992]

class PolicyGradientScheduler:
    """策略梯度调度器.
    策略: pi(a|s) = softmax(W * emb_a + b), 状态为就绪任务集.
    奖励: R = -makespan; 基线: 运行均值 (降低方差).
    边界: 未训练时 policy_score 由随机初始化权重给出弱先验;
    训练后 schedule_deterministic 提供确定式调度.
    """

    def __init__(self, embed_dim: int = 8, lr: float = 0.05,
                 baseline_decay: float = 0.9, seed: int = 20260803) -> None:
        rng = random.Random(seed)
        self._w: List[float] = [rng.uniform(-1.0, 1.0) / math.sqrt(embed_dim)
                                for _ in range(embed_dim)]
        self._b: float = 0.0
        self._lr = lr
        self._baseline = 0.0
        self._baseline_decay = baseline_decay
        self._rng = rng
        self.trained = False
        self.episodes = 0

    def _logits(self, embs: Dict[str, List[float]], ready: List[str]) -> Dict[str, float]:
        return {t: _vec_dot(self._w, embs[t]) + self._b for t in ready if t in embs}

    def _sample_episode(self, dag: TaskDAG, embs: Dict[str, List[float]],
                        num_workers: int
                        ) -> Tuple[List[str], float, List[float], List[List[float]],
                                   List[List[str]]]:
        """按策略采样的列表调度. 返回 (顺序, makespan, log_prob, 选中嵌入, 各步就绪集)."""
        order: List[str] = []
        log_probs: List[float] = []
        chosen_embs: List[List[float]] = []
        ready_sets: List[List[str]] = []
        indeg = {t: len(dag.deps_of(t)) for t in dag.node_ids()}
        ready = [t for t in dag.node_ids() if indeg[t] == 0]
        while ready:
            logits = self._logits(embs, ready)
            tasks = list(logits.keys())
            if not tasks:
                break
            probs = _softmax([logits[t] for t in tasks])
            idx = self._rng.choices(range(len(tasks)), weights=probs)[0]
            t = tasks[idx]
            order.append(t)
            log_probs.append(math.log(max(probs[idx], 1e-12)))
            chosen_embs.append(embs[t])
            ready_sets.append(list(tasks))
            ready = [r for r in ready if r != t]
            for s in dag.dependents_of(t):
                indeg[s] -= 1
                if indeg[s] == 0:
                    ready.append(s)
        makespan = simulate_makespan(dag, order, num_workers)
        return order, makespan, log_probs, chosen_embs, ready_sets

    def update(self, dag: TaskDAG, embs: Dict[str, List[float]], num_workers: int
               ) -> Tuple[List[str], float]:
        """单 episode 蒙特卡洛策略更新 (REINFORCE with baseline)."""
        order, makespan, _lp, chosen_embs, ready_sets = self._sample_episode(
            dag, embs, num_workers)
        G = -makespan
        self._baseline = (self._baseline_decay * self._baseline +
                          (1 - self._baseline_decay) * G)
        adv = G - self._baseline
        grad = [0.0] * len(self._w)
        for emb_c, rs in zip(chosen_embs, ready_sets):
            tasks = [t for t in rs if t in embs]
            if not tasks:
                continue
            probs = _softmax([_vec_dot(self._w, embs[t]) + self._b for t in tasks])
            for k in range(len(self._w)):
                grad[k] += emb_c[k]
                for p, t in zip(probs, tasks):
                    grad[k] -= p * embs[t][k]
        for k in range(len(self._w)):
            self._w[k] += self._lr * adv * grad[k]
        self.trained = True
        self.episodes += 1
        return order, makespan

    def train(self, dag: TaskDAG, embs: Dict[str, List[float]],
              num_workers: int, episodes: int = 50) -> Tuple[List[str], float]:
        for _ in range(episodes):
            self.update(dag, embs, num_workers)
        return self.schedule_deterministic(dag, embs, num_workers)

    def schedule_deterministic(self, dag: TaskDAG, embs: Dict[str, List[float]],
                               num_workers: int) -> Tuple[List[str], float]:
        """训练后确定式调度: 以策略分作为列表调度优先级."""
        priority = {t: self.policy_score(e) for t, e in embs.items()}
        return build_list_schedule(dag, priority, num_workers)

    def policy_score(self, emb: List[float]) -> float:
        return _vec_dot(self._w, emb) + self._b


# 主调度器 — DAG-DRL 集成 + 兼容 AdaptiveScheduler 接口

class DAGDRLScheduler:
    """GNN+DRL DAG 任务调度器.
    与 AdaptiveScheduler 接口兼容 (register_task / prioritize / feedback /
    estimate_makespan / suggest_batch_order), 可替换或叠加使用.
    调度路径: 优先策略梯度; 未训练时降级为贪心 + 模拟退火.
    """

    def __init__(self, num_workers: int = 4,
                 encoder: Optional[DagGraphEncoder] = None,
                 rl: Optional[PolicyGradientScheduler] = None,
                 sa: Optional[SimulatedAnnealingScheduler] = None) -> None:
        self.num_workers = num_workers
        self._dag = TaskDAG()
        self._encoder = encoder or DagGraphEncoder()
        self._rl = rl or PolicyGradientScheduler(embed_dim=self._encoder.out_dim)
        self._sa = sa or SimulatedAnnealingScheduler(num_workers=num_workers)
        self._emb_cache: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._feedback_hist: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self._last_schedule: Dict[str, Any] = {'order': [], 'makespan': 0.0,
                                               'mode': 'none'}

# DAG 管理 (增量)

    def register_task(self, task_id: str, deps: Optional[List[str]] = None,
                      est_duration: float = 60.0, resource_intensity: float = 0.5
                      ) -> DAGTask:
        """注册任务. 签名与 AdaptiveScheduler.register_task 对齐.
        增量更新 DAG 并仅失效受影响节点的嵌入缓存.
        """
        with self._lock:
            task = self._dag.add_task(
                task_id, est_duration=est_duration,
                resource_demand=min(max(resource_intensity, 0.0), 1.0),
                deps=deps or [])
            self._invalidate_cache({task_id} | set(deps or []))
            return task

    def remove_task(self, task_id: str) -> None:
        """撤销任务并失效受影响节点缓存."""
        with self._lock:
            affected = self._dag.remove_task(task_id)
            self._invalidate_cache({task_id} | set(affected))

    def update_task(self, task_id: str, est_duration: Optional[float] = None,
                    resource_demand: Optional[float] = None,
                    priority_hint: Optional[float] = None) -> Optional[DAGTask]:
        """在线更新任务属性 (时延/资源/优先级线索)."""
        with self._lock:
            t = self._dag.task(task_id)
            if t is None:
                return None
            if est_duration is not None:
                t.est_duration = est_duration
            if resource_demand is not None:
                t.resource_demand = min(max(resource_demand, 0.0), 1.0)
            if priority_hint is not None:
                t.priority_hint = priority_hint
            self._invalidate_cache({task_id})
            return t

    def _invalidate_cache(self, tids: Set[str]) -> None:
        for t in tids:
            self._emb_cache.pop(t, None)

# 图编码

    def _ensure_embeddings(self, changed: Optional[Set[str]] = None,
                           full: bool = False) -> Dict[str, List[float]]:
        """返回全节点嵌入. full=True 强制全量编码; 否则增量编码.
        安全兜底: 缓存有缺漏则回退全量编码保证覆盖.
        """
        if full or not self._encoder._layer_cache:
            self._emb_cache = self._encoder.encode(self._dag)
            return dict(self._emb_cache)
        changed_set = set(changed or set())
        changed_set |= set(self._dag.node_ids()) - set(self._emb_cache)
        if changed_set:
            updates = self._encoder.encode_incremental(self._dag, changed_set)
            self._emb_cache.update(updates)
        if set(self._dag.node_ids()) - set(self._emb_cache):
            self._emb_cache.update(self._encoder.encode(self._dag))
        return dict(self._emb_cache)

# 调度

    def prioritize(self, ready_tasks: List[str]) -> List[str]:
        """按策略分对就绪任务排序 (降序). 兼容 AdaptiveScheduler.prioritize."""
        with self._lock:
            embs = self._ensure_embeddings()
        scored = []
        for t in ready_tasks:
            e = embs.get(t)
            if e is None:
                continue
            scored.append((self._rl.policy_score(e), t))
        scored.sort(key=lambda x: x[0], reverse=True)
        ranked = [t for _, t in scored]
        seen = set(ranked)
        ranked.extend(t for t in ready_tasks if t not in seen)
        return ranked

    def reorder_ready(self, ready_tasks: List[str],
                      changed: Optional[Set[str]] = None) -> List[str]:
        """在线就绪集重排: 就绪任务按策略分重排.
        changed 影响的任务实时重算嵌入, 未受影响沿用缓存.
        对应 GraphEdge §5 在线动态重排.
        """
        with self._lock:
            embs = self._ensure_embeddings(changed)
        scored = []
        for t in ready_tasks:
            e = embs.get(t)
            if e is None:
                continue
            scored.append((self._rl.policy_score(e), t))
        scored.sort(key=lambda x: x[0], reverse=True)
        seen = {t for _, t in scored}
        return [t for _, t in scored] + [t for t in ready_tasks if t not in seen]

    def schedule_all(self, num_workers: Optional[int] = None,
                     use_rl: bool = True) -> Dict[str, Any]:
        """当前 DAG 全量调度.
        返回 {order, makespan, mode, graph_embedding}.
        RL 已训练 -> 策略梯度确定式调度; 否则 -> 模拟退火降级.
        """
        nw = num_workers or self.num_workers
        with self._lock:
            embs = self._ensure_embeddings(full=True)
            nodes = self._dag.node_ids()
        if not nodes:
            self._last_schedule = {'order': [], 'makespan': 0.0, 'mode': 'none',
                                   'graph_embedding': []}
            return self._last_schedule
        if use_rl and self._rl.trained:
            order, mk = self._rl.schedule_deterministic(self._dag, embs, nw)
            mode = 'policy_gradient'
        else:
            order, mk, info = self._sa.schedule(self._dag, nw)
            mode = info['mode']
        ge = self._encoder.embed_graph(self._dag, embs)
        self._last_schedule = {'order': order, 'makespan': mk, 'mode': mode,
                               'graph_embedding': ge}
        return self._last_schedule

    def schedule_online(self, added: Optional[List[Dict[str, Any]]] = None,
                        removed: Optional[List[str]] = None,
                        num_workers: Optional[int] = None) -> Dict[str, Any]:
        """在线增量调度: 新增/撤销任务增量更新 DAG 与嵌入, 重排受影响任务.
        避免全量重算 [GraphEdge 2025 §5].
        added: [{task_id, deps, est_duration, resource_demand, priority_hint}, ...]
        返回: {order, makespan, mode, changed}
        """
        nw = num_workers or self.num_workers
        changed: Set[str] = set()
        with self._lock:
            for spec in added or []:
                tid = spec['task_id']
                self._dag.add_task(tid,
                                   est_duration=spec.get('est_duration', 60.0),
                                   resource_demand=spec.get('resource_demand', 0.5),
                                   priority_hint=spec.get('priority_hint', 50.0),
                                   deps=spec.get('deps'))
                changed.add(tid)
                changed.update(spec.get('deps', []))
            for tid in removed or []:
                aff = self._dag.remove_task(tid)
                changed.add(tid)
                changed.update(aff)
            embs = self._ensure_embeddings(changed if changed else None)
        if not self._dag.node_ids():
            self._last_schedule = {'order': [], 'makespan': 0.0, 'mode': 'none',
                                   'changed': sorted(changed)}
            return self._last_schedule
        if self._rl.trained:
            order, mk = self._rl.schedule_deterministic(self._dag, embs, nw)
            mode = 'policy_gradient'
        else:
            order, mk, info = self._sa.schedule(self._dag, nw)
            mode = info['mode']
        self._last_schedule = {'order': order, 'makespan': mk, 'mode': mode,
                               'changed': sorted(changed)}
        return self._last_schedule

# 训练

    def train(self, episodes: int = 50,
              num_workers: Optional[int] = None) -> Dict[str, Any]:
        """策略梯度训练: 以负 makespan 为奖励优化调度顺序.
        训练后 schedule_all 走策略梯度路径.
        """
        nw = num_workers or self.num_workers
        with self._lock:
            embs = self._ensure_embeddings(full=True)
        best_order: List[str] = []
        best_mk = float('inf')
        for _ in range(episodes):
            order, mk = self._rl.update(self._dag, embs, nw)
            if mk < best_mk:
                best_order, best_mk = order, mk
        return {'episodes': self._rl.episodes, 'best_order': best_order,
                'best_makespan': best_mk, 'trained': self._rl.trained}

# 兼容接口 / 反馈

    def feedback(self, task_id: str, duration: float, success: bool,
                 was_blocker: bool = False) -> None:
        """执行结果反馈: 记录历史时延. 兼容 AdaptiveScheduler.feedback.
        边界: 不在此处改写 est_duration (由外部显式 update_task 决定),
        避免在线调度抖动.
        """
        self._feedback_hist[task_id].append((time.time(), duration, success))

    def estimate_makespan(self, task_ids: List[str]) -> float:
        """估算给定任务集调度时延 (子图关键路径下界).
        兼容 AdaptiveScheduler.estimate_makespan.
        """
        idset = set(task_ids)
        sub = TaskDAG()
        for tid in task_ids:
            t = self._dag.task(tid)
            if t is None:
                continue
            deps = [d for d in t.deps if d in idset]
            sub.add_task(tid, est_duration=t.est_duration,
                         resource_demand=t.resource_demand,
                         priority_hint=t.priority_hint, deps=deps)
        lp = sub.longest_path_lengths()
        return max(lp.values()) if lp else 0.0

    def suggest_batch_order(self, tasks: List[Tuple[str, float]]
                            ) -> List[Tuple[str, float]]:
        """批量任务排序建议. 兼容 AdaptiveScheduler.suggest_batch_order.
        返回 [(task_id, 策略分), ...] 按策略分降序.
        """
        with self._lock:
            for tid, dur in tasks:
                self._dag.add_task(tid, est_duration=dur)
            embs = self._ensure_embeddings()
        scored = []
        for tid, _ in tasks:
            e = embs.get(tid)
            if e is not None:
                scored.append((tid, self._rl.policy_score(e)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def export_state(self) -> Dict[str, Any]:
        """导出调度器状态: DAG 结构 / 策略权重 / 训练统计."""
        with self._lock:
            nodes = [{'task_id': t.task_id, 'est_duration': t.est_duration,
                      'resource_demand': t.resource_demand,
                      'priority_hint': t.priority_hint,
                      'deps': list(t.deps)} for t in self._dag._tasks.values()]
            return {'dag': {'nodes': nodes, 'node_count': len(nodes)},
                    'policy_weights': list(self._rl._w),
                    'policy_bias': self._rl._b,
                    'trained': self._rl.trained,
                    'episodes': self._rl.episodes,
                    'last_schedule': self._last_schedule}

    @property
    def dag(self) -> TaskDAG:
        return self._dag


# TaskScheduler 叠加插件 (与 AdaptiveSchedulerPlugin 用法对齐)

@dataclass(order=True)
class _QItemDag:
    priority: int
    task_id: str = field(compare=False)
    payload: Any = field(compare=False, default=None)


class DAGDRLSchedulerPlugin:
    """TaskScheduler 的 DAG-DRL 叠加插件.
    用法与 AdaptiveSchedulerPlugin 对齐:
      sched = TaskScheduler()
      plugin = DAGDRLSchedulerPlugin(sched)
      sched.run_all()  # 插件在 _enq 阶段介入, 按 DAG 依赖感知策略分重建就绪堆.
    """

    def __init__(self, scheduler=None,
                 dag_scheduler: Optional[DAGDRLScheduler] = None) -> None:
        self.scheduler = scheduler
        self.dag_scheduler = dag_scheduler or DAGDRLScheduler()
        self._enabled = True

    def wrapped_enqueue(self, original_enqueue_fn):
        """装饰 TaskScheduler._enq: 入队后按 DAG-DRL 优先级重建堆."""
        def wrapper():
            original_enqueue_fn()
            if not self._enabled:
                return
            if not hasattr(self.scheduler, '_rq'):
                return
            items = []
            while self.scheduler._rq:
                items.append(heapq.heappop(self.scheduler._rq))
            tids = [item.task_id for item in items]
            ranked = self.dag_scheduler.prioritize(tids)
            rank_map = {tid: i for i, tid in enumerate(ranked)}
            for item in items:
                new_prio = rank_map.get(item.task_id, item.priority)
                heapq.heappush(self.scheduler._rq,
                               _QItemDag(new_prio, item.task_id, item.payload))
        return wrapper

    def feedback_from_result(self, task_id: str, duration: float,
                             success: bool, blocker: bool = False) -> None:
        self.dag_scheduler.feedback(task_id, duration, success, blocker)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, v: bool) -> None:
        self._enabled = v


# 便捷工厂

def create_dag_drl_scheduler(num_workers: int = 4, seed: int = 20260803,
                             train_episodes: int = 0) -> DAGDRLScheduler:
    """构建 DAG-DRL 调度器. train_episodes > 0 时立即执行策略梯度训练."""
    enc = DagGraphEncoder(seed=seed)
    sched = DAGDRLScheduler(num_workers=num_workers, encoder=enc)
    if train_episodes > 0:
        sched.train(episodes=train_episodes)
    return sched


def _debug_print(*args, **kwargs): pass

__all__ = [
    'DAGTask', 'TaskDAG', 'DagGraphEncoder',
    'SimulatedAnnealingScheduler', 'PolicyGradientScheduler',
    'DAGDRLScheduler', 'DAGDRLSchedulerPlugin',
    'build_list_schedule', 'simulate_makespan', 'create_dag_drl_scheduler',
]
