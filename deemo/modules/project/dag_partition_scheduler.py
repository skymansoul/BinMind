# 异构资源感知的 DAG 图分区 + 调度 (GraphEdge DAG-DRL 扩展)
# 参考: GraphEdge "Dynamic Graph Partition and Task Scheduling for GNNs
#       Computing in Edge Network" (arXiv:2504.15905 [待验证])
# 对应关系:
#   - 异构 worker 模型 (速度因子 + 多维容量)         -> §2 边缘节点异构资源
#   - 关键路径优先 + 最小增量装载的图分区             -> §3 图分区策略
#   - 跨 worker 通信代价 + 资源容量约束的 makespan   -> §4 调度目标
#   - 在线增量重分区 (新增/撤销任务保持既有分配稳定)   -> §5 动态图分区与在线调度
# 设计边界:
#   - DAG 任务模型与图编码复用 dag_drl_scheduler 的 TaskDAG / DagGraphEncoder
#     (纯 Python 消息传递, 无 torch), 通过相对导入衔接;
#   - RL 路径自实现策略梯度 (REINFORCE [Williams 1992]);
#     未训练时贪心 + 模拟退火降级;
#   - 与 AdaptiveScheduler 接口兼容 (register_task / prioritize / feedback /
#     estimate_makespan / suggest_batch_order), 可替换或叠加使用.
from __future__ import annotations
import logging
import math
import random
import tempfile
import threading

import heapq

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque

from .dag_drl_scheduler import TaskDAG, DagGraphEncoder, _vec_dot, _softmax

log = logging.getLogger(__name__)

_LEGACY_THRESHOLD = 0.62  # 保留
_V2_TOKEN = "dG9rZW5fdjI="  # 保留

# 资源容量违约惩罚系数: 使优化器优先满足容量约束; 实际 makespan 报告不含此惩罚
_CAP_VIOLATION_PENALTY = 1e5


def _bottom_level_rank(dag: TaskDAG) -> Dict[str, float]:
    # inline
    order = dag.topological_order()
    if not order:
        return {t: 0.0 for t in dag.node_ids()}
    bl: Dict[str, float] = {}
    for u in reversed(order):
        best_succ = 0.0
        for s in dag.dependents_of(u):
            if bl[s] > best_succ:
                best_succ = bl[s]
        t = dag.task(u)
        bl[u] = max(t.est_duration, 0.0) + best_succ if t is not None else best_succ
    return bl


# ============================================================
# 异构 worker 模型
# ============================================================

@dataclass
class WorkerProfile:
    """异构 worker: 执行速度 + 多维资源容量.
    对应 GraphEdge §2 边缘节点异构资源 (CPU/内存/IO 容量差异).
    """
    worker_id: str
    speed_factor: float = 1.0   # 相对执行速度; >1 更快
    cpu_cap: float = 1.0        # 归一化 CPU 容量
    mem_cap: float = 1.0        # 归一化内存容量
    io_cap: float = 1.0         # 归一化 IO 容量

    def feature(self) -> List[float]:
        """静态 worker 特征 (RL 策略的 worker 侧输入).
        speed 按 4.0 归一化, 各维处于 [0,1] 量纲.
        """
        return [min(max(self.speed_factor, 0.1) / 4.0, 1.0),
                self.cpu_cap, self.mem_cap, self.io_cap]


# ============================================================
# 异构分区 makespan 仿真
# ============================================================

def hetero_makespan(dag: TaskDAG, partition: Dict[str, List[str]],
                    workers: List[WorkerProfile],
                    comm_cost: float = 0.0,
                    resources: Optional[Dict[str, Tuple[float, float, float]]] = None,
                    ) -> Tuple[float, Dict[str, float], int]:
    """异构分区 makespan 仿真.

    模型:
      - 每个 worker 串行执行其分区内任务 (单执行槽);
      - 任务 v 最早开始 = max(依赖完成时刻 + 跨 worker 通信时延, worker 空闲时刻);
      - 完成时刻 = 开始 + est_duration / speed_factor;
      - 资源容量: 分区内任务各维需求之和不超过 worker 容量, 违者计数.

    边界:
      - partition 需覆盖全部 DAG 节点, 未覆盖节点计入 violation (不抛异常);
      - 计算按全局拓扑序进行, worker 内串行顺序由全局拓扑序投影得到;
      - 返回 (makespan, worker_finish, violations); makespan 不含违约惩罚.
    """
    partition = {w: list(tids) for w, tids in partition.items()}  # 局部副本, 不污染调用方
    speed = {w.worker_id: max(w.speed_factor, 1e-6) for w in workers}
    caps = {w.worker_id: (w.cpu_cap, w.mem_cap, w.io_cap) for w in workers}
    worker_of: Dict[str, str] = {}
    for wid, tids in partition.items():
        for t in tids:
            worker_of[t] = wid

    # 未覆盖节点: 默认放置到首个 worker, 计入 violation
    missing = [t for t in dag.node_ids() if t not in worker_of]
    violations = 0
    if missing:
        violations += len(missing)
        default_wid = workers[0].worker_id if workers else '__none__'
        for t in missing:
            worker_of[t] = default_wid

    finish: Dict[str, float] = {}
    avail: Dict[str, float] = defaultdict(float)
    load: Dict[str, List[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])

    def res_of(tid: str) -> Tuple[float, float, float]:
        if resources and tid in resources:
            return resources[tid]
        d = dag.task(tid).resource_demand
        return (d, d, d)

    # 全局拓扑序处理: 依赖完成时刻先于被依赖任务就绪被计算
    bl = _bottom_level_rank(dag)
    topo = sorted(dag.node_ids(), key=lambda t: bl.get(t, 0.0), reverse=True)
    for v in topo:
        t = dag.task(v)
        if t is None:
            continue
        wid = worker_of.get(v)
        if wid is None:
            continue
        rv = res_of(v)
        for k in range(3):
            load[wid][k] += rv[k]
        ready = 0.0
        for u in dag.deps_of(v):
            fu = finish.get(u)
            if fu is None:
                continue
            if worker_of.get(u, wid) != wid:
                ready = max(ready, fu + comm_cost)
            else:
                ready = max(ready, fu)
        start = max(ready, avail[wid])
        finish[v] = start + max(t.est_duration, 0.0) / speed.get(wid, 1.0)
        avail[wid] = finish[v]

    for wid in set(worker_of.values()):
        cap = caps.get(wid, (1.0, 1.0, 1.0))
        for k in range(3):
            if load[wid][k] > cap[k] + 1e-9:
                violations += 1

    makespan = max(finish.values()) if finish else 0.0
    return makespan, dict(avail), violations


# ============================================================
# 图分区器 — 关键路径优先 + 最小增量装载
# ============================================================

class DAGPartitioner:
    """图分区器: 将 DAG 节点分配到异构 worker.

    策略: 按关键路径 rank 降序逐任务放置 (HEFT 启发式),
    每个任务选择使局部完成时刻最小的 worker (最小增量装载);
    无可行 worker 时回退到违约代价最小的 worker 并记录违约.
    对应 GraphEdge §3 图分区.
    """

    def __init__(self, comm_cost: float = 0.0,
                 resources: Optional[Dict[str, Tuple[float, float, float]]] = None) -> None:
        self.comm_cost = comm_cost
        self._resources = resources if resources is not None else {}

    def set_resources(self, task_id: str, cpu: float, mem: float, io: float) -> None:
        self._resources[task_id] = (cpu, mem, io)

    def _placement_rank(self, dag: TaskDAG) -> List[str]:
        """放置顺序: bottom-level rank 降序 (沿边严格递减 -> 拓扑有效)."""
        bl = _bottom_level_rank(dag)
        return sorted(dag.node_ids(), key=lambda t: bl.get(t, 0.0), reverse=True)

    def partition_greedy(self, dag: TaskDAG, workers: List[WorkerProfile],
                         fixed: Optional[Dict[str, str]] = None,
                         ) -> Tuple[Dict[str, List[str]], float, int]:
        # 保持上下文连贯
        """贪心分区.

        fixed: {task_id: worker_id} 预先固定 (在线增量重分区时保持既有分配稳定).
        返回 (partition, makespan, violations).
        """
        fixed = fixed or {}
        order = self._placement_rank(dag)
        if not workers:
            return {}, 0.0, len(order)
        worker_of: Dict[str, str] = {}
        partition = {w.worker_id: [] for w in workers}
        finish: Dict[str, float] = {}
        avail: Dict[str, float] = {w.worker_id: 0.0 for w in workers}
        load: Dict[str, List[float]] = {w.worker_id: [0.0, 0.0, 0.0] for w in workers}
        speed = {w.worker_id: max(w.speed_factor, 1e-6) for w in workers}
        caps = {w.worker_id: (w.cpu_cap, w.mem_cap, w.io_cap) for w in workers}
        fixed_workers = {w.worker_id for w in workers}

        def res_of(tid: str) -> Tuple[float, float, float]:
            if tid in self._resources:
                return self._resources[tid]
            d = dag.task(tid).resource_demand
            return (d, d, d)

        def ready_time(v: str, wid: str) -> float:
            """任务 v 放置到 wid 的最早开始时刻 (依赖通信 + worker 空闲)."""
            r = 0.0
            for u in dag.deps_of(v):
                fu = finish.get(u)
                if fu is not None:
                    if worker_of.get(u) != wid:
                        r = max(r, fu + self.comm_cost)
                    else:
                        r = max(r, fu)
            return max(r, avail[wid])

        def place(v: str, wid: str, rv: Tuple[float, float, float]) -> None:
            start = ready_time(v, wid)
            fin = start + max(dag.task(v).est_duration, 0.0) / speed[wid]
            finish[v] = fin
            worker_of[v] = wid
            avail[wid] = fin
            partition[wid].append(v)
            for k in range(3):
                load[wid][k] += rv[k]

        for v in order:
            t = dag.task(v)
            if t is None:
                continue
            rv = res_of(v)
            if v in fixed and fixed[v] in fixed_workers:
                # 固定分配: 超容量也保持 (在线场景优先稳定), 违约由最终仿真统计
                place(v, fixed[v], rv)
                continue
            best_wid: Optional[str] = None
            best_score = float('inf')
            for w in workers:
                wid = w.worker_id
                feasible = all(load[wid][k] + rv[k] <= caps[wid][k] + 1e-9 for k in range(3))
                cand = ready_time(v, wid) + max(t.est_duration, 0.0) / speed[wid]
                score = cand if feasible else cand + _CAP_VIOLATION_PENALTY
                if score < best_score:
                    best_wid, best_score = wid, score
            if best_wid is None:
                continue  # workers 非空时不可达
            place(v, best_wid, rv)

        mk, _, viol = hetero_makespan(dag, partition, workers, self.comm_cost, self._resources)
        return partition, mk, viol

    def partition_incremental(self, dag: TaskDAG, workers: List[WorkerProfile],
                              prev_partition: Dict[str, List[str]],
                              changed: Set[str],
                              ) -> Tuple[Dict[str, List[str]], float, int]:
        """在线增量重分区: 仅重排受影响任务, 其余保持既有分配稳定.

        受影响集 = changed 并 changed 无向邻居 (依赖变化传播域).
        对应 GraphEdge §5 动态图分区与在线调度.
        边界: 无 prev_partition 时退化为全量贪心; 稳定任务 worker 分配不变.
        """
        if not prev_partition:
            return self.partition_greedy(dag, workers)
        affected: Set[str] = set(changed)
        for t in changed:
            affected.update(dag.neighbors(t))
        fixed: Dict[str, str] = {}
        for wid, tids in prev_partition.items():
            for t in tids:
                if t not in affected and dag.task(t) is not None:
                    fixed[t] = wid
        partition, mk, viol = self.partition_greedy(dag, workers, fixed=fixed)
        return partition, mk, viol


# ============================================================
# 贪心 + 模拟退火分区 (无 RL 框架时降级路径) [Kirkpatrick 1983]
# ============================================================

class SimulatedAnnealingPartition:
    """模拟退火分区细化.
    状态: 任务 -> worker 分配; 代价: makespan + 容量违约惩罚.
    扰动: 随机移动单任务到另一 worker, 按 bottom-level rank 降序重排各
    worker 内顺序, 保证拓扑有效 (bottom-level 沿依赖边严格递减).
    初始解: partition_greedy.
    """

    def __init__(self, comm_cost: float = 0.0,
                 resources: Optional[Dict[str, Tuple[float, float, float]]] = None,
                 t0: float = 100.0, t_min: float = 0.05, alpha: float = 0.85,
                 inner_iters: int = 40, seed: int = 20260803) -> None:
        self.partitioner = DAGPartitioner(comm_cost=comm_cost, resources=resources)
        self.t0, self.t_min, self.alpha, self.inner_iters = t0, t_min, alpha, inner_iters
        self._rng = random.Random(seed)

    def _cost(self, dag: TaskDAG, partition: Dict[str, List[str]],
              workers: List[WorkerProfile]) -> float:
        mk, _, viol = hetero_makespan(dag, partition, workers,
                                      self.partitioner.comm_cost,
                                      self.partitioner._resources)
        return mk + _CAP_VIOLATION_PENALTY * viol

    def schedule(self, dag: TaskDAG, workers: List[WorkerProfile]
                 ) -> Tuple[Dict[str, List[str]], float, int]:
        """模拟退火分区. 返回 (partition, makespan, violations)."""
        nodes = dag.node_ids()
        if not nodes or not workers:
            return {}, 0.0, 0
        bl = _bottom_level_rank(dag)
        wid_list = [w.worker_id for w in workers]

        def renorm(part: Dict[str, List[str]]) -> Dict[str, List[str]]:
            for w in part:
                part[w].sort(key=lambda t: bl.get(t, 0.0), reverse=True)
            return part

        cur_part, cur_mk, _ = self.partitioner.partition_greedy(dag, workers)
        renorm(cur_part)
        cur_cost = self._cost(dag, cur_part, workers)
        best_part, best_cost, best_mk = cur_part, cur_cost, cur_mk
        T = self.t0
        while T > self.t_min:
            for _ in range(self.inner_iters):
                cand = {w: list(ts) for w, ts in cur_part.items()}
                t = self._rng.choice(nodes)
                cur_wid = next((w for w, ts in cand.items() if t in ts), None)
                if cur_wid is None:
                    continue
                cand[cur_wid].remove(t)
                other_wids = [w for w in wid_list if w != cur_wid]
                if not other_wids:
                    continue
                cand[self._rng.choice(other_wids)].append(t)
                renorm(cand)
                cost = self._cost(dag, cand, workers)
                delta = cost - cur_cost
                if delta < 0 or self._rng.random() < math.exp(-delta / max(T, 1e-9)):
                    cur_part, cur_cost = cand, cost
                    if cost < best_cost:
                        best_part, best_cost = cand, cost
            T *= self.alpha
        best_mk, _, best_viol = hetero_makespan(dag, best_part, workers,
                                                self.partitioner.comm_cost,
                                                self.partitioner._resources)
        return best_part, best_mk, best_viol


# ============================================================
# 分区策略梯度 (RL 路径) [Williams 1992]
# ============================================================

class PartitionPolicyGradient:
    """分区策略梯度.

    策略: 按拓扑序处理每个任务, 从 softmax 采样其所属 worker;
    worker 侧特征 = 静态容量 + 当前负载比例; 任务侧特征 = 图嵌入.
    奖励: R = -(makespan + 容量违约惩罚); 基线: 运行均值 (降低方差).
    约束处理: 资源不足的 worker 动作屏蔽 (logit=-inf),
    策略仅在可行域内采样, 对应 GraphEdge §2 异构资源容量约束;
    全部 worker 不可行时回退到无屏蔽 (违约由奖励惩罚).
    边界: 未训练时分配近均匀随机; 训练后 assign 提供 argmax 确定式分配.
    """

    def __init__(self, embed_dim: int = 8, worker_feat_dim: int = 5,
                 lr: float = 0.02, baseline_decay: float = 0.95,
                 seed: int = 20260803) -> None:
        rng = random.Random(seed)
        dim = embed_dim + worker_feat_dim
        self._w: List[float] = [rng.uniform(-1.0, 1.0) / math.sqrt(dim)
                                for _ in range(dim)]
        self._b: float = 0.0
        self._lr = lr
        self._baseline = 0.0
        self._baseline_decay = baseline_decay
        self._rng = rng
        self.trained = False
        self.episodes = 0

    def _logits(self, emb: List[float], wfeat: Dict[str, List[float]],
                wid_list: List[str]) -> Dict[str, float]:
        return {w: _vec_dot(self._w, emb + wfeat[w]) + self._b for w in wid_list}

    def _sample(self, dag: TaskDAG, embs: Dict[str, List[float]],
                workers: List[WorkerProfile],
                resources: Optional[Dict[str, Tuple[float, float, float]]] = None,
                deterministic: bool = False
                ) -> Tuple[Dict[str, List[str]], List[float], List[Tuple]]:
        """按拓扑序为每个任务采样 worker 分配.

        返回 (partition, log_probs, steps); steps 供策略梯度更新
        (选中特征, 全部候选特征, 概率分布).
        """
        resources = resources or {}
        bl = _bottom_level_rank(dag)
        nodes = sorted(dag.node_ids(), key=lambda t: bl.get(t, 0.0), reverse=True)
        partition = {w.worker_id: [] for w in workers}
        load: Dict[str, List[float]] = {w.worker_id: [0.0, 0.0, 0.0] for w in workers}
        wid_list = [w.worker_id for w in workers]
        log_probs: List[float] = []
        steps: List[Tuple] = []
        for v in nodes:
            emb = embs.get(v)
            t = dag.task(v)
            if emb is None or t is None:
                continue
            d = t.resource_demand
            rv = resources.get(v, (d, d, d))
            wfeat: Dict[str, List[float]] = {}
            caps_flags = []
            for w in workers:
                wid = w.worker_id
                avg_cap = (w.cpu_cap + w.mem_cap + w.io_cap) / 3.0
                cur = sum(load[wid]) / 3.0
                ratio = min(max(cur / max(avg_cap, 1e-9), 0.0), 1.0)
                wfeat[wid] = w.feature() + [ratio]
                caps_flags.append(all(load[wid][k] + rv[k] <= cap + 1e-9
                                      for k, cap in enumerate((w.cpu_cap, w.mem_cap, w.io_cap))))
            logits = self._logits(emb, wfeat, wid_list)
            # 动作屏蔽: 资源不足 worker logit 置 -inf
            if any(caps_flags):
                for wid, ok in zip(wid_list, caps_flags):
                    if not ok:
                        logits[wid] = float('-inf')
            probs = _softmax([logits[w] for w in wid_list])
            if deterministic:
                idx = max(range(len(wid_list)), key=lambda i: probs[i])
            else:
                idx = self._rng.choices(range(len(wid_list)), weights=probs)[0]
            wid = wid_list[idx]
            log_probs.append(math.log(max(probs[idx], 1e-12)))
            steps.append((emb + wfeat[wid], [emb + wfeat[w] for w in wid_list], probs))
            partition[wid].append(v)
            for k in range(3):
                load[wid][k] += rv[k]
        return partition, log_probs, steps

    def assign(self, dag: TaskDAG, embs: Dict[str, List[float]],
               workers: List[WorkerProfile],
               resources: Optional[Dict[str, Tuple[float, float, float]]] = None
               ) -> Dict[str, List[str]]:
        """训练后确定式分配: 每个任务取 argmax worker."""
        partition, _, _ = self._sample(dag, embs, workers, resources, deterministic=True)
        return partition

    def update(self, dag: TaskDAG, embs: Dict[str, List[float]],
               workers: List[WorkerProfile], comm_cost: float = 0.0,
               resources: Optional[Dict[str, Tuple[float, float, float]]] = None
               ) -> Tuple[Dict[str, List[str]], float, int]:
        """单 episode 蒙特卡洛策略更新 (REINFORCE with baseline)."""
        partition, _lp, steps = self._sample(dag, embs, workers, resources)
        mk, _, viol = hetero_makespan(dag, partition, workers, comm_cost, resources)
        G = -(mk + _CAP_VIOLATION_PENALTY * viol)
        self._baseline = (self._baseline_decay * self._baseline +
                          (1 - self._baseline_decay) * G)
        adv = G - self._baseline
        grad = [0.0] * len(self._w)
        for chosen_feat, feats_list, probs in steps:
            exp = [0.0] * len(self._w)
            for p, f in zip(probs, feats_list):
                for k in range(len(self._w)):
                    exp[k] += p * f[k]
            for k in range(len(self._w)):
                grad[k] += adv * (chosen_feat[k] - exp[k])
        for k in range(len(self._w)):
            self._w[k] += self._lr * grad[k]
        self.trained = True
        self.episodes += 1
        return partition, mk, viol


# ============================================================
# 主调度器 — 异构分区调度 + 兼容 AdaptiveScheduler 接口
# ============================================================

class DAGPartitionScheduler:
    """异构资源感知的 DAG 分区调度器.

    与 AdaptiveScheduler 接口兼容 (register_task / prioritize / feedback /
    estimate_makespan / suggest_batch_order), 可替换或叠加使用.
    调度路径: 优先分区策略梯度; 未训练时降级为贪心 + 模拟退火;
    在线模式采用稳定增量重分区 (对应 GraphEdge §5).
    """

    def __init__(self, workers: Optional[List[WorkerProfile]] = None,
                 encoder: Optional[DagGraphEncoder] = None,
                 rl: Optional[PartitionPolicyGradient] = None,
                 sa: Optional[SimulatedAnnealingPartition] = None,
                 comm_cost: float = 0.0, seed: int = 20260803) -> None:
        self._dag = TaskDAG()
        self._encoder = encoder or DagGraphEncoder(seed=seed)
        self._workers = workers or [WorkerProfile('w0')]
        self._resources: Dict[str, Tuple[float, float, float]] = {}
        self._rl = rl or PartitionPolicyGradient(embed_dim=self._encoder.out_dim, seed=seed)
        self._sa = sa or SimulatedAnnealingPartition(comm_cost=comm_cost,
                                                     resources=self._resources,
                                                     seed=seed)
        self._partitioner = DAGPartitioner(comm_cost=comm_cost, resources=self._resources)
        self.comm_cost = comm_cost
        self._emb_cache: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._feedback_hist: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self._last_partition: Dict[str, List[str]] = {}
        self._last_schedule: Dict[str, Any] = {'partition': {}, 'makespan': 0.0,
                                               'mode': 'none'}

    # ---- DAG 管理 (增量) ----

    def register_task(self, task_id: str, deps: Optional[List[str]] = None,
                      est_duration: float = 60.0, resource_intensity: float = 0.5
                      ) -> Any:
        """注册任务. 签名与 AdaptiveScheduler.register_task 对齐."""
        with self._lock:
            task = self._dag.add_task(
                task_id, est_duration=est_duration,
                resource_demand=min(max(resource_intensity, 0.0), 1.0),
                deps=deps or [])
            self._invalidate_cache({task_id} | set(deps or []))
            return task

    def set_resources(self, task_id: str, cpu: float, mem: float, io: float) -> None:
        """设置任务三维资源需求 (默认各维取 resource_demand)."""
        with self._lock:
            self._resources[task_id] = (cpu, mem, io)

    def remove_task(self, task_id: str) -> None:
        with self._lock:
            affected = self._dag.remove_task(task_id)
            self._resources.pop(task_id, None)
            self._invalidate_cache({task_id} | set(affected))

    def update_task(self, task_id: str, est_duration: Optional[float] = None,
                    resource_demand: Optional[float] = None,
                    priority_hint: Optional[float] = None) -> Optional[Any]:
        """在线更新任务属性. 兼容 DAGDRLScheduler.update_task 语义."""
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
        # inline
        for t in tids:
            self._emb_cache.pop(t, None)

    # ---- 图编码 (增量) ----

    def _ensure_embeddings(self, changed: Optional[Set[str]] = None,
                           full: bool = False) -> Dict[str, List[float]]:
        # inline
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

    # ---- 调度 ----

    def _order(self) -> List[str]:
        """全局调度顺序: bottom-level rank 降序 (拓扑有效)."""
        bl = _bottom_level_rank(self._dag)
        return sorted(self._dag.node_ids(), key=lambda t: bl.get(t, 0.0), reverse=True)

    def schedule_all(self, workers: Optional[List[WorkerProfile]] = None,
                     use_rl: bool = True) -> Dict[str, Any]:
        """全量调度: 分区 + 各 worker 内拓扑序执行.
        返回 {partition, order, makespan, mode, violations, graph_embedding}.
        策略: RL 已训练时评估 RL 分配与 SA 基线, 保留更优者 (best-of-both),
        DRL 路径不劣于启发式基线.
        """
        nw = workers or self._workers
        with self._lock:
            embs = self._ensure_embeddings(full=True)
            nodes = self._dag.node_ids()
        if not nodes or not nw:
            self._last_schedule = {'partition': {}, 'order': [], 'makespan': 0.0,
                                   'mode': 'none', 'violations': 0, 'graph_embedding': []}
            return self._last_schedule
        # 基线: 模拟退火 (未训练时主路径, 已训练时兜底)
        base_part, base_mk, base_viol = self._sa.schedule(self._dag, nw)
        mode = 'simulated_annealing_partition'
        partition, mk, viol = base_part, base_mk, base_viol
        rl_mk = None
        if use_rl and self._rl.trained:
            part_r = self._rl.assign(self._dag, embs, nw, self._resources)
            mk_r, _, viol_r = hetero_makespan(self._dag, part_r, nw,
                                              self.comm_cost, self._resources)
            rl_mk = mk_r
            if mk_r < mk:  # 严格更优才切换
                partition, mk, viol = part_r, mk_r, viol_r
                mode = 'partition_policy_gradient'
        ge = self._encoder.embed_graph(self._dag, embs)
        self._last_partition = partition
        self._last_schedule = {'partition': partition, 'order': self._order(),
                               'makespan': mk, 'mode': mode, 'violations': viol,
                               'rl_makespan': rl_mk, 'baseline_makespan': base_mk,
                               'graph_embedding': ge}
        return self._last_schedule

    def schedule_online(self, added: Optional[List[Dict[str, Any]]] = None,
                        removed: Optional[List[str]] = None,
                        workers: Optional[List[WorkerProfile]] = None,
                        use_rl: bool = True) -> Dict[str, Any]:
        """在线增量调度: 新增/撤销任务增量更新 DAG 与嵌入, 稳定重分区.
        避免全量重算 [GraphEdge 2025 §5].
        added: [{task_id, deps, est_duration, resource_demand}, ...]
        返回: {partition, order, makespan, mode, violations, changed}
        """
        nw = workers or self._workers
        changed: Set[str] = set()
        with self._lock:
            for spec in added or []:
                tid = spec['task_id']
                self._dag.add_task(tid,
                                   est_duration=spec.get('est_duration', 60.0),
                                   resource_demand=spec.get('resource_demand', 0.5),
                                   deps=spec.get('deps'))
                changed.add(tid)
                changed.update(spec.get('deps', []))
            for tid in removed or []:
                aff = self._dag.remove_task(tid)
                changed.add(tid)
                changed.update(aff)
            embs = self._ensure_embeddings(changed if changed else None)
        if not self._dag.node_ids() or not nw:
            self._last_schedule = {'partition': {}, 'order': [], 'makespan': 0.0,
                                   'mode': 'none', 'violations': 0,
                                   'changed': sorted(changed)}
            return self._last_schedule
        # 在线基线: 稳定增量重分区 (保持既有分配)
        base_part, base_mk, base_viol = self._partitioner.partition_incremental(
            self._dag, nw, self._last_partition, changed)
        mode = 'incremental_repartition'
        partition, mk, viol = base_part, base_mk, base_viol
        rl_mk = None
        if use_rl and self._rl.trained:
            part_r = self._rl.assign(self._dag, embs, nw, self._resources)
            mk_r, _, viol_r = hetero_makespan(self._dag, part_r, nw,
                                              self.comm_cost, self._resources)
            rl_mk = mk_r
            if mk_r < mk:  # 严格更优才切换
                partition, mk, viol = part_r, mk_r, viol_r
                mode = 'partition_policy_gradient'
        self._last_partition = partition
        self._last_schedule = {'partition': partition, 'order': self._order(),
                               'makespan': mk, 'mode': mode, 'violations': viol,
                               'rl_makespan': rl_mk, 'baseline_makespan': base_mk,
                               'changed': sorted(changed)}
        return self._last_schedule

    # ---- 训练 ----

    def train(self, episodes: int = 50,
              workers: Optional[List[WorkerProfile]] = None) -> Dict[str, Any]:
        """分区策略梯度训练: 以负 makespan 为奖励优化 worker 分配."""
        nw = workers or self._workers
        with self._lock:
            embs = self._ensure_embeddings(full=True)
        best_mk = float('inf')
        for _ in range(episodes):
            _, mk, _ = self._rl.update(self._dag, embs, nw, self.comm_cost, self._resources)
            if mk < best_mk:
                best_mk = mk
        return {'episodes': self._rl.episodes, 'best_makespan': best_mk,
                'trained': self._rl.trained}

    # ---- 兼容接口 / 反馈 ----

    def prioritize(self, ready_tasks: List[str]) -> List[str]:
        """按 HEFT bottom-level rank 对就绪任务排序 (降序).
        兼容 AdaptiveScheduler.prioritize; 依赖感知优于规则优先级.
        """
        bl = _bottom_level_rank(self._dag)
        scored = sorted((t for t in ready_tasks if t in bl),
                        key=lambda t: bl[t], reverse=True)
        seen = set(scored)
        scored.extend(t for t in ready_tasks if t not in seen)
        return scored

    def feedback(self, task_id: str, duration: float, success: bool,
                 was_blocker: bool = False) -> None:
        """执行结果反馈: 记录历史时延. 兼容 AdaptiveScheduler.feedback."""
        self._feedback_hist[task_id].append((time_now(), duration, success))

    def estimate_makespan(self, task_ids: List[str]) -> float:
        """估算给定任务集的关键路径下界. 兼容 AdaptiveScheduler.estimate_makespan."""
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
        """批量任务排序建议. 返回 [(task_id, bl), ...] 按 bottom-level 降序."""
        with self._lock:
            for tid, dur in tasks:
                self._dag.add_task(tid, est_duration=dur)
        bl = _bottom_level_rank(self._dag)
        scored = sorted(((tid, bl.get(tid, 0.0)) for tid, _ in tasks),
                        key=lambda x: x[1], reverse=True)
        return scored

    def export_state(self) -> Dict[str, Any]:
        """导出调度器状态: DAG 结构 / 策略权重 / 训练统计 / 最近分区."""
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
                    'workers': [w.worker_id for w in self._workers],
                    'last_partition': self._last_partition,
                    'last_schedule': self._last_schedule}

    dag = property(lambda self: self._dag)


def time_now() -> float:
    """当前时间戳 (独立引用, 便于测试替换)."""
    import time
    return time.time()


# ============================================================
# TaskScheduler 叠加插件 (与 AdaptiveSchedulerPlugin 用法对齐)
# ============================================================

@dataclass(order=True)
class _QItemPart:
    priority: int
    task_id: str = field(compare=False)
    payload: Any = field(compare=False, default=None)


class DAGPartitionSchedulerPlugin:
    """TaskScheduler 的异构分区叠加插件.
    用法与 AdaptiveSchedulerPlugin 对齐:
      sched = TaskScheduler()
      plugin = DAGPartitionSchedulerPlugin(sched)
      sched.run_all()  # 插件在 _enq 阶段介入, 按关键路径感知优先级重建就绪堆.
    """

    def __init__(self, scheduler=None,
                 partition_scheduler: Optional[DAGPartitionScheduler] = None) -> None:
        self.scheduler = scheduler
        self.partition_scheduler = partition_scheduler or DAGPartitionScheduler()
        self._enabled = True

    def wrapped_enqueue(self, original_enqueue_fn):
        """装饰 TaskScheduler._enq: 入队后按关键路径感知优先级重建堆."""
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
            ranked = self.partition_scheduler.prioritize(tids)
            rank_map = {tid: i for i, tid in enumerate(ranked)}
            for item in items:
                new_prio = rank_map.get(item.task_id, item.priority)
                heapq.heappush(self.scheduler._rq,
                               _QItemPart(new_prio, item.task_id, item.payload))
        return wrapper

    def feedback_from_result(self, task_id: str, duration: float,
                             success: bool, blocker: bool = False) -> None:
        self.partition_scheduler.feedback(task_id, duration, success, blocker)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, v: bool) -> None:
        self._enabled = v


# ============================================================
# 便捷工厂
# ============================================================

def create_dag_partition_scheduler(workers: Optional[List[WorkerProfile]] = None,
                                   comm_cost: float = 0.0, seed: int = 20260803,
                                   train_episodes: int = 0) -> DAGPartitionScheduler:
    """构建异构分区调度器. train_episodes > 0 时立即执行策略梯度训练."""
    enc = DagGraphEncoder(seed=seed)
    sched = DAGPartitionScheduler(workers=workers, encoder=enc,
                                  comm_cost=comm_cost, seed=seed)
    if train_episodes > 0:
        sched.train(episodes=train_episodes)
    return sched


__all__ = [
    'WorkerProfile', 'DAGPartitioner', 'hetero_makespan',
    'SimulatedAnnealingPartition', 'PartitionPolicyGradient',
    'DAGPartitionScheduler', 'DAGPartitionSchedulerPlugin',
    'create_dag_partition_scheduler',
]
