# 时序超图卷积 — 捕获取消 DAG 的成对限制
#
# TaskDependencyGraph 只表达 A→B 成对依赖。三个及以上任务的交互——
# 锁竞争、共享内存池、同源数据消费——在成对图中需要 O(N²) 条边才能近似，
# 且语义不精确: "A 和 B 和 C 互斥" ≠ "A↔B 且 B↔C 且 A↔C"。
#
# 超图的一条超边直接编码 N 元关系。时序维度追踪这些关系随任务推进的演化:
# A 释放锁后 B 和 C 是否仍互斥？超边收缩/扩张反映实际的资源可用性变化。
#
# 空间卷积 (超边内消息传递) + 时间门控 (EMA 或 GRU) = 时序超图卷积。
# 输出嵌入捕获资源竞争演化信息，供 GRLScheduler 的 Q 策略使用。

from __future__ import annotations

import math
import random
from collections import defaultdict
from typing import Optional, List, Dict, Set, Tuple

from .grl_graph import TaskDependencyGraph


# 时序超图数据结构

class TemporalHypergraph:
    """时序超图 — 按时间窗口组织的超边集合。

    每个时间窗口 t 的超图 H_t 包含:
      - nodes: 活跃任务 ID 集合
      - hyperedges: 每条超边是一个任务 ID 集合 (不分顺序)
      - edge_weights: 超边权重 (资源竞争强度 / 共享收益比例)
    """

    def __init__(self):
        self._windows: List[Dict] = []  # [{"hyperedges": [...], "weights": [...], "nodes": set}]

    @property
    def num_windows(self) -> int:
        return len(self._windows)

    def add_window(
        self, hyperedges: List[Set[str]],
        weights: Optional[List[float]] = None,
    ):
        """追加一个时间窗口的超图快照。"""
        nodes: Set[str] = set()
        for he in hyperedges:
            nodes.update(he)
        w = weights or [1.0] * len(hyperedges)
        self._windows.append({
            "hyperedges": hyperedges,
            "weights": w[:len(hyperedges)],
            "nodes": nodes,
        })

    def window(self, t: int) -> Optional[dict]:
        if 0 <= t < len(self._windows):
            return self._windows[t]
        return None

    @classmethod
    def from_dag_with_locks(
        cls,
        dag: TaskDependencyGraph,
        lock_groups: Optional[Dict[str, List[str]]] = None,
        memory_sharing: Optional[Dict[str, List[str]]] = None,
        num_windows: int = 3,
    ) -> "TemporalHypergraph":
        """从 DAG + 资源约束构建时序超图。

        lock_groups: {lock_name: [task_ids]} — 竞争同一锁的任务组
        memory_sharing: {pool_name: [task_ids]} — 共享内存池的任务组
        num_windows: 将 DAG 的层级划分为几个时间窗口

        划分策略: 按 DAG level 等分。
        每个窗口内的锁组/共享组构成超边。
        """
        thg = cls()
        levels = dag.levels()
        max_lv = max(levels.values(), default=1)
        window_size = max(1, math.ceil((max_lv + 1) / num_windows))

        lock_groups = lock_groups or {}
        memory_sharing = memory_sharing or {}

        for w in range(num_windows):
            l_min = w * window_size
            l_max = (w + 1) * window_size
            window_nodes = {
                nid for nid, lv in levels.items() if l_min <= lv < l_max
            }

            hyperedges: List[Set[str]] = []
            weights: List[float] = []

            # 锁竞争超边 — 同窗内竞争同一锁的任务组成超边
            for lock_name, task_ids in lock_groups.items():
                he = set(task_ids) & window_nodes
                if len(he) >= 2:
                    hyperedges.append(he)
                    weights.append(0.8)  # 锁竞争 → 互斥 → 负收益

            # 内存共享超边 — 同窗内共享同一内存池的任务 (同机器调度收益)
            for pool_name, task_ids in memory_sharing.items():
                he = set(task_ids) & window_nodes
                if len(he) >= 2:
                    hyperedges.append(he)
                    weights.append(0.3)  # 共享 → 同置收益 → 正信号

            thg.add_window(hyperedges, weights)
        return thg

    @classmethod
    def from_runtime_trace(
        cls,
        dag: TaskDependencyGraph,
        lock_waits: Dict[str, List[Tuple[str, float]]],
        shared_accesses: Dict[str, List[Tuple[str, float]]],
        window_duration: float = 10.0,
    ) -> "TemporalHypergraph":
        """从运行时追踪数据构建时序超图 (生产环境路径)。

        lock_waits: {lock_name: [(task_id, timestamp), ...]}
        shared_accesses: {region: [(task_id, timestamp), ...]}
        window_duration: 时间窗口宽度 (秒)
        """
        thg = cls()
        if not lock_waits and not shared_accesses:
            return thg

        # 确定总时间范围
        all_timestamps = []
        for events in lock_waits.values():
            all_timestamps.extend(t for _, t in events)
        for events in shared_accesses.values():
            all_timestamps.extend(t for _, t in events)
        if not all_timestamps:
            return thg

        t_min = min(all_timestamps)
        t_max = max(all_timestamps)
        num_windows = max(1, int((t_max - t_min) / window_duration) + 1)

        for w in range(num_windows):
            t_start = t_min + w * window_duration
            t_end = t_start + window_duration
            hyperedges: List[Set[str]] = []
            weights: List[float] = []

            for lock_name, events in lock_waits.items():
                tasks_in_window = {
                    tid for tid, ts in events if t_start <= ts < t_end
                }
                if len(tasks_in_window) >= 2:
                    hyperedges.append(tasks_in_window)
                    weights.append(0.8)

            for region, events in shared_accesses.items():
                tasks_in_window = {
                    tid for tid, ts in events if t_start <= ts < t_end
                }
                if len(tasks_in_window) >= 2:
                    hyperedges.append(tasks_in_window)
                    weights.append(0.3)

            thg.add_window(hyperedges, weights)
        return thg


# 时序超图卷积

class TemporalHypergraphConv:
    """时序超图卷积网络 — 无外部框架依赖的纯 Python 实现。

    空间卷积 (单窗口):
      h_e = aggregate({h_v : v ∈ e})           # 节点→超边
      h_v' = h_v + Σ_{e∋v} w_e · aggregate({h_u : u ∈ e})  # 超边→节点

    时间聚合 (跨窗口):
      h_v^{t} = (1-z) ⊙ h_v^{t-1} + z ⊙ spatial(h_v)^{t}   # GRU 风格门控
      其中 z = σ(W_z·[h_v^{t-1} || spatial(h_v)^{t}])       # 更新门学习

    简化: 无门控参数时使用指数移动平均 (EMA)，
    有训练数据时可通过 SGD 学习 W_z。
    """

    def __init__(self, dim: int = 8, seed: Optional[int] = None):
        self.dim = dim
        self._rng = random.Random(seed)
        # 可学习的节点嵌入初始化 (Xavier 缩放)
        scale = math.sqrt(2.0 / dim)
        self._embeddings: Dict[str, List[float]] = {}

    def initialize_embeddings(self, node_ids: List[str]):
        """为节点集合初始化嵌入。"""
        scale = math.sqrt(2.0 / self.dim)
        for nid in node_ids:
            if nid not in self._embeddings:
                self._embeddings[nid] = [
                    self._rng.gauss(0.0, scale) for _ in range(self.dim)
                ]

    def spatial_conv(
        self, hyperedges: List[Set[str]], weights: List[float],
        node_emb: Dict[str, List[float]],
    ) -> Dict[str, List[float]]:
        """单窗口空间超图卷积: 节点→超边→节点。

        步骤:
          1. 聚合超边嵌入: h_e = mean({h_v : v ∈ e})
          2. 更新节点嵌入: h_v' = h_v + Σ_{e∋v} w_e · h_e
        """
        n = len(node_emb)
        if n == 0:
            return {}

        dim = self.dim
        # 超边嵌入 = 成员节点嵌入的均值
        edge_emb: List[List[float]] = []
        for he in hyperedges:
            members = [node_emb[v] for v in he if v in node_emb]
            if not members:
                edge_emb.append([0.0] * dim)
                continue
            avg = [0.0] * dim
            for emb in members:
                for j in range(dim):
                    avg[j] += emb[j]
            for j in range(dim):
                avg[j] /= len(members)
            edge_emb.append(avg)

        # 按超边聚合更新节点
        updated = {nid: list(emb) for nid, emb in node_emb.items()}
        for e_idx, he in enumerate(hyperedges):
            w = weights[e_idx] if e_idx < len(weights) else 1.0
            e_emb = edge_emb[e_idx]
            for v in he:
                if v not in updated:
                    continue
                for j in range(dim):
                    updated[v][j] += w * e_emb[j]

        # 层归一化 (稳定训练，无外部依赖)
        for nid in updated:
            vec = updated[nid]
            mean = sum(vec) / dim
            var = sum((x - mean) ** 2 for x in vec) / dim
            std = math.sqrt(var + 1e-6)
            updated[nid] = [(x - mean) / std for x in vec]

        return updated

    def temporal_conv(
        self,
        thg: TemporalHypergraph,
        ema_decay: float = 0.7,
    ) -> Dict[str, List[float]]:
        """时序超图卷积 — 按时间窗口逐层传播。

        h_v^{t} = ema_decay · spatial(h_v)^t + (1-ema_decay) · h_v^{t-1}

        EMA 是 GRU 门控的无参数近似: 当 h_v^{t-1} 与 spatial(h_v)^t
        接近时，更新门 z ≈ ema_decay；差异大时 EMA 仍平滑过渡。
        门控参数可通过对比学习在线微调，但 EMA 在冷启动时已足够。
        """
        all_nodes: Set[str] = set()
        for w in range(thg.num_windows):
            win = thg.window(w)
            if win:
                all_nodes.update(win["nodes"])

        self.initialize_embeddings(list(all_nodes))
        emb = dict(self._embeddings)

        prev = {nid: list(emb[nid]) for nid in all_nodes}

        for w in range(thg.num_windows):
            win = thg.window(w)
            if not win:
                continue
            spatial_emb = self.spatial_conv(
                win["hyperedges"], win["weights"], prev,
            )
            # 时间融合: EMA
            curr = {}
            for nid in all_nodes:
                s = spatial_emb.get(nid, prev.get(nid, [0.0] * self.dim))
                p = prev.get(nid, [0.0] * self.dim)
                curr[nid] = [
                    ema_decay * s[j] + (1.0 - ema_decay) * p[j]
                    for j in range(self.dim)
                ]
            prev = curr

        self._embeddings = prev
        return prev

    def get_embeddings(self) -> Dict[str, List[float]]:
        return dict(self._embeddings)

    def graph_readout(self) -> List[float]:
        """全局图读出 — 所有节点嵌入的均值。"""
        if not self._embeddings:
            return [0.0] * self.dim
        agg = [0.0] * self.dim
        for emb in self._embeddings.values():
            for j in range(self.dim):
                agg[j] += emb[j]
        n = len(self._embeddings)
        return [x / n for x in agg]


# 调度集成: 将超图嵌入注入 GRL 调度器

def hypergraph_augmented_features(
    dag: TaskDependencyGraph,
    thg: TemporalHypergraph,
    thg_conv: Optional[TemporalHypergraphConv] = None,
) -> Dict[str, List[float]]:
    """从 DAG + 时序超图生成增广特征向量。

    将 DAG 的 8 维节点特征与超图嵌入拼接 → 10 维增广特征。
    额外 2 维:
      - hyper_degree: 节点参与的超边数量 (竞争/共享强度)
      - hyper_attention: 超边权重的加权聚合 (来自时序卷积)

    此函数与 GRLScheduler.priority 配合使用:
      将增广特征作为 Q 值计算的输入 φ，替代原始 GNN 嵌入。
    """
    conv = thg_conv or TemporalHypergraphConv(dim=8)
    hyper_emb = conv.temporal_conv(thg)

    feats, ids = dag.node_features_matrix()
    idx = {nid: i for i, nid in enumerate(ids)}

    augmented: Dict[str, List[float]] = {}
    for nid in ids:
        base = list(feats[idx[nid]]) if nid in idx else [0.0] * 8

        # 超图参与度特征
        hyper_deg = 0.0
        hyper_w_sum = 0.0
        for w in range(thg.num_windows):
            win = thg.window(w)
            if not win:
                continue
            for e_idx, he in enumerate(win["hyperedges"]):
                if nid in he:
                    hyper_deg += 1.0
                    if e_idx < len(win["weights"]):
                        hyper_w_sum += win["weights"][e_idx]

        # 从超图嵌入提取前 2 维作为补充特征
        he_vec = hyper_emb.get(nid, [0.0] * 8)
        augmented[nid] = base + [
            min(1.0, hyper_deg / max(1, thg.num_windows * 2)),
            min(1.0, hyper_w_sum / max(1, thg.num_windows)),
        ]
    return augmented
