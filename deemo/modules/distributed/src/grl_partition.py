# GRL-Sched 第二层: 动态图划分 (GraphPartitioner)
#
# 论文对应: GraphEdge: Dynamic Graph Partition and Task Scheduling for GNNs
#   Computing in Edge Network — arXiv:2504.15905 [待验证]
#   GraphEdge 对 GNN 计算图做多级划分，使子图落到不同边缘设备并行执行，
#   拓扑变化 (算子增删/边重连) 时在线重划分，控制迁移成本。
#   本模块移植同一目标: 最小化割边 (通信代价) 同时维持负载均衡。
#
# 算法管线 (对应 METIS/Chaco 的多级划分框架):
#   1. 初始划分 _layer_initial — 按层级 round-robin，层内并行、层间通信
#   2. 细化 _kernighan_lin — Kernighan-Lin 局部交换降低割边，带平衡约束
#   3. 在线重划分 repartition — 仅对受影响邻域重排，复用未变化节点的归属
#
# 边界条件:
#   - n_partitions <= 1 或 节点数 < 分区数 时退化为平凡划分
#   - node_loads 由外部注入 (如 NodeRegistry.get_available_nodes 的负载)，缺省按节点数均衡

from __future__ import annotations

import math
import random
from typing import Optional, List, Dict, Any

from .grl_graph import TaskDependencyGraph


class Partition:
    """划分结果 — assignments: node_id → partition_id (0..n_partitions-1)。"""

    __slots__ = ("assignments", "n_partitions")

    def __init__(self, assignments: Dict[str, int], n_partitions: int):
        self.assignments: Dict[str, int] = dict(assignments)
        self.n_partitions: int = n_partitions

    def node_partition(self, node_id: str) -> int:
        return self.assignments.get(node_id, 0)

    def partition_nodes(self, pid: int) -> List[str]:
        return [n for n, p in self.assignments.items() if p == pid]

    def to_dict(self) -> dict:
        return {"n_partitions": self.n_partitions, "assignments": dict(self.assignments)}

    @classmethod
    def from_dict(cls, d: dict) -> "Partition":
        return cls(dict(d.get("assignments", {})), int(d.get("n_partitions", 1)))

    def __repr__(self) -> str:
        dist: Dict[int, int] = {}
        for p in self.assignments.values():
            dist[p] = dist.get(p, 0) + 1
        return f"Partition(parts={self.n_partitions}, dist={dist})"


class GraphPartitioner:
    """动态图划分器 — 最小化割边 (通信) 且保持负载均衡。

    线程安全: 单次划分调用不共享可变状态 (仅用 _rng)，
    并发调用建议各自持有实例或加外部锁。
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    # ---- 主入口 ----

    def partition(self, dag: TaskDependencyGraph, n_partitions: int,
                  node_loads: Optional[Dict[str, float]] = None,
                  max_passes: int = 4) -> Partition:
        """整体划分。node_loads: 节点负载估计 (缺省按 1.0)。

        返回 Partition；重复调用结果确定性由 seed 保证。
        """
        n_p = max(1, n_partitions)
        ids = dag.node_ids
        if n_p <= 1:
            return Partition({n: 0 for n in ids}, 1)
        if len(ids) < n_p:
            # 节点数不足时分到不同分区意义有限 — 按插入序轮询
            return Partition({n: i % n_p for i, n in enumerate(ids)}, n_p)

        loads = node_loads or {}
        initial = self._layer_initial(dag, n_p, loads)
        refined = self._kernighan_lin(dag, initial, n_p, loads, max_passes)
        return Partition(refined, n_p)

    def repartition(self, dag: TaskDependencyGraph, old: Partition,
                    n_partitions: int,
                    node_loads: Optional[Dict[str, float]] = None,
                    changed_nodes: Optional[set] = None) -> Partition:
        """在线重划分 — 拓扑/负载变化时的增量更新。

        changed_nodes: 新增/删除/负载突变的节点集合；None 表示全量重划。
        策略 (GraphEdge 的增量重划分思想):
          1. 删除图中已不存在的节点归属
          2. 新增节点落入当前最空分区
          3. 以 changed_nodes 的入/出邻居圈定候选集，仅对候选集做单遍 KL 细化
        未受影响节点归属保持不变 → 迁移成本 = 受影响邻域大小。
        """
        n_p = max(1, n_partitions)
        ids = dag.node_ids
        if n_p <= 1:
            return Partition({n: 0 for n in ids}, 1)

        assignments = dict(old.assignments)
        current = set(ids)
        # 1) 清理已删除节点
        for nid in list(assignments.keys()):
            if nid not in current:
                del assignments[nid]
        # 2) 新增节点 → 最空分区 (就地重算计数，避免维持状态)
        for nid in ids:
            if nid not in assignments:
                assignments[nid] = self._least_loaded_partition(assignments, n_p)
        # 3) 候选集 = 变化节点 + 其直接前驱/后继 (影响域的 1-hop 闭包)
        if changed_nodes is None:
            candidate = set(current)
        else:
            candidate = set(changed_nodes)
            for nid in list(candidate):
                candidate.update(dag.predecessors(nid))
                candidate.update(dag.successors(nid))
            candidate &= current
        refined = self._kl_pass(dag, assignments, n_p,
                                loads=node_loads or {}, allowed_to_move=candidate)
        return Partition(refined, n_p)

    # ---- 初始划分 ----

    def _trivial(self, dag: TaskDependencyGraph, n_p: int) -> Dict[str, int]:
        return {n: i % n_p for i, n in enumerate(dag.node_ids)}

    def _least_loaded_partition(self, assignments: Dict[str, int], n_p: int) -> int:
        counts = [0] * n_p
        for p in assignments.values():
            counts[p] += 1
        return min(range(n_p), key=lambda p: (counts[p], p))

    def _layer_initial(self, dag: TaskDependencyGraph, n_p: int,
                       loads: Dict[str, float]) -> Dict[str, int]:
        """按层级初始划分。

        同一 level 的节点相互独立 (无路径依赖) → 分散到不同分区最大化并行；
        跨层边自然成为割边，对应 GraphEdge 中层间张量传输。
        分区负载累计选最轻者，使初始解已接近均衡。
        """
        level = dag.levels()
        by_level: Dict[int, List[str]] = {}
        for nid in dag.node_ids:
            by_level.setdefault(level[nid], []).append(nid)

        assignments: Dict[str, int] = {}
        part_load = [0.0] * n_p
        for lv in sorted(by_level.keys()):
            for nid in by_level[lv]:
                # 最轻分区 + 极小随机扰动避免同层平局抖动
                p = min(range(n_p),
                        key=lambda x: part_load[x] + self._rng.random() * 1e-6)
                assignments[nid] = p
                part_load[p] += loads.get(nid, 1.0)
        return assignments

    # ---- Kernighan-Lin 细化 ----

    def _kernighan_lin(self, dag: TaskDependencyGraph, assignments: Dict[str, int],
                       n_p: int, loads: Dict[str, float], max_passes: int) -> Dict[str, int]:
        """KL 局部搜索: 每 pass 对所有节点做一次最陡下降单点移动。

        停止条件: 连续 pass 未降低总割边。
        平衡约束在 _kl_pass 内按分区容量上限强制。
        """
        result = dict(assignments)
        for _ in range(max_passes):
            improved = self._kl_pass(dag, result, n_p, loads=loads,
                                     allowed_to_move=None)
            if self._cut_weight(dag, improved) >= self._cut_weight(dag, result):
                break
            result = improved
        return result

    def _kl_pass(self, dag: TaskDependencyGraph, assignments: Dict[str, int],
                 n_p: int, loads: Dict[str, float],
                 allowed_to_move: Optional[set]) -> Dict[str, int]:
        """经典 Kernighan-Lin 单遍: 序列移动 + 最佳平衡前缀回退。

        与传统 KL 一致，算法允许在序列中间经过不平衡状态以跳出局部最优，
        结束时回退到「累计收益最大且满足平衡约束」的前缀。
        平衡约束 (METIS 的 ε 松弛思想):
          - 源分区移出后 ≥ min_sz (min_sz 保证分区不空)
          - 目标分区移入后 ≤ max_sz (max_sz 防止坍缩为单分区集中)
        min_sz/max_sz 取 floor/ceil(target)±1，使均衡度有界而保留搜索空间。

        贪心收益 = -_move_delta (割边下降量为正)。移动节点加锁 (KL 的锁定集)，
        保证每个节点至多移动一次，序列长度 ≤ 可移动节点数。
        """
        result = dict(assignments)
        ids = dag.node_ids
        counts = [0] * n_p
        for nid in ids:
            counts[result[nid]] += 1
        target = len(ids) / n_p if n_p else 1.0
        min_sz = max(1, int(target) - 1)
        max_sz = math.ceil(target) + 1

        moveable = [
            nid for nid in ids
            if allowed_to_move is None or nid in allowed_to_move
        ]
        locked = set()
        cur = dict(result)
        cum_gain = 0.0
        best_cum = 0.0
        best_snapshot: Optional[Dict[str, int]] = None

        for _ in range(len(moveable)):
            best_nid, best_dst, best_gain = None, None, 0.0
            for nid in moveable:
                if nid in locked:
                    continue
                src = cur[nid]
                for dst in range(n_p):
                    if dst == src:
                        continue
                    if counts[src] - 1 < min_sz:
                        continue
                    if counts[dst] + 1 > max_sz:
                        continue
                    g = -self._move_delta(dag, cur, nid, src, dst)
                    if g > best_gain:
                        best_gain, best_nid, best_dst = g, nid, dst
            if best_nid is None:
                break
            src = cur[best_nid]
            cur[best_nid] = best_dst
            counts[src] -= 1
            counts[best_dst] += 1
            locked.add(best_nid)
            cum_gain += best_gain
            # 仅接受满足平衡约束的前缀
            if all(min_sz <= c <= max_sz for c in counts) and cum_gain > best_cum:
                best_cum = cum_gain
                best_snapshot = dict(cur)

        if best_snapshot is not None:
            return best_snapshot
        return result

    def _move_delta(self, dag: TaskDependencyGraph, assignments: Dict[str, int],
                    nid: str, src_p: int, dst_p: int) -> float:
        """把 nid 从 src_p 移到 dst_p 的割边权重增量 (负 = 更优)。"""
        delta = 0.0
        for e in dag._out[nid]:
            ep = assignments[e.dst]
            if ep == src_p:
                delta += e.comm_cost   # 内部边 → 割边
            elif ep == dst_p:
                delta -= e.comm_cost   # 割边 → 内部边
        for e in dag._in[nid]:
            ep = assignments[e.src]
            if ep == src_p:
                delta += e.comm_cost
            elif ep == dst_p:
                delta -= e.comm_cost
        return delta

    # ---- 评估 ----

    def _cut_weight(self, dag: TaskDependencyGraph, assignments: Dict[str, int]) -> float:
        """总割边权重 — 跨分区边的 comm_cost 之和，即通信总代价。"""
        cut = 0.0
        for nid in dag.node_ids:
            p = assignments[nid]
            for e in dag._out[nid]:
                if assignments.get(e.dst, -1) != p:
                    cut += e.comm_cost
        return cut

    def balance(self, dag: TaskDependencyGraph, assignments: Dict[str, int],
                n_p: int, loads: Optional[Dict[str, float]] = None) -> float:
        """负载均衡度 = 最重分区负载 / 平均分区负载 (1.0 为理想)。"""
        part_load = [0.0] * n_p
        for nid in dag.node_ids:
            part_load[assignments[nid]] += (loads or {}).get(nid, 1.0)
        avg = sum(part_load) / n_p if n_p else 1.0
        mx = max(part_load) if part_load else 0.0
        return mx / avg if avg > 0 else 1.0

    def evaluate(self, dag: TaskDependencyGraph, partition: Partition,
                 loads: Optional[Dict[str, float]] = None) -> dict:
        """划分质量报告 — 割边权重/割边数/均衡度/分布。"""
        assign = partition.assignments
        cut_edges = 0
        for nid in dag.node_ids:
            p = assign[nid]
            for e in dag._out[nid]:
                if assign.get(e.dst, -1) != p:
                    cut_edges += 1
        return {
            "n_partitions": partition.n_partitions,
            "cut_weight": self._cut_weight(dag, assign),
            "cut_edges": cut_edges,
            "balance": self.balance(dag, assign, partition.n_partitions, loads),
            "distribution": {
                p: partition.partition_nodes(p) for p in range(partition.n_partitions)
            },
        }
