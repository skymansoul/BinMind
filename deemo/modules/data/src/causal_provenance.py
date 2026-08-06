# 因果溯源分析: Katz中心性+反事实影响+攻击链重构+混淆因子检测
# 纯图算法, 零训练. 区别于 R-CAID(GNN), FALCON(transformer 联邦), SecTracer(SDN).
import math
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from .provenance import ProvenanceGraph, ProvNode, ProvEdge
from .analysis_types import CausalNodeScore, ChainStep, CausalAnalysis

class CausalProvenanceAnalyzer:
    """在 ProvenanceGraph 上叠加因果分析层.

    输入: ProvenanceGraph (来自 ProvenanceTracker)
    输出: 因果强度排序的节点列表, 攻击链路径, 混淆因子标记

    使用模式:
      tracker = ProvenanceTracker(db)
      graph = tracker.get_chain(sig_id)
      cpa = CausalProvenanceAnalyzer()
      analysis = cpa.analyze(graph)
      print(analysis.attack_chain)
    """

    def __init__(self, decay_factor: float = 0.5):
        # Katz 中心性的衰减因子: α < 1/λ_max 保证收敛
        self.alpha = decay_factor

    def analyze(self, graph: ProvenanceGraph) -> "CausalAnalysis":
        """主分析入口: 对 provenance graph 执行完整因果分析."""
        if graph.node_count == 0:
            return CausalAnalysis()

        nodes = list(graph._nodes.values())
        node_ids = [n.node_id for n in nodes]

        # 构建邻接矩阵 (稀疏表示) + 索引映射
        id_to_idx = {nid: i for i, nid in enumerate(node_ids)}
        idx_to_id = {i: nid for i, nid in enumerate(node_ids)}
        n = len(node_ids)

        adj_out: Dict[int, List[int]] = defaultdict(list)
        adj_in: Dict[int, List[int]] = defaultdict(list)
        for e in graph._edges:
            s_idx = id_to_idx.get(e.src)
            t_idx = id_to_idx.get(e.tgt)
            if s_idx is not None and t_idx is not None:
                adj_out[s_idx].append(t_idx)
                adj_in[t_idx].append(s_idx)

        # 1. 因果强度评分 (Katz 中心性)
        katz = self._katz_centrality(adj_out, adj_in, n)

        # 2. 反事实影响评分
        counterfactual = self._counterfactual_impact(adj_out, adj_in, n)

        # 3. 攻击链路径: 从最高因果强度的 activity 出发
        attack_chain = self._reconstruct_chain(
            nodes, katz, counterfactual, adj_out, adj_in,
            id_to_idx, idx_to_id
        )

        # 4. 混淆因子检测
        confounders = self._detect_confounders(adj_out, adj_in, n, idx_to_id)

        # 组装结果
        node_scores = []
        for i, node in enumerate(nodes):
            node_scores.append(CausalNodeScore(
                node_id=node.node_id,
                node_type=node.node_type,
                name=node.name,
                katz_centrality=round(katz[i], 6),
                counterfactual_impact=counterfactual[i],
                is_confounder=node.node_id in confounders,
            ))

        node_scores.sort(key=lambda x: x.katz_centrality, reverse=True)

        return CausalAnalysis(
            node_scores=node_scores,
            attack_chain=attack_chain,
            confounders=confounders,
            graph_summary={
                "nodes": n,
                "edges": graph.edge_count,
                "max_katz": round(max(katz), 6) if katz else 0,
                "max_impact": max(counterfactual) if counterfactual else 0,
            },
        )

    # ---- Katz 中心性: 加权路径计数, 远程依赖衰减更慢 ----

    def _katz_centrality(self, adj_out: Dict[int, List[int]],
                          adj_in: Dict[int, List[int]], n: int) -> List[float]:
        """Katz 中心性: x_i = α·Σ_j A_ji·x_j + β_i.

        用幂迭代求解, O(k·n·d̄) 其中 k 为迭代次数, d̄ 为平均度.
        β_i = 1 作为各节点的基线重要性.
        """
        if n == 0:
            return []
        katz = [1.0] * n
        for _ in range(20):  # 幂迭代, 收敛快 (20 轮足够)
            new_katz = [1.0] * n
            for i in range(n):
                contrib = 0.0
                # 入边贡献: 指向节点 i 的节点将自己的 katz 传递给 i
                for pred in adj_in.get(i, []):
                    contrib += katz[pred]
                new_katz[i] += self.alpha * contrib
            # 归一化避免溢出
            norm = math.sqrt(sum(v * v for v in new_katz))
            if norm > 0:
                new_katz = [v / norm for v in new_katz]
            # 收敛检查: 变化 < 1e-6
            delta = max(abs(new_katz[i] - katz[i]) for i in range(n))
            katz = new_katz
            if delta < 1e-6:
                break
        return katz

    # ---- 反事实影响: 移除节点后下游受影响节点数 ----

    def _counterfactual_impact(self, adj_out: Dict[int, List[int]],
                                adj_in: Dict[int, List[int]],
                                n: int) -> List[int]:
        """对每个节点计算反事实影响 = 移除后不可达的下游节点数.

        模拟每个节点的移除: BFS 从原始入口出发, 跳过目标节点,
        计算可达节点集合的缩减量. 对每个节点独立计算, O(n·(n+E)).
        """
        if n == 0:
            return []

        # 所有入口节点 (入度=0 或 entity 类型)
        entries = [i for i in range(n) if not adj_in.get(i)]

        impact = [0] * n
        for target in range(n):
            # 跳过入口节点: 移除入口意味着整个图不存在
            if target in entries:
                impact[target] = n
                continue

            # BFS 从入口出发, 跳过 target
            visited = set()
            queue = deque(entries)
            for e in entries:
                visited.add(e)

            while queue:
                cur = queue.popleft()
                if cur == target:
                    continue
                for nb in adj_out.get(cur, []):
                    if nb == target:
                        continue
                    if nb not in visited:
                        visited.add(nb)
                        queue.append(nb)

            impact[target] = n - len(visited)

        return impact

    # ---- 攻击链重构 ----

    def _reconstruct_chain(self, nodes: List[ProvNode],
                            katz: List[float], impact: List[int],
                            adj_out: Dict, adj_in: Dict,
                            id_to_idx: Dict, idx_to_id: Dict
                            ) -> List["ChainStep"]:
        """从最高因果得分的 activity 节点出发, 重构攻击步骤链.

        链 = 上游溯源 (used/wasDerivedFrom 回溯) +
             下游影响 (wasGeneratedBy 前向).
        各步骤按因果贡献排序.
        """
        if not nodes:
            return []

        # 识别种子节点: activity 类型中 katz 最高者
        activity_scores = [
            (i, katz[i]) for i, node in enumerate(nodes)
            if node.node_type == "activity"
        ]
        if not activity_scores:
            # 若无 activity, 取 katz 最高的任意节点
            activity_scores = [(i, katz[i]) for i in range(len(nodes))]

        activity_scores.sort(key=lambda x: x[1], reverse=True)
        seed_idx = activity_scores[0][0]

        # BFS 上游
        upstream = []
        visited = {seed_idx}
        queue = deque([seed_idx])
        while queue:
            cur = queue.popleft()
            upstream.append(cur)
            for pred in adj_in.get(cur, []):
                if pred not in visited:
                    visited.add(pred)
                    queue.append(pred)

        # BFS 下游
        downstream = []
        queue = deque([seed_idx])
        visited_ds = {seed_idx}
        while queue:
            cur = queue.popleft()
            if cur != seed_idx:
                downstream.append(cur)
            for succ in adj_out.get(cur, []):
                if succ not in visited_ds:
                    visited_ds.add(succ)
                    queue.append(succ)

        # 组合为有序链: 上游 (逆序) → seed → 下游 (顺序)
        chain = []
        # 上游: 从最远端到 seed
        upstream_order = list(reversed(upstream))  # seed 在最前
        for idx in upstream_order:
            node = nodes[idx]
            chain.append(ChainStep(
                node_id=node.node_id,
                node_type=node.node_type,
                name=node.name,
                causal_score=round(katz[idx], 6),
                impact=impact[idx],
                position="upstream" if idx != seed_idx else "seed",
            ))

        # 下游: 按 BFS 层序
        for idx in downstream:
            node = nodes[idx]
            chain.append(ChainStep(
                node_id=node.node_id,
                node_type=node.node_type,
                name=node.name,
                causal_score=round(katz[idx], 6),
                impact=impact[idx],
                position="downstream",
            ))

        return chain

    # ---- 混淆因子检测 ----

    def _detect_confounders(self, adj_out: Dict[int, List[int]],
                             adj_in: Dict[int, List[int]], n: int,
                             idx_to_id: Dict[int, str]) -> Set[str]:
        """检测混淆因子: 出度 >= 3 且下游节点位于不同子图的节点.

        在 exploit chain 语境中, 混淆因子是同时影响多个独立
        分析路径的共同输入或工具 (如共享的 libc 识别结果).
        """
        confounders = set()
        for node_idx in range(n):
            children = adj_out.get(node_idx, [])
            if len(children) < 3:
                continue

            # 检测子节点是否分散在不同连通分量中
            # 构建子节点间的无向可达性 (在跳过父节点的情况下)
            child_sets = self._connected_components_skipping(
                children, adj_out, node_idx
            )
            if len(child_sets) >= 2:
                confounders.add(idx_to_id[node_idx])

        return confounders

    def _connected_components_skipping(self, nodes: List[int],
                                        adj_out: Dict, skip: int
                                        ) -> List[Set[int]]:
        """在跳过 skip 节点后, 计算 nodes 中各节点的连通分量."""
        node_set = set(nodes)
        visited = set()
        components = []

        for start in nodes:
            if start in visited:
                continue
            comp = set()
            queue = deque([start])
            while queue:
                cur = queue.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                comp.add(cur)
                for nb in adj_out.get(cur, []):
                    if nb != skip and nb in node_set and nb not in visited:
                        queue.append(nb)
            components.append(comp)

        return components

__all__ = ["CausalProvenanceAnalyzer"]
