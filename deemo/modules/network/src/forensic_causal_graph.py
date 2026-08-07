# 轻量级法庭因果事件图 —— 从孤立流告警重构攻击证据链。
# 用时序优先+资源共享推断因果边, 零ML/SDN/LLM依赖。
# 与GRAIN(GNN+RL)/GenDFIR(LLM+RAG)/SecTracer(SDN来源图)互补。

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 衰减常数(秒): 两事件间隔超过此值, 时序因果权重衰减至1/e
_TAU_DECAY = 300.0
# 因果边最小强度阈值 —— 低于此值视为噪声边, 不加入图
_MIN_CAUSAL_STRENGTH = 0.15


@dataclass
class ForensicEvent:
    """法庭事件 —— event_id由类型+流键哈希确定"""
    event_id: str
    event_type: str      # "beacon" / "exfiltration" / "port_mismatch" / "custom"
    timestamp: float     # epoch seconds, 取关联流的最小start_ts
    end_timestamp: float = 0.0
    resources: Set[str] = field(default_factory=set)
    # 资源: {IP地址, 端口号, 协议} 的字符串表示
    flow_keys: List[Tuple] = field(default_factory=list)
    severity: float = 0.0     # [0,1]
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CausalEdge:
    """因果边 —— 从源事件到目标事件的因果关系"""
    source_id: str
    target_id: str
    strength: float           # [0,1] 因果强度
    temporal_score: float     # 时序接近度分量
    resource_score: float     # 资源共享度分量
    pattern_score: float      # 攻击模式模板匹配分量


@dataclass
class EvidenceChain:
    """证据链 —— 一条从根因到最终影响的因果路径"""
    events: List[str]         # 按时间排序的event_id序列
    total_strength: float     # 路径上所有边强度的几何均值
    length: int
    root_cause_event: str     # 链中最靠前的事件(因果源头)
    root_cause_score: float   # 根因的因果中心性


@dataclass
class ForensicCausalReport:
    """法庭因果分析完整报告"""
    events: List[ForensicEvent]
    edges: List[CausalEdge]
    evidence_chains: List[EvidenceChain]
    root_cause_ranking: List[Tuple[str, float]]  # (event_id, centrality)
    total_events: int
    total_edges: int
    graph_density: float


# 已知攻击模式模板 —— 特定事件类型序对具有先验因果关联
# 权重来自MITRE ATT&CK和公开APT报告中的阶段转移统计
_ATTACK_PATTERNS: Dict[Tuple[str, str], float] = {
    ("beacon", "exfiltration"): 0.8,       # C2信标→数据外泄
    ("port_mismatch", "beacon"): 0.5,      # 非标端口→C2
    ("port_mismatch", "exfiltration"): 0.4, # 非标端口→外泄
    ("beacon", "beacon"): 0.3,             # 多阶段C2
    ("exfiltration", "exfiltration"): 0.6, # 分批外泄
}


class ForensicCausalGraph:
    """法庭因果图构造器。O(N²)事件对, N≤500可行。

    因果边=时序优先+资源交集+模式模板, 强度≥阈值才保留。
    """

    def __init__(self, tau_decay: float = _TAU_DECAY,
                 min_strength: float = _MIN_CAUSAL_STRENGTH):
        self._tau = tau_decay
        self._min_strength = min_strength

    def build(self, events: List[ForensicEvent]) -> ForensicCausalReport:
        """从事件列表构造因果图并抽取证据链。"""
        if len(events) < 2:
            return ForensicCausalReport(
                events=events, edges=[],
                evidence_chains=[], root_cause_ranking=[],
                total_events=len(events), total_edges=0,
                graph_density=0.0)

        # 按时序排序
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # 构建因果边
        edges, adj = self._build_causal_edges(sorted_events)

        # 计算因果中心性(eigenvector-like)
        centrality = self._causal_centrality(sorted_events, adj)

        # 抽取最大权重证据链
        chains = self._extract_chains(sorted_events, adj, centrality)

        # 根因排序
        ranking = sorted(centrality.items(), key=lambda x: -x[1])

        n = len(sorted_events)
        e = len(edges)
        max_edges = n * (n - 1)
        density = e / max(1, max_edges)

        return ForensicCausalReport(
            events=sorted_events, edges=edges,
            evidence_chains=chains,
            root_cause_ranking=[(eid, round(sc, 5)) for eid, sc in ranking[:10]],
            total_events=n, total_edges=e,
            graph_density=round(density, 4),
        )

    def _build_causal_edges(self, events: List[ForensicEvent]
                             ) -> Tuple[List[CausalEdge],
                                        Dict[str, List[Tuple[str, float]]]]:
        edges: List[CausalEdge] = []
        adj: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

        for i, src in enumerate(events):
            for j in range(i + 1, len(events)):
                tgt = events[j]
                # 时序优先: src必须在tgt之前
                dt = tgt.timestamp - src.timestamp
                if dt <= 0:
                    continue

                # 时序接近度: 指数衰减
                temporal = math.exp(-dt / self._tau)

                # 资源共享度: Jaccard系数
                s_res = src.resources or set()
                t_res = tgt.resources or set()
                union = len(s_res | t_res)
                if union == 0:
                    continue
                resource = len(s_res & t_res) / union

                # 无法共享任何资源 → 虽有时序但非因果
                if resource < 0.05:
                    continue

                # 攻击模式模板匹配
                pattern = _ATTACK_PATTERNS.get(
                    (src.event_type, tgt.event_type), 0.0)

                # 因果强度: 加权组合
                strength = (0.40 * temporal +
                           0.35 * resource +
                           0.25 * pattern)

                if strength < self._min_strength:
                    continue

                edge = CausalEdge(
                    source_id=src.event_id,
                    target_id=tgt.event_id,
                    strength=round(strength, 4),
                    temporal_score=round(temporal, 4),
                    resource_score=round(resource, 4),
                    pattern_score=round(pattern, 4),
                )
                edges.append(edge)
                adj[src.event_id].append((tgt.event_id, strength))

        return edges, adj

    def _causal_centrality(self, events: List[ForensicEvent],
                            adj: Dict[str, List[Tuple[str, float]]]
                            ) -> Dict[str, float]:
        """因果中心性: 加权特征向量中心性的迭代近似。

        入边权重越高的节点因果影响力越大(被更多前置事件指向)。
        同时考虑出边权重——既是"导致者"也是"被导致者"的事件
        (如C2中转节点)获得高分。

        对稀疏小图使用10次乘幂迭代, 精度/速度平衡。
        """
        n = len(events)
        if n == 0:
            return {}

        eid_to_idx = {e.event_id: i for i, e in enumerate(events)}
        scores = [1.0 / n] * n

        for _ in range(20):
            new_scores = [0.0] * n
            for src_id, targets in adj.items():
                src_idx = eid_to_idx.get(src_id)
                if src_idx is None:
                    continue
                for tgt_id, strength in targets:
                    tgt_idx = eid_to_idx.get(tgt_id)
                    if tgt_idx is None:
                        continue
                    # 入边贡献
                    new_scores[tgt_idx] += scores[src_idx] * strength
                    # 出边也贡献(双向因果性)
                    new_scores[src_idx] += scores[tgt_idx] * strength * 0.3

            norm = sum(new_scores) or 1.0
            new_scores = [s / norm for s in new_scores]

            max_diff = max(
                abs(new_scores[i] - scores[i]) for i in range(n))
            scores = new_scores
            if max_diff < 1e-5:
                break

        return {events[i].event_id: scores[i] for i in range(n)}

    def _extract_chains(self, events: List[ForensicEvent],
                         adj: Dict[str, List[Tuple[str, float]]],
                         centrality: Dict[str, float]
                         ) -> List[EvidenceChain]:
        """从因果图中抽取top-k证据链。

        对每个无入边的根节点做DFS, 收集到叶子节点的最大强度路径。
        最多返回10条链, 按总强度降序。
        """
        # 计算入度
        in_deg: Dict[str, int] = defaultdict(int)
        for src, targets in adj.items():
            for tgt_id, _ in targets:
                in_deg[tgt_id] += 1

        # 根节点: 入度=0
        roots = [e for e in events if in_deg.get(e.event_id, 0) == 0]
        if not roots:
            roots = events[:1]  # 兜底: 取最早事件

        chains: List[EvidenceChain] = []
        for root in roots[:5]:  # 最多5个根节点
            path = self._dfs_max_path(root.event_id, adj, centrality,
                                       set(), [], 1.0, 5)
            if path:
                chains.append(path)

        chains.sort(key=lambda c: -c.total_strength)
        return chains[:10]

    def _dfs_max_path(self, current: str,
                       adj: Dict[str, List[Tuple[str, float]]],
                       centrality: Dict[str, float],
                       visited: Set[str],
                       path: List[str],
                       strength_product: float,
                       max_depth: int
                       ) -> Optional[EvidenceChain]:
        if current in visited or max_depth <= 0:
            return None
        visited.add(current)
        path.append(current)

        next_nodes = sorted(adj.get(current, []),
                            key=lambda x: -x[1])  # 按边强度降序

        best_chain: Optional[EvidenceChain] = None

        if not next_nodes:
            # 叶子节点: 构建证据链
            root = path[0] if path else current
            best_chain = EvidenceChain(
                events=list(path),
                total_strength=round(strength_product, 4),
                length=len(path),
                root_cause_event=root,
                root_cause_score=round(centrality.get(root, 0.0), 4),
            )
        else:
            for tgt_id, strength in next_nodes[:3]:  # 每层最多探索3个分支
                sub = self._dfs_max_path(
                    tgt_id, adj, centrality, visited.copy(),
                    list(path), strength_product * strength, max_depth - 1)
                if sub and (best_chain is None or
                            sub.total_strength > best_chain.total_strength):
                    best_chain = sub

        return best_chain


__all__ = [
    "ForensicEvent", "CausalEdge", "EvidenceChain",
    "ForensicCausalReport", "ForensicCausalGraph",
]
