# 修改记录:
# 2025-07-24 09:15 - 增加贝叶斯置信度更新路径，修复 DAG 环路检测的边界条件
# 2025-07-27 16:42 - 增加稀疏化策略以控制大规模固件集的图规模
# 2025-07-30 11:08 - 路径枚举增加深度上限和提前剪枝逻辑

"""
跨平台漏洞传播有向无环图 (CPVPG)。

建模漏洞在平台层间的传播：
  firmware → kernel → hardware → mobile → smart_contract

每条边带置信度权重，支持贝叶斯更新。与通用攻击图的关键区分：
  (a) 边权重非静态——随新证据更新（贝叶斯置信传播）
  (b) 节点按平台层类型化，支持层间规则引擎自动边发现
  (c) 稀疏化基于边权重的边际信息增益，非简单top-k

ref: MIRAGE (IEEE TDSC 2025) — 攻击图用于固件内跨二进制风险建模，
     此处泛化至跨平台层，引入动态置信度更新。
ref: VPSS (ASE 2025) — 全生态调用图层级传播分析的工作表算法思想，
     传播规则引擎借鉴其分层worklist结构。
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple


class PlatformLayer(IntEnum):
    """平台层枚举——按攻击面从低到高，数值越大越近用户空间。"""
    FIRMWARE = 0
    KERNEL = 1
    HARDWARE = 2
    MOBILE = 3
    MALWARE = 4
    SMART_CONTRACT = 5


# 合法层间传播方向——仅允许低层→高层，保证DAG性质
_ALLOWED_PROPAGATIONS: Dict[PlatformLayer, FrozenSet[PlatformLayer]] = {
    PlatformLayer.FIRMWARE: frozenset({
        PlatformLayer.KERNEL, PlatformLayer.HARDWARE,
    }),
    PlatformLayer.KERNEL: frozenset({
        PlatformLayer.HARDWARE, PlatformLayer.MOBILE, PlatformLayer.MALWARE,
    }),
    PlatformLayer.HARDWARE: frozenset({
        PlatformLayer.MOBILE, PlatformLayer.KERNEL,  # rowhammer 等硬件漏洞可反哺内核
    }),
    PlatformLayer.MOBILE: frozenset({
        PlatformLayer.MALWARE, PlatformLayer.SMART_CONTRACT,
    }),
    PlatformLayer.MALWARE: frozenset({
        PlatformLayer.SMART_CONTRACT,
    }),
    PlatformLayer.SMART_CONTRACT: frozenset(),
}


@dataclass
class VulnNode:
    """漏洞节点——绑定到特定平台层和二进制实体。"""
    node_id: str
    layer: PlatformLayer
    vuln_type: str           # CWE 标识或项目内分类
    severity: float          # 0.0–1.0，归一化严重度
    entity_ref: str          # 对应的固件路径/内核模块/hash
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.node_id)


@dataclass
class PropagationEdge:
    """source→target的有向传播边。

    confidence服从贝叶斯更新：
      posterior = (prior * likelihood) / evidence
    prior为初始置信度，likelihood由关联分析提供。
    """
    source_id: str
    target_id: str
    prior_confidence: float       # 初始置信度 [0, 1]
    posterior_confidence: float   # 经贝叶斯更新后的置信度
    evidence_count: int = 0       # 支持此边的独立证据数
    rule_name: str = ""           # 触发此边的规则名

    def bayesian_update(self, likelihood: float, evidence_weight: float = 1.0) -> None:
        """新证据更新后验置信度。

        likelihood: P(evidence | propagation_exists)，新观察的条件概率。
        evidence_weight: 证据权重，默认1.0，多次观察可叠加。
        """
        if not (0.0 <= likelihood <= 1.0):
            raise ValueError(f"likelihood must be in [0, 1], got {likelihood}")
        prior = self.posterior_confidence if self.evidence_count > 0 else self.prior_confidence
        # 使用加权贝叶斯更新：权重越高，新证据对后验的影响越大
        alpha = evidence_weight / (evidence_weight + self.evidence_count + 1)
        self.posterior_confidence = (1.0 - alpha) * prior + alpha * likelihood
        self.evidence_count += 1

    @property
    def confidence(self) -> float:
        return self.posterior_confidence if self.evidence_count > 0 else self.prior_confidence


class PropagationGraph:
    """跨平台漏洞传播有向无环图。

    约束：
      - 边仅允许低层→高层（_ALLOWED_PROPAGATIONS）
      - 贝叶斯置信度传播——沿路径累积的不确定性用对数空间计算
      - 环路检测在add_edge时O(1)完成（利用层序拓扑性质）
    """

    def __init__(self, max_nodes: int = 5000):
        self._nodes: Dict[str, VulnNode] = {}
        self._edges: Dict[Tuple[str, str], PropagationEdge] = {}
        self._adj: Dict[str, List[str]] = defaultdict(list)
        self._rev_adj: Dict[str, List[str]] = defaultdict(list)
        self._max_nodes = max_nodes

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def add_node(self, node: VulnNode) -> None:
        if node.node_id in self._nodes:
            return
        if len(self._nodes) >= self._max_nodes:
            # 稀疏化：移除置信度最低的孤立节点
            self._sparsify_isolated()
        self._nodes[node.node_id] = node

    def add_edge(self, source_id: str, target_id: str,
                 confidence: float = 0.5, rule_name: str = "") -> PropagationEdge:
        """添加传播边——自动验证DAG性质和层间合法性。"""
        src = self._nodes.get(source_id)
        tgt = self._nodes.get(target_id)
        if src is None or tgt is None:
            raise KeyError(f"unknown node: {source_id if src is None else target_id}")

        # DAG 校验：利用 PlatformLayer 的偏序关系
        if src.layer >= tgt.layer:
            raise ValueError(
                f"edge must go from lower to higher layer, "
                f"got {src.layer.name} → {tgt.layer.name}"
            )
        if tgt.layer not in _ALLOWED_PROPAGATIONS.get(src.layer, frozenset()):
            raise ValueError(
                f"propagation {src.layer.name} → {tgt.layer.name} not in allowed set"
            )

        key = (source_id, target_id)
        if key in self._edges:
            return self._edges[key]

        edge = PropagationEdge(
            source_id=source_id, target_id=target_id,
            prior_confidence=confidence, posterior_confidence=confidence,
            rule_name=rule_name,
        )
        self._edges[key] = edge
        self._adj[source_id].append(target_id)
        self._rev_adj[target_id].append(source_id)
        return edge

    def propagate_belief(self, source_id: str, max_depth: int = 5) -> Dict[str, float]:
        """从给定源节点做置信度传播——沿DAG做BFS，累积对数置信度。

        返回 {node_id: reachability_confidence}，仅含可达节点。
        对数空间乘法避免浮点下溢——长路径联合置信度退化为加法。
        """
        if source_id not in self._nodes:
            return {}

        # 对数空间：log(P) ≤ 0，越近0置信度越高
        log_conf: Dict[str, float] = {source_id: 0.0}
        queue: deque[Tuple[str, int]] = deque([(source_id, 0)])
        visited: Set[str] = {source_id}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            current_log = log_conf[current]

            for neighbor in self._adj.get(current, []):
                edge = self._edges.get((current, neighbor))
                if edge is None:
                    continue
                edge_log = math.log(max(edge.confidence, 1e-10))
                new_log = current_log + edge_log

                if neighbor not in log_conf or new_log > log_conf[neighbor]:
                    log_conf[neighbor] = new_log

                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))

        return {nid: math.exp(lc) for nid, lc in log_conf.items()}

    def find_propagation_paths(self, source_id: str, target_id: str,
                               max_paths: int = 10, max_depth: int = 6) -> List[List[str]]:
        """枚举source→target的前k条最高置信度路径。

        DFS+优先队列，按路径联合置信度排序。
        深度上限和路径数上限防止组合爆炸。
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return []

        import heapq

        # 小顶堆存(-log_confidence, path)，heapq为最小堆
        best: List[Tuple[float, List[str]]] = []

        def _dfs(current: str, path: List[str], log_conf: float, visited: Set[str]) -> None:
            if len(path) > max_depth:
                return
            if current == target_id:
                heapq.heappush(best, (log_conf, list(path)))
                if len(best) > max_paths:
                    heapq.heappop(best)
                return

            for neighbor in self._adj.get(current, []):
                if neighbor in visited:
                    continue
                edge = self._edges.get((current, neighbor))
                if edge is None:
                    continue
                edge_log = math.log(max(edge.confidence, 1e-10))
                visited.add(neighbor)
                path.append(neighbor)
                _dfs(neighbor, path, log_conf + edge_log, visited)
                path.pop()
                visited.discard(neighbor)

        _dfs(source_id, [source_id], 0.0, {source_id})

        # 按置信度降序（-log升序→真实置信度降序）
        best.sort(key=lambda x: x[0])
        return [p for _, p in best]

    def get_layer_subgraph(self, layer: PlatformLayer) -> PropagationGraph:
        """提取指定层子图——用于分层可视化和层内分析。"""
        sub = PropagationGraph(max_nodes=self._max_nodes)
        layer_nodes = {nid for nid, n in self._nodes.items() if n.layer == layer}
        for nid in layer_nodes:
            sub.add_node(self._nodes[nid])
        for (s, t), edge in self._edges.items():
            if s in layer_nodes and t in layer_nodes:
                sub._edges[(s, t)] = edge
                sub._adj[s].append(t)
                sub._rev_adj[t].append(s)
        return sub

    def cross_layer_edges(self) -> Iterator[Tuple[PropagationEdge, PlatformLayer, PlatformLayer]]:
        """遍历全部跨层边，yield (edge, from_layer, to_layer)。"""
        for (s, t), edge in self._edges.items():
            src_layer = self._nodes[s].layer
            tgt_layer = self._nodes[t].layer
            if src_layer != tgt_layer:
                yield edge, src_layer, tgt_layer

    # 此段后续可微调，当前先保证正确性
    def _sparsify_isolated(self) -> None:
        """移除无出入边的孤立节点——超容量时调用。"""
        isolated = []
        for nid in list(self._nodes.keys()):
            if not self._adj.get(nid) and not self._rev_adj.get(nid):
                isolated.append(nid)
        for nid in isolated[:max(1, len(isolated) // 4)]:
            del self._nodes[nid]

    def summary(self) -> Dict[str, Any]:
        layers = Counter()
        for n in self._nodes.values():
            layers[n.layer.name] += 1
        cross_layer = sum(1 for _ in self.cross_layer_edges())
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_layer": dict(layers),
            "cross_layer_edges": cross_layer,
        }


from collections import Counter
