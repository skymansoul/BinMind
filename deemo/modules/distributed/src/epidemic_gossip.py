# 流行病源检测的 Gossip 协议 — 状态传播起源追踪
#
# node_registry.py 的 GossipDiscovery 通过 SWIM 协议传播节点状态。
# SWIM 能告诉你 "哪些节点失效了" 但无法回答 "失效消息从哪个节点
# 首次发出"——即流行病学中的零号病人 (patient zero) 问题。
#
# 在调度场景中，起源追踪用于:
#   - 熔断传播溯源: 哪个节点的故障首先触发了级联熔断?
#   - 配置漂移检测: 哪个节点首先引入了错误的调度配置?
#   - 负载异常定位: 负载飙升从哪个节点开始扩散?
#
# 方法: 基于谣言中心性 (Rumor Centrality) 的极大似然估计。
# Shah & Zaman (2011) 证明在树上，零号病人是谣言中心性最大
# 的节点。谣言中心性 = 以该节点为根的传播树的不同拓扑序数。
# 在一般图上用 BFS 生成树近似。
#
# 本模块在每个 gossip 消息中嵌入轻型传播链 (最近 K 跳),
# 接收方增量更新局部传播图，周期性运行溯源算法。

from __future__ import annotations

import math
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple


@dataclass
class GossipTrace:
    """一次 gossip 传播的追踪记录。"""
    message_id: str
    origin_node: str           # 消息创建者 (声称)
    propagation_path: List[str] # 最近 K 跳的传播路径
    state_key: str             # 状态键 (e.g. "node_status:node_X")
    state_value: str
    timestamp: float


class EpidemicSourceDetector:
    """流行病源检测器 — 谣言中心性驱动的起源定位。

    维护局部传播图 G = (V, E)，边=传播关系 (谁传给谁)。
    溯源: 计算每个节点的谣言中心性，排序输出候选。
    """

    def __init__(self, max_path_len: int = 8, window_s: float = 300.0):
        self._max_path = max_path_len
        self._window = window_s
        # 传播图: adjacency (parent → children)
        self._graph: Dict[str, Set[str]] = defaultdict(set)
        # 最近追踪
        self._traces: deque = deque(maxlen=500)
        self._lock = threading.Lock()

    def record_propagation(self, trace: GossipTrace):
        """记录一次传播事件 → 更新传播图。"""
        with self._lock:
            self._traces.append(trace)
            path = trace.propagation_path
            for i in range(len(path) - 1):
                self._graph[path[i]].add(path[i + 1])
            # 清理过期边
            now = time.monotonic()
            self._prune(now)

    def _prune(self, now: float):
        """清理窗口外的旧追踪。"""
        cutoff = now - self._window
        while self._traces and self._traces[0].timestamp < cutoff:
            self._traces.popleft()

    def detect_source(self, state_key: str) -> List[Tuple[str, float]]:
        """对指定状态键的传播溯源 — 返回 [(node_id, centrality_score)]。

        谣言中心性: 以该节点为根的 BFS 生成树上，消息传播的不同
        拓扑序的数量。对数尺度: log R(v, G) ≈ Σ_u≠v log(depth(u))。
        """
        with self._lock:
            # 获取涉及 state_key 的所有节点
            involved: Set[str] = set()
            for trace in self._traces:
                if trace.state_key == state_key:
                    involved.add(trace.origin_node)
                    involved.update(trace.propagation_path)

            if not involved:
                return []

            # 对每个候选节点做 BFS → 计算近似谣言中心性
            scores = []
            for candidate in involved:
                centrality = self._rumor_centrality(candidate, involved)
                scores.append((candidate, centrality))

            scores.sort(key=lambda x: -x[1])
            return scores[:5]

    def _rumor_centrality(self, root: str,
                          nodes: Set[str]) -> float:
        """近似谣言中心性 — BFS 生成树上的对数拓扑序数。

        log R(v, T) = Σ_u≠v log(size(subtree(u)))
        其中 subtree(u) 是以 u 为根的 BFS 子树大小。
        """
        # BFS 生成树
        parent: Dict[str, Optional[str]] = {root: None}
        level: Dict[str, int] = {root: 0}
        queue = deque([root])
        while queue:
            u = queue.popleft()
            for v in self._graph.get(u, set()):
                if v in nodes and v not in parent:
                    parent[v] = u
                    level[v] = level[u] + 1
                    queue.append(v)

        # 自底向上计算子树大小
        size: Dict[str, int] = {v: 1 for v in parent}
        for v in sorted(parent, key=lambda x: -level.get(x, 0)):
            p = parent[v]
            if p is not None:
                size[p] = size.get(p, 0) + size[v]

        # log R = Σ log(size(v))
        log_r = 0.0
        for v in parent:
            if v != root and size.get(v, 0) > 0:
                log_r += math.log(size[v])
        return log_r

    def propagation_stats(self) -> dict:
        with self._lock:
            return {
                "graph_nodes": len(self._graph),
                "graph_edges": sum(len(v) for v in self._graph.values()),
                "traces_recorded": len(self._traces),
            }
