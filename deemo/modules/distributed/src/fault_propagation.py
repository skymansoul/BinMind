# 因果故障传播图 — 从熔断/背压信号中识别根因节点
#
# 目标：分布式系统中单节点故障会级联触发下游熔断器和背压，
# 仅凭告警无法区分根因与受害节点。本模块构建轻量因果传播图，
# 以干预主义因果推断 (IDI, arXiv:2505.00930 [待验证]) 的思想进行根因评分。
#
# IDI 加性噪声模型假设:
#   故障沿因果边（任务依赖边）传播。若父节点正常而子节点异常，
#   则故障源于子节点自身（干预该节点可消除异常）。
#   本模块简化：对每一异常节点 v，评分 = 自身异常度 - Σ(父节点异常度 * 衰减)
#   得分最高者 → 根因候选。
#
# 输入: 熔断器状态快照 (CircuitBreaker.to_dict) + 背压信号 (BackpressureSignal)
#       + 任务依赖图 (TaskDependencyGraph) 作为因果骨架
# 输出: 根因候选排序列表 + 故障影响子图

from __future__ import annotations

import time
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple

from .grl_graph import TaskDependencyGraph

# 故障沿依赖边每跳衰减系数（经验值，可经 RL 调优）
# 参考 DynaCausal (arXiv:2510.22613 [待验证]) 以 GAT 学习传播权重；此处固定值以保持零外部依赖
_PROPAGATION_DECAY = 0.65


@dataclass
class FaultSignal:
    """单节点故障信号 — 聚合熔断状态与背压信息。"""
    node_id: str
    # 熔断维度
    breaker_open: bool = False
    breaker_failure_rate: float = 0.0
    # 背压维度
    backpressure: float = 0.0       # composite_pressure ∈ [0,1]
    queue_pressure: float = 0.0
    # 观测时刻
    observed_at: float = field(default_factory=time.monotonic)

    @property
    def anomaly_score(self) -> float:
        """综合异常度 ∈ [0,1]。breaker_open 直接贡献 0.6 权重。"""
        brk = 0.6 if self.breaker_open else self.breaker_failure_rate * 0.3
        return min(1.0, brk + 0.4 * self.backpressure)


@dataclass
class RootCauseCandidate:
    """根因候选 — 按 rca_score 降序输出。"""
    node_id: str
    rca_score: float         # 干预评分，值越大越可能是根因
    anomaly_score: float     # 自身异常度
    propagation_score: float # 从父节点传入的异常量估算值
    affected_descendants: int
    is_isolated: bool = False # 异常但无异常父节点 → 高概率为根因


class FaultPropagationGraph:
    """因果故障传播图 — 熔断/背压事件的根因定位。

    构建步骤:
      1. 以 TaskDependencyGraph 为因果骨架（边方向 = 因果方向）
      2. 从异常节点集沿因果边回溯提取异常子图
      3. 对每个异常节点计算 IDI 风格的干预评分
      4. 输出根因排序 + 影响域

    线程安全: analyze() 为无状态纯函数，不持有可变共享状态。
    """

    def __init__(self, decay: float = _PROPAGATION_DECAY):
        self._decay = max(0.0, min(1.0, decay))

    def analyze(
        self,
        dag: TaskDependencyGraph,
        signals: Dict[str, FaultSignal],
        anomaly_threshold: float = 0.3,
    ) -> dict:
        """主入口 — 从信号集中提取根因。

        返回:
          root_causes: 根因候选列表（按 rca_score 降序）
          affected_subgraph: {node_id: 受影响深度}
          propagation_paths: 每条从根因出发的传播路径
        """
        if not signals:
            return {"root_causes": [], "affected_subgraph": {}, "propagation_paths": []}

        # 1. 标记异常节点
        anomalous: Set[str] = {
            nid for nid, sig in signals.items()
            if sig.anomaly_score >= anomaly_threshold and nid in dag
        }
        if not anomalous:
            return {"root_causes": [], "affected_subgraph": {}, "propagation_paths": []}

        # 2. 提取异常子图（包含异常节点及其因果祖先）
        subgraph_nodes = self._extract_anomaly_subgraph(dag, anomalous)

        # 3. IDI 干预评分计算
        candidates = self._score_candidates(dag, signals, anomalous, subgraph_nodes)

        # 4. 从每个根因候选向前追踪影响域
        paths: List[dict] = []
        affected: Dict[str, int] = {}  # node_id → 距根因跳数
        for c in candidates[:5]:       # 仅 top-5，避免输出冗余
            reachable = self._trace_impact(dag, c.node_id, anomalous, max_depth=5)
            paths.append({"root": c.node_id, "rca_score": c.rca_score,
                          "reachable": list(reachable)})
            for nid, depth in reachable.items():
                if nid not in affected or depth < affected[nid]:
                    affected[nid] = depth

        candidates.sort(key=lambda c: c.rca_score, reverse=True)
        return {
            "root_causes": [
                {"node_id": c.node_id, "rca_score": round(c.rca_score, 4),
                 "anomaly_score": round(c.anomaly_score, 4),
                 "is_isolated": c.is_isolated,
                 "affected_descendants": c.affected_descendants}
                for c in candidates
            ],
            "affected_subgraph": affected,
            "propagation_paths": paths,
        }

    # ---- 子图提取 ----

    def _extract_anomaly_subgraph(
        self, dag: TaskDependencyGraph, anomalous: Set[str]
    ) -> Set[str]:
        """从异常节点沿反向因果边 BFS，纳入所有因果祖先。

        因果方向 = 依赖方向 (parent → child)。异常节点的祖先中可能包含根因，
        即使祖先自身未触发阈值也需纳入评分（潜在根因可能表现为低异常度）。
        """
        result = set(anomalous)
        queue = deque(anomalous)
        while queue:
            nid = queue.popleft()
            for pred in dag.predecessors(nid):
                if pred not in result:
                    result.add(pred)
                    queue.append(pred)
        return result

    def _score_candidates(
        self,
        dag: TaskDependencyGraph,
        signals: Dict[str, FaultSignal],
        anomalous: Set[str],
        subgraph: Set[str],
    ) -> List[RootCauseCandidate]:
        """IDI 风格干预评分: rca = anomaly - propagation_from_parents。

        propagation_from_parents = Σ(parent_anomaly * decay^hop_distance)
        父节点对子节点的传播影响随跳数指数递减。
        无异常父节点的异常节点得分最高 → 很可能是根因。
        """
        candidates: List[RootCauseCandidate] = []
        anomaly_map = {nid: signals[nid].anomaly_score
                       if nid in signals else 0.0
                       for nid in subgraph}

        for nid in anomalous:
            own = anomaly_map[nid]
            # 沿因果边回溯，计算传播到当前节点的异常量
            propagated = self._compute_propagation(dag, nid, anomaly_map,
                                                   anomalous, max_depth=4)
            score = own - propagated
            # 负分 → 异常可由父节点完全解释，自身非根因
            score = max(0.0, score)
            # 无异常父节点的节点加分
            is_isolated = not any(
                pred in anomalous for pred in dag.predecessors(nid)
            )
            if is_isolated:
                score = own  # 无传播来源 → 自身即根因

            descendants = len(self._trace_impact(dag, nid, anomalous, max_depth=3))
            candidates.append(RootCauseCandidate(
                node_id=nid, rca_score=score, anomaly_score=own,
                propagation_score=propagated,
                affected_descendants=descendants, is_isolated=is_isolated,
            ))
        return candidates

    def _compute_propagation(
        self, dag: TaskDependencyGraph, target: str,
        anomaly_map: Dict[str, float], anomalous: Set[str], max_depth: int,
    ) -> float:
        """计算所有异常祖先传播到 target 的累积异常量。

        BFS 沿反向边遍历，每层乘 _decay。
        同一节点可经由多条路径影响 target，取最短路径（影响最大者）。
        """
        total = 0.0
        visited: Dict[str, int] = {target: 0}  # node_id → 最短跳距
        queue = deque([target])
        while queue:
            cur = queue.popleft()
            cur_dist = visited[cur]
            if cur_dist >= max_depth:
                continue
            for pred in dag.predecessors(cur):
                new_dist = cur_dist + 1
                if pred in visited and visited[pred] <= new_dist:
                    continue
                visited[pred] = new_dist
                if pred in anomalous and pred != target:
                    total += anomaly_map.get(pred, 0.0) * (self._decay ** new_dist)
                queue.append(pred)
        return min(total, anomaly_map.get(target, 0.0))  # 传播量 ≤ 自身异常度

    def _trace_impact(
        self, dag: TaskDependencyGraph, root: str, anomalous: Set[str],
        max_depth: int,
    ) -> Dict[str, int]:
        """从 root 沿因果边正向 BFS，标记影响域内异常节点的深度。"""
        impact: Dict[str, int] = {}
        queue = deque([(root, 0)])
        visited = {root}
        while queue:
            nid, depth = queue.popleft()
            if nid in anomalous and nid != root:
                impact[nid] = depth
            if depth >= max_depth:
                continue
            for succ in dag.successors(nid):
                if succ not in visited:
                    visited.add(succ)
                    queue.append((succ, depth + 1))
        return impact


# ---- 批量构造工具 ----

def fault_signals_from_breakers(
    breakers: Dict[str, dict],
    backpressure: Optional[Dict[str, float]] = None,
) -> Dict[str, FaultSignal]:
    """从熔断器状态字典与背压值批量构造 FaultSignal。

    breakers: {node_id: CircuitBreaker.to_dict()}
    backpressure: {node_id: composite_pressure}，可选。
    """
    bp = backpressure or {}
    return {
        nid: FaultSignal(
            node_id=nid,
            breaker_open=(info.get("state") == "open"),
            breaker_failure_rate=float(info.get("failures", 0))
                                / max(float(info.get("failures", 0))
                                      + float(info.get("successes", 0)), 1.0)
                                if info.get("failures") else 0.0,
            backpressure=bp.get(nid, 0.0),
        )
        for nid, info in breakers.items()
    }
