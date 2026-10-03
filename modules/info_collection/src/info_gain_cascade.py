"""
多阶段信息增益级联调度器 (MSIGC)。

背景: 安全分析中不同采集动作的信息价值和执行成本差异可达数量级。
例如 hash_compute (成本 1.0, 本地计算) 对 INTEL_CORRELATION 的信息增益
(0.50) 远低于 cve_lookup (成本 5.0, 网络 IO, 增益 0.85),
但现有平级路由在资源受限时无法区分优先级。

建模: 采集器组织为有向无环依赖图 G = (V, E)。
每条边 (u → v) 表示 v 依赖 u 的输出。
节点 v 的属性: gain(v, intent) ∈ [0,1], cost(v) ∈ [1,10]。
调度目标: 在拓扑约束下, 最大化 ∑ gain(v) 同时最小化 ∑ cost(v),
当边际 gain / cost 低于自适应阈值时早停。

关键属性: gain(v, intent) 是意图感知的 —— 同一采集器在不同意图下
增益不同 (如 cve_lookup 对 INTEL_CORRELATION 增益 0.85,
对 STATIC_COLLECTION 仅 0.10)。这使调度器能根据当前意图
动态调整执行优先级, 而非使用固定的全局排序。
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .intent_route import IntentCategory


# 采集器→意图信息增益矩阵。同一采集器对不同意图类别贡献的比特量不同。
# 数值为经验估计的占位值, 实际部署时通过 A/B 标定或在线贝叶斯优化替换。

_GAIN_MATRIX: Dict[str, Dict[IntentCategory, float]] = {
    "host_enum": {
        IntentCategory.STATIC_COLLECTION: 0.90,
        IntentCategory.DYNAMIC_INTERACTION: 0.15,
        IntentCategory.INTEL_CORRELATION: 0.10,
        IntentCategory.FILE_ANALYSIS: 0.05,
        IntentCategory.UNKNOWN: 0.25,
    },
    "net_mapping": {
        IntentCategory.STATIC_COLLECTION: 0.75,
        IntentCategory.DYNAMIC_INTERACTION: 0.30,
        IntentCategory.INTEL_CORRELATION: 0.20,
        IntentCategory.FILE_ANALYSIS: 0.05,
        IntentCategory.UNKNOWN: 0.20,
    },
    "service_enum": {
        IntentCategory.STATIC_COLLECTION: 0.80,
        IntentCategory.DYNAMIC_INTERACTION: 0.40,
        IntentCategory.INTEL_CORRELATION: 0.15,
        IntentCategory.FILE_ANALYSIS: 0.10,
        IntentCategory.UNKNOWN: 0.20,
    },
    "ioctl_probe": {
        IntentCategory.STATIC_COLLECTION: 0.05,
        IntentCategory.DYNAMIC_INTERACTION: 0.85,
        IntentCategory.INTEL_CORRELATION: 0.05,
        IntentCategory.FILE_ANALYSIS: 0.00,
        IntentCategory.UNKNOWN: 0.15,
    },
    "driver_probe": {
        IntentCategory.STATIC_COLLECTION: 0.05,
        IntentCategory.DYNAMIC_INTERACTION: 0.80,
        IntentCategory.INTEL_CORRELATION: 0.05,
        IntentCategory.FILE_ANALYSIS: 0.00,
        IntentCategory.UNKNOWN: 0.15,
    },
    "input_fuzz": {
        IntentCategory.STATIC_COLLECTION: 0.00,
        IntentCategory.DYNAMIC_INTERACTION: 0.70,
        IntentCategory.INTEL_CORRELATION: 0.05,
        IntentCategory.FILE_ANALYSIS: 0.20,
        IntentCategory.UNKNOWN: 0.20,
    },
    "cve_lookup": {
        IntentCategory.STATIC_COLLECTION: 0.10,
        IntentCategory.DYNAMIC_INTERACTION: 0.10,
        IntentCategory.INTEL_CORRELATION: 0.85,
        IntentCategory.FILE_ANALYSIS: 0.25,
        IntentCategory.UNKNOWN: 0.30,
    },
    "ioc_lookup": {
        IntentCategory.STATIC_COLLECTION: 0.05,
        IntentCategory.DYNAMIC_INTERACTION: 0.05,
        IntentCategory.INTEL_CORRELATION: 0.80,
        IntentCategory.FILE_ANALYSIS: 0.30,
        IntentCategory.UNKNOWN: 0.25,
    },
    "osint_recon": {
        IntentCategory.STATIC_COLLECTION: 0.15,
        IntentCategory.DYNAMIC_INTERACTION: 0.05,
        IntentCategory.INTEL_CORRELATION: 0.70,
        IntentCategory.FILE_ANALYSIS: 0.15,
        IntentCategory.UNKNOWN: 0.25,
    },
    "pe_analyze": {
        IntentCategory.STATIC_COLLECTION: 0.05,
        IntentCategory.DYNAMIC_INTERACTION: 0.05,
        IntentCategory.INTEL_CORRELATION: 0.30,
        IntentCategory.FILE_ANALYSIS: 0.90,
        IntentCategory.UNKNOWN: 0.20,
    },
    "strings_extract": {
        IntentCategory.STATIC_COLLECTION: 0.10,
        IntentCategory.DYNAMIC_INTERACTION: 0.05,
        IntentCategory.INTEL_CORRELATION: 0.40,
        IntentCategory.FILE_ANALYSIS: 0.85,
        IntentCategory.UNKNOWN: 0.20,
    },
    "hash_compute": {
        IntentCategory.STATIC_COLLECTION: 0.05,
        IntentCategory.DYNAMIC_INTERACTION: 0.05,
        IntentCategory.INTEL_CORRELATION: 0.50,
        IntentCategory.FILE_ANALYSIS: 0.75,
        IntentCategory.UNKNOWN: 0.15,
    },
}

_COST_MAP: Dict[str, float] = {
    "host_enum": 2.0, "net_mapping": 4.0, "service_enum": 3.0,
    "ioctl_probe": 6.0, "driver_probe": 7.0, "input_fuzz": 8.0,
    "cve_lookup": 5.0, "ioc_lookup": 5.0, "osint_recon": 6.0,
    "pe_analyze": 3.0, "strings_extract": 1.5, "hash_compute": 1.0,
}

# 采集器依赖关系: action_id → {前置 action_id}
_DEPENDENCIES: Dict[str, Set[str]] = {
    "net_mapping": {"host_enum"},
    "service_enum": {"host_enum"},
    "ioc_lookup": {"hash_compute"},
    "osint_recon": {"cve_lookup"},
}


@dataclass
class CascadeNode:
    """信息增益级联图中的节点。"""
    action_id: str
    gain: float            # 对当前意图的信息增益
    cost: float            # 归一化成本
    priority: float = 0.0  # gain / cost 比值
    dependencies: FrozenSet[str] = field(default_factory=frozenset)
    optional: bool = False  # 可选节点, 资源不足时可跳过


@dataclass
class CascadePlan:
    """信息增益级联执行计划。"""
    intent: IntentCategory
    stages: List[List[CascadeNode]]  # 每个阶段是一组可并行的节点
    total_gain: float
    total_cost: float
    early_termination: bool = False
    termination_reason: str = ""
    skipped_nodes: List[str] = field(default_factory=list)


class InfoGainScheduler:
    """
    多阶段信息增益级联调度器。

    输入: 意图类别 + 匹配的采集器列表
    输出: 按 info_gain/cost 比值分阶段排序的执行计划

    阶段划分依据:
    - 阶段 0: 无依赖的高增益低成本采集器 (快速信息获取)
    - 阶段 1: 依赖阶段 0 输出的采集器
    - 阶段 N: 深度关联采集器, 仅在前序阶段增益足够时执行
    """

    def __init__(
        self,
        gain_matrix: Optional[Dict[str, Dict[IntentCategory, float]]] = None,
        cost_map: Optional[Dict[str, float]] = None,
        dependencies: Optional[Dict[str, Set[str]]] = None,
        min_marginal_gain: float = 0.05,
        max_total_cost: float = 20.0,
    ):
        self._gain = gain_matrix or _GAIN_MATRIX
        self._cost = cost_map or _COST_MAP
        self._deps = dependencies or _DEPENDENCIES
        self._min_marginal_gain = min_marginal_gain
        self._max_total_cost = max_total_cost

    def estimate_gain(self, action_id: str, intent: IntentCategory) -> float:
        """查询采集器对给定意图的信息增益估计。"""
        action_gains = self._gain.get(action_id, {})
        return action_gains.get(intent, 0.10)

    def estimate_cost(self, action_id: str) -> float:
        """查询采集器的归一化成本。"""
        return self._cost.get(action_id, 3.0)

    def get_dependencies(self, action_id: str) -> FrozenSet[str]:
        """查询采集器的前置依赖。"""
        return frozenset(self._deps.get(action_id, set()))

    def plan(
        self,
        intent: IntentCategory,
        action_ids: List[str],
        budget_cost: Optional[float] = None,
    ) -> CascadePlan:
        """
        生成信息增益级联执行计划。

        budget_cost: 外部指定的成本上限, 覆盖 _max_total_cost。
        """
        max_cost = budget_cost if budget_cost is not None else self._max_total_cost

        nodes: Dict[str, CascadeNode] = {}
        for aid in set(action_ids):
            gain = self.estimate_gain(aid, intent)
            cost = self.estimate_cost(aid)
            deps = self.get_dependencies(aid)
            priority = gain / max(0.1, cost)
            nodes[aid] = CascadeNode(
                action_id=aid, gain=gain, cost=cost,
                priority=priority, dependencies=deps,
            )

        # 对仅在依赖关系中出现但不在 action_ids 中的节点,
        # 标记为可选 (作为依赖链的中间节点)
        all_dep_ids = set()
        for node in nodes.values():
            all_dep_ids.update(node.dependencies)
        for dep_id in all_dep_ids:
            if dep_id not in nodes:
                gain = self.estimate_gain(dep_id, intent)
                cost = self.estimate_cost(dep_id)
                deps = self.get_dependencies(dep_id)
                nodes[dep_id] = CascadeNode(
                    action_id=dep_id, gain=gain, cost=cost,
                    priority=gain / max(0.1, cost),
                    dependencies=deps, optional=True,
                )

        # 拓扑排序 + 按 priority 分层
        stages = self._topological_layers(nodes, intent)

        total_gain = 0.0
        total_cost = 0.0
        skipped: List[str] = []
        executed_stages: List[List[CascadeNode]] = []
        early_term = False
        term_reason = ""

        for stage in stages:
            stage_gain = sum(n.gain for n in stage)
            stage_cost = sum(n.cost for n in stage)

            # 早停判定: 累计增益饱和 或 成本超限
            marginal = stage_gain / max(1, len(stage))
            if marginal < self._min_marginal_gain and total_gain > 0.3:
                skipped.extend(n.action_id for n in stage)
                if not early_term:
                    early_term = True
                    term_reason = (
                        f"阶段边际增益 {marginal:.4f} 低于阈值 "
                        f"{self._min_marginal_gain}, 剩余 {len(stage)} 个采集器跳过"
                    )
                continue

            if total_cost + stage_cost > max_cost:
                # 按 priority 择优执行
                sorted_stage = sorted(stage, key=lambda n: n.priority, reverse=True)
                kept: List[CascadeNode] = []
                for n in sorted_stage:
                    if total_cost + n.cost <= max_cost:
                        kept.append(n)
                        total_cost += n.cost
                        total_gain += n.gain
                    else:
                        skipped.append(n.action_id)
                if kept:
                    executed_stages.append(kept)
                if not early_term:
                    early_term = True
                    term_reason = f"成本预算耗尽 (上限={max_cost:.1f})"
                break

            executed_stages.append(stage)
            total_gain += stage_gain
            total_cost += stage_cost

        if not early_term and skipped:
            early_term = True
            term_reason = f"边际增益衰减终止, 跳过 {len(skipped)} 个采集器"

        return CascadePlan(
            intent=intent,
            stages=executed_stages,
            total_gain=min(1.0, total_gain),
            total_cost=total_cost,
            early_termination=early_term,
            termination_reason=term_reason,
            skipped_nodes=skipped,
        )

    def _topological_layers(
        self, nodes: Dict[str, CascadeNode], intent: IntentCategory
    ) -> List[List[CascadeNode]]:
        """
        拓扑分层: 每一层内的节点无相互依赖, 可并行执行。
        层内按 priority 降序排列。
        """
        in_degree: Dict[str, int] = {aid: len(n.dependencies & set(nodes.keys()))
                                      for aid, n in nodes.items()}
        queue: deque = deque(aid for aid, d in in_degree.items() if d == 0)
        layers: List[List[CascadeNode]] = []
        processed: Set[str] = set()

        while queue:
            current_layer_ids: List[str] = []
            for _ in range(len(queue)):
                aid = queue.popleft()
                current_layer_ids.append(aid)
                processed.add(aid)

            layer_nodes = sorted(
                [nodes[aid] for aid in current_layer_ids],
                key=lambda n: n.priority, reverse=True,
            )
            layers.append(layer_nodes)

            # 更新下一层节点的入度
            for aid in current_layer_ids:
                for other_id, other_node in nodes.items():
                    if aid in other_node.dependencies and other_id not in processed:
                        in_degree[other_id] -= 1
                        if in_degree[other_id] == 0:
                            queue.append(other_id)

        return [layer for layer in layers if layer]


__all__ = [
    "CascadeNode",
    "CascadePlan",
    "InfoGainScheduler",
]
