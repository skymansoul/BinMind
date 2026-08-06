# created: 2026-08-03
# modified: 2026-08-22 — replaced hardcoded exposure=0.5 with type-based _estimate_exposure()
# 供应链风险传播核心: 时敏衰减 + 传递性风险传播引擎
# 用于 supply_chain_risk.py

import math
import time
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class ExploitMaturity(Enum):
    UNPROVEN = 0
    POC = 1
    FUNCTIONAL = 2
    HIGH = 3
    NOT_DEFINED = 4


class TemporalDecay:
    """时敏风险衰减: risk(t) = risk_0 · exp(-λ · t)

    λ = λ_base × maturity_factor
    高成熟度→快衰减（补丁紧迫），低成熟度→慢衰减（修复窗口长）
    """

    _MATURITY_FACTORS = {
        ExploitMaturity.UNPROVEN: 0.3,
        ExploitMaturity.POC: 0.6,
        ExploitMaturity.FUNCTIONAL: 1.0,
        ExploitMaturity.HIGH: 1.5,
        ExploitMaturity.NOT_DEFINED: 0.7,
    }

    def __init__(self, base_decay_rate: float = 0.05):
        self.lambda_base = base_decay_rate  # 半衰期≈14天

    def current_risk(self, initial_risk: float, cve_publish_time: float,
                     maturity: ExploitMaturity,
                     current_time: Optional[float] = None) -> float:
        if current_time is None:
            current_time = time.time()
        elapsed_days = max(0.0, (current_time - cve_publish_time) / 86400.0)
        factor = self._MATURITY_FACTORS.get(maturity, 0.7)
        lambda_eff = self.lambda_base * factor
        decay = math.exp(-lambda_eff * elapsed_days)
        return initial_risk * max(0.05, decay)


@dataclass
class DependencyNode:
    node_id: str
    name: str
    version: str = ""
    component_type: str = "library"
    direct_risk: float = 0.0
    propagated_risk: float = 0.0
    total_risk: float = 0.0
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    cve_list: List[str] = field(default_factory=list)


@dataclass
class CVEExposure:
    cve_id: str
    affected_node: str
    initial_risk: float
    publish_time: float
    maturity: ExploitMaturity
    interface_exposure: float = 0.5


class TransitiveRiskPropagator:
    """传递性风险传播引擎。

    算法:
      1. 时敏衰减每个CVE的当前风险
      2. 拓扑排序依赖DAG
      3. 沿DEPENDS_ON边反向传播（被依赖者→依赖者）
      4. 对数求和聚合避免风险通胀
    """

    def __init__(self, decay: Optional[TemporalDecay] = None,
                 depth_decay_factor: float = 0.7,
                 max_propagation_depth: int = 10):
        self._decay = decay or TemporalDecay()
        self._depth_decay = depth_decay_factor
        self._max_depth = max_propagation_depth
        self._nodes: Dict[str, DependencyNode] = {}
        self._cve_exposures: Dict[str, List[CVEExposure]] = defaultdict(list)

    def add_node(self, node_id: str, name: str, **kwargs):
        self._nodes[node_id] = DependencyNode(node_id=node_id, name=name, **kwargs)

    def add_dependency(self, dependent: str, dependency: str):
        if dependent in self._nodes and dependency in self._nodes:
            if dependency not in self._nodes[dependent].dependencies:
                self._nodes[dependent].dependencies.append(dependency)
            if dependent not in self._nodes[dependency].dependents:
                self._nodes[dependency].dependents.append(dependent)

    def add_cve(self, exposure: CVEExposure):
        self._cve_exposures[exposure.affected_node].append(exposure)

    def _estimate_exposure(self, source_id: str, target_id: str) -> float:
        """估计source(被依赖者)对target(依赖者)的接口暴露度。

        基于组件类型启发式:
          library→application: 0.7 (应用直接调用库API)
          library→library: 0.5 (库间API调用)
          framework→application: 0.8 (框架深度嵌入应用)
          os→any: 0.6 (OS API普遍存在)
          其他: 0.4 (默认保守估计)
        如果CVE暴露度已明确指定则使用指定值。
        """
        source = self._nodes.get(source_id)
        target = self._nodes.get(target_id)
        if source is None or target is None:
            return 0.4
        st = source.component_type
        tt = target.component_type
        if st == 'framework' and tt == 'application':
            return 0.8
        if st == 'library' and tt == 'application':
            return 0.7
        if st == 'library' and tt == 'library':
            return 0.5
        if st == 'os':
            return 0.6
        return 0.4

    def compute_all_risks(self, current_time: Optional[float] = None
                          ) -> Dict[str, float]:
        if current_time is None:
            current_time = time.time()
        for node_id, node in self._nodes.items():
            direct = 0.0
            for exp in self._cve_exposures.get(node_id, []):
                time_adj = self._decay.current_risk(
                    exp.initial_risk, exp.publish_time, exp.maturity, current_time)
                direct = self._logsumexp_aggregate(direct, time_adj)
            node.direct_risk = min(1.0, direct)
            node.propagated_risk = 0.0

        topo_order = self._topological_sort()
        for node_id in reversed(topo_order):
            node = self._nodes[node_id]
            for dep_id in node.dependents:
                dep_node = self._nodes[dep_id]
                exposure = self._estimate_exposure(node_id, dep_id)
                propagated = node.total_risk * exposure * self._depth_decay
                dep_node.propagated_risk += propagated

        results = {}
        for node_id, node in self._nodes.items():
            node.total_risk = min(1.0,
                self._logsumexp_aggregate(node.direct_risk, node.propagated_risk))
            results[node_id] = node.total_risk
        return results

    def incremental_update(self, changed_node: str,
                           current_time: Optional[float] = None
                           ) -> Dict[str, float]:
        if current_time is None:
            current_time = time.time()
        affected = {changed_node}
        q = deque([changed_node])
        while q:
            u = q.popleft()
            if u in self._nodes:
                for dep_id in self._nodes[u].dependents:
                    if dep_id not in affected:
                        affected.add(dep_id)
                        q.append(dep_id)
        for node_id in affected:
            node = self._nodes[node_id]
            direct = 0.0
            for exp in self._cve_exposures.get(node_id, []):
                time_adj = self._decay.current_risk(
                    exp.initial_risk, exp.publish_time, exp.maturity, current_time)
                direct = self._logsumexp_aggregate(direct, time_adj)
            node.direct_risk = min(1.0, direct)
            propagated = 0.0
            for dep_on in node.dependencies:
                if dep_on in self._nodes:
                    exposure = self._estimate_exposure(dep_on, node_id)
                propagated += (self._nodes[dep_on].total_risk *
                              exposure * self._depth_decay)
            node.propagated_risk = propagated
            node.total_risk = min(1.0,
                self._logsumexp_aggregate(node.direct_risk, node.propagated_risk))
        return {nid: self._nodes[nid].total_risk for nid in affected}

    def _topological_sort(self) -> List[str]:
        in_degree = defaultdict(int)
        for nid, node in self._nodes.items():
            for dep in node.dependencies:
                if dep in self._nodes:
                    in_degree[nid] += 1
        q = deque([nid for nid in self._nodes if in_degree[nid] == 0])
        order = []
        while q:
            u = q.popleft()
            order.append(u)
            if u in self._nodes:
                for dep_id in self._nodes[u].dependents:
                    if dep_id in self._nodes:
                        in_degree[dep_id] -= 1
                        if in_degree[dep_id] == 0:
                            q.append(dep_id)
        for nid in self._nodes:
            if nid not in order:
                order.append(nid)
        return order

    @staticmethod
    def _logsumexp_aggregate(a: float, b: float) -> float:
        if a < 1e-12:
            return b
        if b < 1e-12:
            return a
        max_val = max(a, b)
        return max_val + math.log(1.0 + math.exp(min(a, b) - max_val))

    def get_risk_ranking(self, top_n: int = 20) -> List[Tuple[str, float, float]]:
        ranked = [(nid, node.total_risk, node.direct_risk)
                  for nid, node in self._nodes.items()]
        ranked.sort(key=lambda x: -x[1])
        return ranked[:top_n]
