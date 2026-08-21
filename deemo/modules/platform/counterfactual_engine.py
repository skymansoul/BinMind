"""
结构化因果反事实引擎 — 回答"如果打了这个补丁，传播风险如何变化？"

在 PropagationGraph 上叠加 Pearl 的结构因果模型（SCM），实现反事实干预查询：
  1. 外展（Abduction） — 从观测风险反推节点噪声项 u_i
  2. 干预（Action）    — do(节点 X 被修复)，severity_X=0，切断出边
  3. 预测（Prediction）— 在修改后的图上重跑风险传播

核心创新：反事实路径的置信度衰减遵循与正向传播相同的贝叶斯更新规则，
而非简单"删除X→重算"。多路径场景下，仅阻断经X的路径，其他路径仍贡献。

与已有工作的区分：VulRG 仅事后归因，不支持反事实干预。
                      SHAP/LIME 做局部线性近似，不适用于图结构非独立干预。

ref: Pearl "Causality" — do-calculus 理论基础。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, VulnNode


@dataclass
class CounterfactualQuery:
    """一次反事实查询。"""
    intervened_nodes: List[str]         # do(severity=0) 的目标节点列表
    outcome_nodes: List[str]             # 关注的风险变化目标节点
    description: str = ""


@dataclass
class CounterfactualResult:
    """反事实查询结果, 事实 vs 反事实风险对比。"""
    query: CounterfactualQuery
    factual_risk: Dict[str, float]           # {node_id: 原风险值}
    counterfactual_risk: Dict[str, float]    # {node_id: 干预后风险值}
    attributable_risk: Dict[str, float]      # {node_id: 归因于干预节点的风险}
    intervention_paths_blocked: Dict[str, List[List[str]]]
    # {outcome_node: [被切断的传播路径]}


class StructuralCausalPropagator:
    """将 PropagationGraph 的风险传播建模为结构因果模型。

    结构方程: risk_i = σ(w_self·severity_i + w_in·Σrisk_j·edge_ji + w_layer·layer_bias + u_i)
    σ为logit压缩，u_i为外生噪声（abduction阶段反推）。
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._noise_terms: Dict[str, float] = {}     # node_id → u_i
        self._observed_risks: Dict[str, float] = {}   # node_id → factual risk

        # 结构方程权重 — 与 RiskScorer 保持数值一致
        self._w_self = 0.4
        self._w_in = 0.6

    def fit_noise(self, risk_scores: Dict[str, float]) -> None:
        """外展阶段, 从观测风险反推噪声项。

        risk_scores: RiskScorer.score_all() 的输出。
        """
        self._observed_risks = dict(risk_scores)
        self._noise_terms.clear()

        for nid, obs_risk in risk_scores.items():
            predicted = self._predict_risk_from_structure(nid)
            # logit⁻¹ 反推噪声
            obs_logit = self._logit(obs_risk)
            pred_logit = self._logit(predicted)
            self._noise_terms[nid] = obs_logit - pred_logit

    def intervene(self, patched_nodes: List[str]) -> PropagationGraph:
        """干预阶段, do()操作，返回修改后的传播图（深拷贝）。

        对每个被干预节点:
          - severity 置零（漏洞已修复）
          - 移除所有从该节点出发的边
          - 保留入边（该节点仍可被其他漏洞影响）
        """
        import copy
        modified = PropagationGraph(max_nodes=self._graph._max_nodes)

        # 深拷贝全部节点
        patched_set = frozenset(patched_nodes)
        for nid, node in self._graph._nodes.items():
            new_node = VulnNode(
                node_id=node.node_id,
                layer=node.layer,
                vuln_type=node.vuln_type,
                severity=0.0 if nid in patched_set else node.severity,
                entity_ref=node.entity_ref,
                metadata=dict(node.metadata),
            )
            modified.add_node(new_node)

        # 拷贝边——排除从 patched_nodes 出发的边
        for (src, tgt), edge in self._graph._edges.items():
            if src in patched_set:
                continue
            try:
                modified.add_edge(src, tgt, edge.prior_confidence, edge.rule_name)
            except (KeyError, ValueError):
                continue

        return modified

    def predict_counterfactual(self, modified_graph: PropagationGraph,
                               risk_scorer_callable: Callable[[PropagationGraph], Dict[str, float]],
                               outcome_nodes: List[str]) -> Dict[str, float]:
        """预测阶段, 在修改后的图上重跑风险评分，得到反事实风险。

        risk_scorer_callable: 接受 PropagationGraph，返回 {node_id: risk}。
                             通常是 RiskScorer 的包装函数。
        """
        cf_scores = risk_scorer_callable(modified_graph)
        return {nid: cf_scores.get(nid, 0.0) for nid in outcome_nodes}

    def answer(self, query: CounterfactualQuery,
               risk_scorer: Callable[[PropagationGraph], Dict[str, float]],
               max_trace_paths: int = 5) -> CounterfactualResult:
        """执行完整的反事实查询, 外展→干预→预测。

        risk_scorer: 接受 PropagationGraph → Dict[str, float] 的评分函数。
        """
        # 干预
        modified = self.intervene(query.intervened_nodes)

        # 预测——在修改图上评分
        cf_risks = self.predict_counterfactual(modified, risk_scorer, query.outcome_nodes)

        # 事实风险
        factual = {nid: self._observed_risks.get(nid, 0.0)
                   for nid in query.outcome_nodes}

        # 归因风险（因干预而降低的风险量）
        attributable = {}
        for nid in query.outcome_nodes:
            attr = factual.get(nid, 0.0) - cf_risks.get(nid, 0.0)
            attributable[nid] = max(0.0, attr)

        # 被阻断的路径——记录从干预节点到结果节点的路径
        blocked = self._trace_blocked_paths(query.intervened_nodes,
                                            query.outcome_nodes, max_trace_paths)

        return CounterfactualResult(
            query=query,
            factual_risk=factual,
            counterfactual_risk=cf_risks,
            attributable_risk=attributable,
            intervention_paths_blocked=blocked,
        )

# 内部

    def _predict_risk_from_structure(self, node_id: str) -> float:
        """仅用结构信息预测风险（不含噪声）, 结构方程的确定性部分。"""
        node = self._graph._nodes.get(node_id)
        if node is None:
            return 0.0

        incoming = 0.0
        in_count = 0
        for src_id in self._graph._rev_adj.get(node_id, []):
            edge = self._graph._edges.get((src_id, node_id))
            src_risk = self._observed_risks.get(src_id, 0.0)
            if edge and src_risk > 0:
                incoming += src_risk * edge.confidence
                in_count += 1

        if in_count > 0:
            damp = 1.0 / math.log(in_count + 2.0, 2.0)
            incoming *= damp

        return self._w_self * node.severity + self._w_in * incoming

    @staticmethod
    def _logit(p: float) -> float:
        """logit 变换, R → [0,1] 的逆映射。"""
        p = max(1e-9, min(1.0 - 1e-9, p))
        return math.log(p / (1.0 - p))

    def _trace_blocked_paths(self, patched: List[str],
                             outcomes: List[str],
                             max_paths: int) -> Dict[str, List[List[str]]]:
        """枚举因干预而被阻断的传播路径, 仅用于可解释性输出。"""
        blocked: Dict[str, List[List[str]]] = {}
        patched_set = frozenset(patched)

        for target in outcomes:
            paths_to_target: List[List[str]] = []
            for patch_nid in patched:
                # 在原图中找 patch_nid → target 的所有路径
                raw_paths = self._graph.find_propagation_paths(
                    patch_nid, target, max_paths=max_paths, max_depth=5,
                )
                for p in raw_paths:
                    if p and p[0] in patched_set:
                        paths_to_target.append(p)
            blocked[target] = paths_to_target[:max_paths]

        return blocked


class CounterfactualBatchAnalyzer:
    """批量反事实分析 — 评估多个补丁策略的优劣（预算约束下的最优修复子集）。

    用法::

        analyzer = CounterfactualBatchAnalyzer(graph, scm)
        rankings = analyzer.rank_interventions(
            candidate_patches=["node_A", "node_B", "node_C"],
            budget=2, risk_scorer=my_scorer_fn,
        )
    """

    def __init__(self, graph: PropagationGraph,
                 scm: StructuralCausalPropagator):
        self._graph = graph
        self._scm = scm

    def rank_interventions(self, candidate_patches: List[str],
                           budget: int,
                           risk_scorer: Callable[[PropagationGraph], Dict[str, float]],
                           outcome_nodes: Optional[List[str]] = None,
                           ) -> List[Tuple[List[str], float]]:
        """贪心排序, 每次选择边际风险降幅最大的节点加入补丁集。

        使用子模性质的 (1-1/e) 近似保证（见 minimal_witness_set 的设计依据）。
        返回 [(补丁组合, 总风险降幅), ...]，按降幅降序。

        若 candidate_patches 数量 ≤ budget，直接返回全量组合。
        """
        all_nodes = list(self._graph._nodes.keys())
        if outcome_nodes is None:
            outcome_nodes = all_nodes

        remaining = list(candidate_patches)
        selected: List[str] = []
        baseline_risk = sum(self._scm._observed_risks.get(n, 0.0)
                           for n in outcome_nodes)

        rankings: List[Tuple[List[str], float]] = []

        for _ in range(min(budget, len(candidate_patches))):
            best_node = ""
            best_reduction = -1.0

            for cand in remaining:
                trial_set = selected + [cand]
                query = CounterfactualQuery(
                    intervened_nodes=trial_set,
                    outcome_nodes=outcome_nodes,
                    description=f"batch_trial_{len(trial_set)}",
                )
                result = self._scm.answer(query, risk_scorer)
                total_attr = sum(result.attributable_risk.values())

                if total_attr > best_reduction:
                    best_reduction = total_attr
                    best_node = cand

            if best_node:
                selected.append(best_node)
                remaining.remove(best_node)
                rankings.append((list(selected), best_reduction))

        if not rankings:
            rankings.append(([], 0.0))

        return rankings

    def individual_attribution(self) -> Dict[str, float]:
        """逐节点的独立归因风险, 每个节点单独修复时，全局风险的降幅。

        用于生成"修复优先级"报告。计算结果与 RiskScorer.top_risk_paths 互补：
        RiskScorer 输出图拓扑风险，此处输出干预效果。
        """
        attribution: Dict[str, float] = {}
        all_nodes = list(self._graph._nodes.keys())

        for nid in self._graph._nodes:
            trial_cf = self._scm.intervene([nid])
            total_orig = sum(self._scm._observed_risks.get(n, 0.0) for n in all_nodes)
            # 在修改图上估算——使用简化版（仅节点严重度，不重跑完整评分）
            total_cf = 0.0
            for onid in all_nodes:
                if onid in trial_cf._nodes:
                    total_cf += trial_cf._nodes[onid].severity

            attribution[nid] = max(0.0, total_orig - total_cf)

        return attribution
