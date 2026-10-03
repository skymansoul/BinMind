"""
  主动学习边选择 - 基于模型不确定性的最优传播边调查策略。

问题：
  传播图中有数十条候选边待验证，安全分析师资源有限。
  bandit_edge_investigator用LinUCB赌博机做探索-利用平衡（奖励驱动）。
  本模块用主动学习做纯不确定性驱动选择：
  "调查哪条边能最大程度降低模型对传播结构的不确定性？"

方案：
  三种互补的主动学习查询策略:
  1. 不确定性采样: 选预测方差最大的边（模型最不确定的边）
  2. 委员会查询: 多个风险模型对同一边的预测分歧最大→选该边
  3. 预期模型变化: 选调查后最可能改变传播图风险排序的边

  与赌博机的区别:
    赌博机: max(期望奖励 + 探索奖励) → 无模型不确定性概念
    主动学习: max(模型不确定性) → 纯信息增益驱动
    选择取决于场景: 已知高风险边优先验证(赌博机) vs 最不确定边优先
                   验证以建立准确模型(主动学习)

与已有工作的区分:
  Smart Cuts: 主动学习用于代码漏洞检测(CodeBERT+Big-Vul数据集)，
    非传播图边选择。将dataset map引入样本选择，不涉及图边查询。
  不确定性采样+委员会查询+预期模型变化三种策略
          应用于漏洞传播图的边调查优先级排序。

ref: Settles "Active Learning Literature Survey".
ref: Smart Cuts 主动学习在漏洞检测中的最新应用。
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class EdgeQueryCandidate:
    """待查询的候选边及其不确定性度量。"""
    edge_key: Tuple[str, str]
    uncertainty_score: float         # 不确定性采样得分
    committee_disagreement: float    # 委员会分歧度
    expected_impact: float           # 预期模型变化
    composite_score: float = 0.0     # 融合得分


class ActiveEdgeSelector:
    """主动学习边选择器 - 不确定性驱动的边调查优先级排序。

    用法::

        graph = PropagationGraph()
        selector = ActiveEdgeSelector(graph)
        # 用多个风险模型做委员会
        selector.register_model('RiskScorer', risk_scorer_fn)
        selector.register_model('GNN', gnn_predict_fn)
        # 选择最值得调查的边
        top_edges = selector.select_edges(strategy='committee', k=5)
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._models: Dict[str, Callable[[PropagationGraph], Dict[str, float]]] = {}
        self._prediction_cache: Dict[str, Dict[str, Dict[str, float]]] = {}
        # {model_name: {node_id: risk_prediction}}

    def register_model(self, name: str,
                       predict_fn: Callable[[PropagationGraph], Dict[str, float]]
                       ) -> None:
        """注册一个风险预测模型, 用于委员会查询。"""
        self._models[name] = predict_fn

    def refresh_predictions(self) -> None:
        """刷新所有模型的预测缓存。"""
        self._prediction_cache = {}
        for name, fn in self._models.items():
            try:
                self._prediction_cache[name] = fn(self._graph)
            except Exception:
                self._prediction_cache[name] = {}

    def select_edges(self, strategy: str = 'committee',
                     k: int = 5) -> List[EdgeQueryCandidate]:
        """选择最值得调查的k条边。

        strategy:
          'uncertainty' - 不确定性采样 (需单模型, 用边置信度方差)
          'committee'   - 委员会查询 (需多模型, 用预测分歧度)
          'impact'      - 预期模型变化 (模拟移除每条边后重算风险)
          'composite'   - 三策略融合得分
        """
        candidates = self._build_candidates()

        if strategy == 'uncertainty':
            scored = self._score_uncertainty(candidates)
        elif strategy == 'committee':
            self.refresh_predictions()
            scored = self._score_committee(candidates)
        elif strategy == 'impact':
            scored = self._score_impact(candidates)
        else:  # composite
            self.refresh_predictions()
            u_scored = self._score_uncertainty(candidates)
            c_scored = self._score_committee(candidates)
            i_scored = self._score_impact(candidates)
            # 融合: 归一化后等权加和
            scored = self._fuse_scores(u_scored, c_scored, i_scored)

        scored.sort(key=lambda c: c.composite_score, reverse=True)
        return scored[:k]

    def _build_candidates(self) -> List[EdgeQueryCandidate]:
        """构建候选边列表。"""
        candidates = []
        for key in self._graph._edges:
            candidates.append(EdgeQueryCandidate(
                edge_key=key, uncertainty_score=0.0,
                committee_disagreement=0.0, expected_impact=0.0,
            ))
        return candidates

    def _topological_impact(self, edge_key: Tuple[str, str]) -> float:
        """计算边的拓扑影响力: 下游可达节点数加权。

        传播图中的边具有不对称重要性：连接桥接节点的边比末梢边
        影响更多下游节点的风险估计。此度量捕获该不对称性。
        返回 [0,1] 归一化值，0=无影响，1=全图可达。
        """
        _, tgt = edge_key
        if tgt not in self._graph._nodes:
            return 0.0
        reachable = self._graph.propagate_belief(tgt, max_depth=4)
        n_total = max(self._graph.node_count, 1)
        # 下游节点数 × 平均可达置信度
        if not reachable:
            return 0.0
        impact = len(reachable) / n_total
        mean_conf = sum(reachable.values()) / len(reachable)
        return impact * 0.5 + mean_conf * 0.5

    def _score_uncertainty(self, candidates: List[EdgeQueryCandidate]
                            ) -> List[EdgeQueryCandidate]:
        """不确定性采样 (结构感知版): 边置信度熵 × 拓扑影响力。

        纯熵只考虑边缘自身的置信度不确定性。
        拓扑影响力加权使连接高影响力下游节点的边获得更高优先级
        - 这是传播图特有的非对称重要性，标准主动学习无法捕获。
        """
        for cand in candidates:
            edge = self._graph._edges.get(cand.edge_key)
            if edge is None:
                continue
            p = max(0.01, min(0.99, edge.confidence))
            evidence_factor = 1.0 / math.log2(edge.evidence_count + 2)
            ent = -p * math.log2(p) - (1-p) * math.log2(1-p)
            topo_impact = self._topological_impact(cand.edge_key)
            cand.uncertainty_score = ent * evidence_factor * (0.3 + 0.7 * topo_impact)
            cand.composite_score = cand.uncertainty_score
        return candidates

    def _score_committee(self, candidates: List[EdgeQueryCandidate]
                          ) -> List[EdgeQueryCandidate]:
        """委员会查询: 多模型对边两端节点的风险预测分歧度。

        分歧度 = 目标节点风险预测的方差(跨模型)的均值。
        选择分歧最大的边→验证后可消解模型间不一致。
        """
        if len(self._models) < 2:
            return candidates

        for cand in candidates:
            src, tgt = cand.edge_key
            tgt_preds = []
            for name, preds in self._prediction_cache.items():
                p = preds.get(tgt)
                if p is not None:
                    tgt_preds.append(p)

            if len(tgt_preds) < 2:
                cand.committee_disagreement = 0.0
                continue

            mean_p = sum(tgt_preds) / len(tgt_preds)
            var = sum((p - mean_p)**2 for p in tgt_preds) / len(tgt_preds)
            cand.committee_disagreement = math.sqrt(var)
            cand.composite_score = cand.committee_disagreement

        return candidates

    def _score_impact(self, candidates: List[EdgeQueryCandidate]
                       ) -> List[EdgeQueryCandidate]:
        """预期模型变化: 模拟移除边后风险评分的变化幅度。

        对每条候选边:
          1. 暂存当前边置信度
          2. 模拟两种极端情况: 边不存在(conf=0) vs 边确认(conf=1)
          3. 两者风险评分的差异 = 该边的最大可能影响
          4. 差异越大→调查价值越高
        """
        node_ids = list(self._graph._nodes.keys())
        if not node_ids:
            return candidates

        # 基准评分(当前状态)
        base_scores = self._compute_risk_proxy()

        for cand in candidates:
            edge = self._graph._edges.get(cand.edge_key)
            if edge is None:
                continue

            src, tgt = cand.edge_key
            # 模拟: 若此边被确认存在(conf→1)或证伪(conf→0)
            old_conf = edge.confidence
            max_diff = 0.0

            for sim_conf in [max(0.01, old_conf - 0.5), min(0.99, old_conf + 0.5)]:
                # 临时修改边置信度(在内部数据结构上操作, 需恢复)
                # 用传播信念近似: 边置信度变化 → 目标节点可达置信度变化
                reachable = self._graph.propagate_belief(src, max_depth=3)
                delta = abs(sim_conf - old_conf)
                for nid, conf in reachable.items():
                    max_diff = max(max_diff, delta * conf)

            # 还原(propagate_belief不修改边)
            cand.expected_impact = max_diff
            cand.composite_score = cand.expected_impact

        return candidates

    def _compute_risk_proxy(self) -> Dict[str, float]:
        """计算风险代理值 - 简化版(severity + indegree归一化)。"""
        scores = {}
        for nid, node in self._graph._nodes.items():
            indeg = len(self._graph._rev_adj.get(nid, []))
            scores[nid] = 0.5 * node.severity + 0.5 * min(indeg / 10.0, 1.0)
        return scores

    def _fuse_scores(self, u_list: List[EdgeQueryCandidate],
                     c_list: List[EdgeQueryCandidate],
                     i_list: List[EdgeQueryCandidate]
                     ) -> List[EdgeQueryCandidate]:
        """三策略得分融合 - min-max归一化后等权加和。"""

        def normalize(vals, field):
            if not vals:
                return
            raw = [getattr(v, field) for v in vals]
            mn, mx = min(raw), max(raw)
            rng = max(mx - mn, 1e-9)
            for v in vals:
                setattr(v, field, (getattr(v, field) - mn) / rng)

        normalize(u_list, 'uncertainty_score')
        normalize(c_list, 'committee_disagreement')
        normalize(i_list, 'expected_impact')

        by_key = {}
        for v in u_list:
            by_key[v.edge_key] = v
        for v in c_list:
            if v.edge_key not in by_key:
                by_key[v.edge_key] = v
        for v in i_list:
            if v.edge_key not in by_key:
                by_key[v.edge_key] = v

        result = []
        for key, v in by_key.items():
            # 找对应的三个得分
            u = next((x for x in u_list if x.edge_key == key), v)
            c = next((x for x in c_list if x.edge_key == key), v)
            i = next((x for x in i_list if x.edge_key == key), v)
            v.composite_score = (
                u.uncertainty_score + c.committee_disagreement + i.expected_impact
            ) / 3.0
            v.uncertainty_score = u.uncertainty_score
            v.committee_disagreement = c.committee_disagreement
            v.expected_impact = i.expected_impact
            result.append(v)

        return result
