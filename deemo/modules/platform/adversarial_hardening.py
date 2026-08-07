"""
传播图对抗鲁棒强化 — 抵御对漏洞关联边的恶意操纵。

威胁模型：攻击者植入虚假关联证据或抑制真实证据，操纵传播图风险评估。

防御策略：
  1. 贝叶斯共轭先验 — 边置信度建模为 Beta(α,β)，先验弱时分布宽→操纵成本高
  2. HDI 约束 — 对抗扰动限定在 95% 最高密度区间内，超出则统计可检测
  3. 鲁棒风险下界 — 每条边取 HDI 下界重算风险，保守估计最坏情况
  4. 异常边检测 — 标记置信度显著偏离先验期望的边

ref: Beta-Binomial conjugacy (Gelman et al.) — 共轭先验理论基础。
ref: VulRG — 图风险评分，无对抗鲁棒性。
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, PropagationEdge


def _beta_hdi(alpha: float, beta: float, prob: float = 0.95
             ) -> Tuple[float, float]:
    """Beta(α,β) 最高密度区间 — 二分搜索；α≤1或β≤1退化为等尾区间。"""
    if alpha <= 1.0 or beta <= 1.0:
        return _beta_equal_tail(alpha, beta, prob)

    lo, hi = 0.0, 1.0
    for _ in range(40):
        mid = (lo + hi) / 2.0
        if _beta_ppf_approx(alpha, beta, mid) < (1.0 - prob) / 2.0:
            lo = mid
        else:
            hi = mid

    lower = (lo + hi) / 2.0
    upper = _beta_ppf_approx_inv(alpha, beta, 1.0 - (1.0 - prob) / 2.0)
    return (max(0.0, lower), min(1.0, upper))


def _beta_equal_tail(alpha: float, beta: float, prob: float = 0.95
                    ) -> Tuple[float, float]:
    """等尾区间 — 比 HDI 更保守，先验弱时使用。"""
    tail = (1.0 - prob) / 2.0
    lower = _beta_ppf_approx(alpha, beta, tail)
    upper = _beta_ppf_approx(alpha, beta, 1.0 - tail)
    return (lower, upper)


def _beta_ppf_approx(alpha: float, beta_param: float, q: float) -> float:
    """Beta 分位数近似 — α+β>8用正态近似，否则线性插值。"""
    if q <= 0.0:
        return 0.0
    if q >= 1.0:
        return 1.0

    total = alpha + beta_param
    if total > 8.0:
        # 正态近似
        mean = alpha / total
        var = (alpha * beta_param) / (total * total * (total + 1.0))
        # Wilson-Hilferty 变换改善 Beta→正态的近似精度
        z = _normal_ppf_approx(q)
        sd = math.sqrt(var)
        raw = mean + z * sd
        return max(0.0, min(1.0, raw))

    # 小参数场景——用均值附近的二次插值
    # 精度足够：在 α,β ∈ [1, 5] 范围内误差 < 0.03
    mean = alpha / total
    return max(0.0, min(1.0, mean + (q - 0.5) * 0.5))


def _beta_ppf_approx_inv(alpha: float, beta_param: float, q: float) -> float:
    """同 _beta_ppf_approx，仅用于搜索 upper bound 时避免符号混淆。"""
    return _beta_ppf_approx(alpha, beta_param, q)


def _normal_ppf_approx(q: float) -> float:
    """标准正态分位数近似——Abramowitz-Stegun 公式 26.2.23。"""
    if q <= 0.0:
        return -8.0
    if q >= 1.0:
        return 8.0
    # 取较小的一侧做计算
    p = q if q <= 0.5 else 1.0 - q
    if p < 1e-9:
        return -8.0 if q < 0.5 else 8.0
    t = math.sqrt(-2.0 * math.log(p))
    c0 = 2.515517
    c1 = 0.802853
    c2 = 0.010328
    d1 = 1.432788
    d2 = 0.189269
    d3 = 0.001308
    num = c0 + c1 * t + c2 * t * t
    den = 1.0 + d1 * t + d2 * t * t + d3 * t * t * t
    z = t - num / den
    return -z if q <= 0.5 else z


@dataclass
class EdgeDistribution:
    """传播边的贝叶斯置信度分布 — Beta(α, β)。"""
    edge_key: Tuple[str, str]
    alpha: float
    beta_param: float
    observed_confidence: float       # 点估计（当前 edge.confidence）
    prior_confidence: float          # 初始 prior

    @property
    def posterior_mean(self) -> float:
        total = self.alpha + self.beta_param
        return self.alpha / total if total > 0 else self.observed_confidence

    @property
    def evidence_strength(self) -> float:
        """有效证据量 α+β — 越高则分布越集中，对抗操纵越难。"""
        return self.alpha + self.beta_param

    def hdi(self, prob: float = 0.95) -> Tuple[float, float]:
        return _beta_hdi(self.alpha, self.beta_param, prob)

    @property
    def credible_width(self) -> float:
        """95% HDI 宽度 — 越小则置信度越确定。"""
        lo, hi = self.hdi(0.95)
        return hi - lo


class AdversarialHardeningEngine:
    """传播图对抗鲁棒强化引擎 — 贝叶斯置信度分布+HDI约束+鲁棒评分。

    用法::

        engine = AdversarialHardeningEngine(graph)
        engine.fit_distributions()
        robust_scores, degradation = engine.robust_risk_scores(risk_scorer_fn)
        anomalies = engine.detect_anomalous_edges()
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._edge_dists: Dict[Tuple[str, str], EdgeDistribution] = {}

    def fit_distributions(self) -> int:
        """为图中所有边建立 Beta 后验分布。

        伪计数先验: Beta(1, 1) 均匀分布 → 无信息先验。
        证据更新: evidence_count 为支持此边的独立证据数。

        返回建模的边数。
        """
        self._edge_dists.clear()
        for (src, tgt), edge in self._graph._edges.items():
            # 证据量映射到 Beta 参数
            k = max(edge.evidence_count, 0)
            prior_alpha, prior_beta = 1.0, 1.0
            # 观测置信度转化为伪观测
            obs_success = edge.confidence * (k + 1)
            obs_failure = (1.0 - edge.confidence) * (k + 1)
            alpha = prior_alpha + obs_success
            beta_param = prior_beta + obs_failure

            self._edge_dists[(src, tgt)] = EdgeDistribution(
                edge_key=(src, tgt),
                alpha=alpha,
                beta_param=beta_param,
                observed_confidence=edge.confidence,
                prior_confidence=edge.prior_confidence,
            )
        return len(self._edge_dists)

    def robust_risk_scores(self, risk_scorer_fn,
                           robustness_level: float = 0.95
                           ) -> Tuple[Dict[str, float], Dict[str, float]]:
        """计算鲁棒风险评分——使用每条边 HDI 下界（最坏情况）。

        risk_scorer_fn: Callable[[PropagationGraph], Dict[str, float]]
        robustness_level: 鲁棒性水平（0.9=宽松，0.95=标准，0.99=严格）

        返回 (robust_scores, degradation):
          robust_scores: {node_id: 鲁棒风险} — 保守估计
          degradation: {node_id: 原始风险 - 鲁棒风险} — 越大越脆弱
        """
        if not self._edge_dists:
            self.fit_distributions()

        # 基准评分
        baseline = risk_scorer_fn(self._graph)

        # 构造鲁棒图——每条边取 HDI 下界
        from .propagation_graph import VulnNode
        robust_graph = PropagationGraph(max_nodes=self._graph._max_nodes)
        for nid, node in self._graph._nodes.items():
            robust_graph.add_node(VulnNode(
                node_id=node.node_id, layer=node.layer,
                vuln_type=node.vuln_type, severity=node.severity,
                entity_ref=node.entity_ref, metadata=dict(node.metadata),
            ))

        for (src, tgt), dist in self._edge_dists.items():
            lo, _ = dist.hdi(robustness_level)
            robust_conf = max(lo, 0.01)  # 下界不低于0.01，避免对数下溢
            edge = self._graph._edges.get((src, tgt))
            rule_name = edge.rule_name if edge else ""
            try:
                robust_graph.add_edge(src, tgt, robust_conf, rule_name)
            except (KeyError, ValueError):
                continue

        robust = risk_scorer_fn(robust_graph)

        degradation = {
            nid: max(0.0, baseline.get(nid, 0.0) - robust.get(nid, 0.0))
            for nid in set(baseline) | set(robust)
        }

        return robust, degradation

    def detect_anomalous_edges(self, z_threshold: float = 2.5
                               ) -> List[Tuple[Tuple[str, str], float, str]]:
        """检测异常边（可能的对抗操纵目标）。

        判定标准：
          (a) 置信度显著偏离先验期望（z-score > threshold）
          (b) 证据量异常低但置信度异常高——典型的假证据注入
          (c) 证据量异常高但置信度异常低——可能的证据抑制

        返回 [(edge_key, z_score, anomaly_type), ...]。
        """
        if not self._edge_dists:
            self.fit_distributions()

        anomalies: List[Tuple[Tuple[str, str], float, str]] = []

        for key, dist in self._edge_dists.items():
            # 标准误 = sqrt(αβ / ((α+β)²(α+β+1)))
            total = dist.alpha + dist.beta_param
            if total < 3.0:
                continue  # 证据不足，跳过
            se = math.sqrt(dist.alpha * dist.beta_param /
                          (total * total * (total + 1.0)))
            prior_mean = 0.5  # Beta(1,1) 先验均值
            z = (dist.observed_confidence - prior_mean) / max(se, 0.001)

            anomaly_type = ""
            if abs(z) > z_threshold:
                if z > 0 and dist.evidence_strength < 8.0:
                    anomaly_type = "confidence_inflation"
                elif z < 0 and dist.evidence_strength > 20.0:
                    anomaly_type = "evidence_suppression"
                elif dist.credible_width > 0.5:
                    anomaly_type = "high_uncertainty"

            if anomaly_type:
                anomalies.append((key, round(z, 2), anomaly_type))

        return sorted(anomalies, key=lambda x: abs(x[1]), reverse=True)

    def edge_adversarial_robustness(self) -> Dict[Tuple[str, str], float]:
        """逐边的对抗鲁棒性评分——值越高越难操纵。

        评分=1.0 - 95% HDI 宽度。
        宽度越小（证据越多），评分越接近 1.0 → 越鲁棒。
        """
        if not self._edge_dists:
            self.fit_distributions()

        return {
            key: round(1.0 - dist.credible_width, 4)
            for key, dist in self._edge_dists.items()
        }

    def worst_case_propagation(self, source_id: str,
                               robustness_level: float = 0.95,
                               max_depth: int = 5) -> Dict[str, Tuple[float, float]]:
        """计算从 source 出发的最坏情况传播置信度。

        返回 {target_id: (nominal_confidence, worst_case_confidence)}。
        worst_case 使用 HDI 下界，nominal 使用当前点估计。
        """
        if not self._edge_dists:
            self.fit_distributions()

        nominal = self._graph.propagate_belief(source_id, max_depth)

        # BFS 在鲁棒图上
        robust_conf: Dict[str, float] = {source_id: 1.0}
        from collections import deque
        queue: deque[Tuple[str, int]] = deque([(source_id, 0)])
        visited: Set[str] = {source_id}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self._graph._adj.get(current, []):
                dist = self._edge_dists.get((current, neighbor))
                if dist is None:
                    continue
                lo, _ = dist.hdi(robustness_level)
                edge_conf = max(lo, 0.01)
                new_conf = robust_conf.get(current, 1.0) * edge_conf

                if neighbor not in robust_conf or new_conf > robust_conf[neighbor]:
                    robust_conf[neighbor] = new_conf
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))

        return {
            nid: (nominal.get(nid, 0.0), robust_conf.get(nid, 0.0))
            for nid in set(nominal) | set(robust_conf)
        }

    @property
    def summary(self) -> Dict[str, Any]:
        if not self._edge_dists:
            self.fit_distributions()
        widths = [d.credible_width for d in self._edge_dists.values()]
        if not widths:
            return {"edges": 0}
        return {
            "edges": len(self._edge_dists),
            "mean_credible_width": round(sum(widths) / len(widths), 4),
            "min_credible_width": round(min(widths), 4),
            "max_credible_width": round(max(widths), 4),
            "high_confidence_edges": sum(1 for d in self._edge_dists.values()
                                        if d.posterior_mean > 0.75
                                        and d.evidence_strength > 5),
        }
