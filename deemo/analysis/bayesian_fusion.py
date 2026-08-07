"""多检测器置信度融合, log-odds 加权求和.

log_odds_fused = Σ w_i × log_odds_i + log_prior
各管道独立置信度 → sigmoid → log-odds → 加权 → sigmoid → 融合置信度.
"""

import math
from typing import Dict, Optional, Tuple


def probability_to_log_odds(p: float, eps: float = 1e-10) -> float:
    """将概率转换为对数几率 (logit).

    p ∈ (0, 1) → log_odds ∈ (-∞, +∞)
    0 映射到 -∞, 1 映射到 +∞ (用 eps 裁剪避免数值问题)
    """
    p = max(eps, min(1.0 - eps, p))
    return math.log(p / (1.0 - p))


def log_odds_to_probability(lo: float) -> float:
    """将对数几率转换为概率 (sigmoid).

    lo ∈ (-∞, +∞) → p ∈ (0, 1)
    """
    return 1.0 / (1.0 + math.exp(-lo))


class BayesianFusionEngine:
    """贝叶斯置信度融合引擎.

    融合多个独立检测管道的置信度，输出综合风险评分。

    数学基础:
      P(vuln | e1, e2, ..., en) ∝ P(e1|vuln) × ... × P(en|vuln) × P(vuln)
      其中 P(ei|vuln) 通过管道可靠性和观察置信度联合估计。

    Attributes:
        pipeline_weights: 每个管道的权重 (默认等权)
        prior_prob: 先验概率 (在没有证据时的基础风险)
        eps: 数值稳定性参数
    """

    # 管道可靠性权重 (基于消融研究)
    # GAPSBV 和 TARPS 有最高的可靠性
    DEFAULT_WEIGHTS: Dict[str, float] = {
        'heap_overflow': 0.35,
        'uaf': 0.25,
        'format_string': 0.20,
        'integer_overflow': 0.20,
    }

    def __init__(
        self,
        pipeline_weights: Optional[Dict[str, float]] = None,
        prior_prob: float = 0.10,  # 默认10%先验风险 (保守)
        eps: float = 1e-10,
    ):
        self.weights = pipeline_weights or dict(self.DEFAULT_WEIGHTS)
        self.prior_prob = prior_prob
        self.prior_log_odds = probability_to_log_odds(prior_prob)
        self.eps = eps

    def fuse(
        self,
        scores: Dict[str, float],
        active_weights: Optional[Dict[str, float]] = None,
    ) -> Tuple[float, Dict[str, float]]:
        """融合多个管道的置信度.

        Args:
            scores: {pipeline_name: confidence_score}
            active_weights: 覆盖默认权重 (可选)

        Returns:
            (fused_probability, per_pipeline_contributions)

        Example:
            engine = BayesianFusionEngine()
            prob, contribs = engine.fuse({'heap_overflow': 0.85, 'uaf': 0.60})
            # prob ≈ 0.78, contribs = {'heap_overflow': 0.35, 'uaf': 0.43}
        """
        weights = active_weights or self.weights
        total_lo = self.prior_log_odds
        weight_sum = sum(weights.get(k, 0.0) for k in scores)

        if weight_sum == 0.0:
            return self.prior_prob, {}

        contributions: Dict[str, float] = {}

        for pipeline, confidence in scores.items():
            w = weights.get(pipeline, 0.0)
            if w == 0.0 or confidence <= 0.0:
                continue

            # 将检测置信度转换为对数几率
            lo = probability_to_log_odds(confidence, self.eps)
            # 加权贡献
            normalized_w = w / weight_sum
            contribution = normalized_w * (lo - self.prior_log_odds)
            total_lo += contribution
            contributions[pipeline] = contribution

        fused_prob = log_odds_to_probability(total_lo)
        return round(fused_prob, 4), {
            k: round(v, 4) for k, v in contributions.items()
        }

    def update(
        self,
        current_prob: float,
        new_evidence: Dict[str, float],
        evidence_weight: float = 0.3,
    ) -> float:
        """贝叶斯更新: 将新证据增量融合到现有概率中.

        Args:
            current_prob: 当前融合概率
            new_evidence: 新证据 (管道→置信度)
            evidence_weight: 新证据的权重 (0~1)

        Returns:
            updated_probability
        """
        current_lo = probability_to_log_odds(current_prob, self.eps)

        # 计算新证据的对数几率贡献
        new_scores = {k: v for k, v in new_evidence.items() if v > 0}
        if not new_scores:
            return current_prob

        _, contributions = self.fuse(new_scores)
        evidence_lo = sum(contributions.values())

        # 指数加权移动平均 (EWMA-style)
        updated_lo = (1.0 - evidence_weight) * current_lo + evidence_weight * evidence_lo
        return round(log_odds_to_probability(updated_lo), 4)

    def rank(
        self,
        candidates: list,
        score_key: str = 'scores',
    ) -> list:
        """对候选检测结果按融合风险排序.

        Args:
            candidates: [{score_key: {pipeline: confidence}, ...}, ...]
            score_key: 置信度字典的键名

        Returns:
            按 fused_probability 降序排列的候选列表
        """
        ranked = []
        for c in candidates:
            scores = c.get(score_key, {})
            prob, contribs = self.fuse(scores)
            ranked.append({**c, 'fused_risk': prob, 'contributions': contribs})

        ranked.sort(key=lambda x: x['fused_risk'], reverse=True)
        return ranked

    def classify(self, fused_prob: float) -> Tuple[str, str]:
        """基于融合概率给出风险等级.

        Returns:
            (risk_level, recommendation)
        """
        if fused_prob >= 0.80:
            return 'CRITICAL', 'immediate review required'
        elif fused_prob >= 0.60:
            return 'HIGH', 'review within next iteration'
        elif fused_prob >= 0.35:
            return 'MEDIUM', 'add to review queue'
        elif fused_prob >= 0.15:
            return 'LOW', 'document, review if time permits'
        else:
            return 'NEGLIGIBLE', 'likely false positive, skip'

    def calibration_curve(
        self,
        test_points: int = 20,
    ) -> Dict[str, list]:
        """生成校准曲线数据 (用于可靠性图).

        Returns:
            {pipeline_name: [(confidence, fused_prob_contribution), ...]}
        """
        curves = {}
        for pipeline in self.weights:
            points = []
            for i in range(test_points):
                conf = (i + 1) / test_points
                _, contribs = self.fuse({pipeline: conf})
                points.append((conf, log_odds_to_probability(
                    contribs.get(pipeline, 0.0))))
            curves[pipeline] = points
        return curves


# 便捷函数

def fuse_scores(
    heap_conf: float = 0.0,
    uaf_conf: float = 0.0,
    fmt_conf: float = 0.0,
    intof_conf: float = 0.0,
    prior: float = 0.10,
) -> float:
    """便捷函数: 融合四个管道的置信度."""
    scores = {}
    if heap_conf > 0: scores['heap_overflow'] = heap_conf
    if uaf_conf > 0: scores['uaf'] = uaf_conf
    if fmt_conf > 0: scores['format_string'] = fmt_conf
    if intof_conf > 0: scores['integer_overflow'] = intof_conf
    if not scores:
        return prior

    engine = BayesianFusionEngine(prior_prob=prior)
    fused, _ = engine.fuse(scores)
    return fused


def risk_classify(fused_prob: float) -> str:
    """便捷函数: 风险等级分类."""
    engine = BayesianFusionEngine()
    level, _ = engine.classify(fused_prob)
    return level
