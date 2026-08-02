# 2026-07-27 — Bayesian置信度评分 (BiNLLM-inspired)
# 朴素贝叶斯+Laplace平滑+独立性奖励，用于CVE匹配的可信度量化

from typing import Dict, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import math


@dataclass
class ConfidenceResult:
    score: float
    factors: Dict[str, float] = field(default_factory=dict)
    evidence_count: int = 0


class BayesianConfidenceScorer:
    """朴素贝叶斯置信度评分器。

    核心思路:
    - 每个证据源(string_match, symbol_match, disasm_match)视为独立特征
    - 先验概率P(Vuln) = base_rate (默认0.1)
    - Laplace平滑处理零频问题
    - 独立性奖励: 多特征同时命中时加分

    score(features): 输入证据特征dict，返回0-1置信度评分。
    """

    def __init__(self, base_rate: float = 0.1, alpha: float = 1.0):
        self.base_rate = base_rate
        self.alpha = alpha  # Laplace平滑参数
        # 条件概率计数
        self._pos_counts: Dict[str, int] = defaultdict(int)  # P(feature | vulnerable)
        self._neg_counts: Dict[str, int] = defaultdict(int)  # P(feature | not vulnerable)
        self._total_pos = 0
        self._total_neg = 0

    def fit(self, training_data: List[Tuple[Dict[str, bool], bool]]):
        """训练：输入(features_dict, is_vulnerable)对"""
        for features, is_vuln in training_data:
            if is_vuln:
                self._total_pos += 1
                for k, v in features.items():
                    if v:
                        self._pos_counts[k] += 1
            else:
                self._total_neg += 1
                for k, v in features.items():
                    if v:
                        self._neg_counts[k] += 1

    def score(self, features: Dict[str, bool]) -> ConfidenceResult:
        """计算给定证据特征集下的漏洞置信度。"""
        prior_pos = self.base_rate
        prior_neg = 1.0 - self.base_rate

        log_odds = math.log(prior_pos / prior_neg) if prior_neg > 0 else 0
        factors = {}
        evidence_count = 0

        for feat_name, feat_value in features.items():
            if not feat_value:
                continue
            evidence_count += 1
            # P(feat | vuln) with Laplace
            p_given_pos = (self._pos_counts.get(feat_name, 0) + self.alpha) / (self._total_pos + self.alpha * 2) if self._total_pos > 0 else 0.5
            p_given_neg = (self._neg_counts.get(feat_name, 0) + self.alpha) / (self._total_neg + self.alpha * 2) if self._total_neg > 0 else 0.5

            if p_given_neg > 0 and p_given_pos > 0:
                lr = math.log(p_given_pos / p_given_neg)
                log_odds += lr
                factors[feat_name] = round(p_given_pos, 3)

        # 独立性奖励: 多证据并行命中时加分（实际特征间可能相关，但贝叶斯假设独立）
        if evidence_count >= 2:
            independence_bonus = min(0.15, (evidence_count - 1) * 0.05)
            log_odds += independence_bonus

        # sigmoid映射到[0,1]
        score = 1.0 / (1.0 + math.exp(-log_odds))
        score = min(1.0, max(0.0, score))

        return ConfidenceResult(score=round(score, 4), factors=factors,
                                evidence_count=evidence_count)

    def score_raw(self, features: Dict[str, bool]) -> float:
        return self.score(features).score

    def reset(self):
        self._pos_counts.clear()
        self._neg_counts.clear()
        self._total_pos = 0
        self._total_neg = 0


# 便捷函数
def confidence_score(features: Dict[str, bool],
                     base_rate: float = 0.1) -> float:
    """单次快速置信度评分（使用默认先验）。"""
    scorer = BayesianConfidenceScorer(base_rate=base_rate)
    return scorer.score(features).score


# 加权融合多个评分结果
def fuse_scores(scores: List[float], weights: List[float] = None) -> float:
    if not scores:
        return 0.0
    if weights is None:
        weights = [1.0] * len(scores)
    total_w = sum(weights)
    if total_w == 0:
        return sum(scores) / len(scores)
    return sum(s * w for s, w in zip(scores, weights)) / total_w
