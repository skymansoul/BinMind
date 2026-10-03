"""
校准置信度与风险控制路由。

为什么需要校准: LLM 的 token-probability 置信度在 RLHF 后通常过度集中
于 0.7-0.9 区间, 不构成真实概率。规则分类器的归一化分数同样缺乏统计语义。
在安全工具路由场景中, 将未校准分数等同于可靠概率导致:
  · 过度路由 → 高置信度但错误分类的请求消耗昂贵采集资源
  · 过度延迟 → 低置信度但实际可用的请求被退回人工

方案: 对 LLM 输出做温度缩放 (逆 logit 变换 + 参数化 softmax),
对规则分类器做 Platt scaling (逻辑回归映射),
再以加权几何平均融合为校准概率向量。
基于校准概率做三态决策: route / defer / escalate。

与 UniCR 的差异:
UniCR 面向生成式拒绝, 本模块面向执行路由 —— 不丢弃请求,
而是降级到更低成本的采集路径或排队等待更完整的上下文。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .intent_route import IntentCategory, IntentResult


class DeferralDecision(Enum):
    """路由决策结果。"""
    ROUTE = "route"            # 置信度足够, 直接路由
    DEFER = "defer"            # 置信度不足, 延迟到人工或降级处理
    ESCALATE = "escalate"      # 高风险信号, 升级处理


@dataclass
class CalibratedResult:
    """校准后的分类结果。"""
    category: IntentCategory
    raw_confidence: float        # 原始未校准置信度
    calibrated_probability: float  # 校准后的概率估计
    probability_vector: Dict[IntentCategory, float]  # 全类别校准概率
    deferral: DeferralDecision
    risk_score: float            # 综合风险评分
    calibration_method: str      # 使用的校准方法名


@dataclass
class CalibrationConfig:
    """校准参数配置。"""
    # 温度缩放参数 (LLM 分类器)
    temperature: float = 1.8
    # Platt scaling 参数 (规则分类器)
    platt_a: float = 2.5
    platt_b: float = -0.8
    # 风险控制
    risk_threshold: float = 0.65   # 低于此值的校准概率触发 defer
    escalate_threshold: float = 0.35  # 低于此值触发 escalate (高风险)
    # 融合权重
    llm_weight: float = 0.60       # LLM 校准后的权重
    rule_weight: float = 0.40      # 规则分类器校准后的权重


# 校准函数


def _temperature_scale(confidence: float, temperature: float) -> float:
    """
    温度缩放: p_calibrated = softmax(logit / T)。

    由于没有原始 logit, 使用逆变换: logit ≈ ln(p / (1-p))
    然后 p_cal = sigmoid(logit / T)
    """
    eps = 1e-7
    p = max(eps, min(1.0 - eps, confidence))
    logit = math.log(p / (1.0 - p))
    calibrated_logit = logit / max(0.2, temperature)
    return 1.0 / (1.0 + math.exp(-calibrated_logit))


def _platt_scale(score: float, a: float, b: float) -> float:
    """Platt scaling: p = sigmoid(a * score + b)。"""
    return 1.0 / (1.0 + math.exp(-(a * score + b)))


def _geometric_mean(a: float, b: float, wa: float, wb: float) -> float:
    """加权几何平均, 对低概率更敏感。"""
    if a <= 0 or b <= 0:
        return 0.0
    w_sum = wa + wb
    return math.exp((wa * math.log(a) + wb * math.log(b)) / w_sum)


# 类别先验: 基于安全分析中各类别的经验出现频率
# 先验用于调整校准概率, 罕见类别的低置信度应给予更保守的处理

_CATEGORY_PRIORS: Dict[IntentCategory, float] = {
    IntentCategory.STATIC_COLLECTION: 0.30,
    IntentCategory.DYNAMIC_INTERACTION: 0.15,
    IntentCategory.INTEL_CORRELATION: 0.25,
    IntentCategory.FILE_ANALYSIS: 0.25,
    IntentCategory.UNKNOWN: 0.05,
}


class ConfidenceCalibrator:
    """
    多分类器置信度校准与风险控制路由。

    三阶段管线:
    1. 对各分类器输出独立校准
    2. 加权融合为校准概率向量
    3. 风险控制决策: route / defer / escalate
    """

    def __init__(self, config: Optional[CalibrationConfig] = None):
        self._config = config or CalibrationConfig()

    def calibrate_llm(
        self, confidence: float, category: IntentCategory
    ) -> float:
        """对 LLM 分类器的置信度做温度缩放校准。"""
        calib = _temperature_scale(confidence, self._config.temperature)
        # 应用类别先验贝叶斯调整
        prior = _CATEGORY_PRIORS.get(category, 0.1)
        calib = calib * prior / max(0.01, (calib * prior + (1 - calib) * (1 - prior)))
        return min(0.99, max(0.01, calib))

    def calibrate_rule(
        self, score: float, _category: IntentCategory = IntentCategory.UNKNOWN
    ) -> float:
        """对规则分类器的原始分数做 Platt scaling 校准。"""
        return _platt_scale(score, self._config.platt_a, self._config.platt_b)

    def fuse(
        self,
        llm_calibrated: Optional[Dict[IntentCategory, float]],
        rule_calibrated: Optional[Dict[IntentCategory, float]],
    ) -> Dict[IntentCategory, float]:
        """
        融合多个分类器的校准概率向量。

        使用加权几何平均, 对低概率区域更敏感。
        当仅有一方可用时, 直接使用该方的校准结果。
        """
        all_categories = set()
        if llm_calibrated:
            all_categories.update(llm_calibrated.keys())
        if rule_calibrated:
            all_categories.update(rule_calibrated.keys())

        if not all_categories:
            return {IntentCategory.UNKNOWN: 0.5}

        fused: Dict[IntentCategory, float] = {}
        w_llm = self._config.llm_weight
        w_rule = self._config.rule_weight

        for cat in all_categories:
            p_llm = (llm_calibrated or {}).get(cat, 0.0)
            p_rule = (rule_calibrated or {}).get(cat, 0.0)

            if llm_calibrated and rule_calibrated and p_llm > 0 and p_rule > 0:
                fused[cat] = _geometric_mean(p_llm, p_rule, w_llm, w_rule)
            elif p_llm > 0:
                fused[cat] = p_llm * w_llm / (w_llm + w_rule * 0.3)
            elif p_rule > 0:
                fused[cat] = p_rule * w_rule / (w_rule + w_llm * 0.3)
            else:
                prior = _CATEGORY_PRIORS.get(cat, 0.05)
                fused[cat] = prior * 0.1

        # 重新归一化
        total = sum(fused.values())
        if total > 0:
            fused = {k: v / total for k, v in fused.items()}

        return fused

    def decide_deferral(self, calibrated_prob: float, category: IntentCategory) -> DeferralDecision:
        """
        基于校准概率和类别先验做风险控制决策。

        决策规则:
        - prob < escalate_threshold → ESCALATE: 分类极不可靠, 需人工介入
        - prob < risk_threshold → DEFER: 降级到规则分类器或等待更多上下文
        - prob >= risk_threshold → ROUTE: 直接路由到采集器

        UNKNOWN 类别的阈值提升 12%, 减少误路由的未知请求。
        """
        risk_threshold = self._config.risk_threshold
        escalate_threshold = self._config.escalate_threshold

        if category == IntentCategory.UNKNOWN:
            risk_threshold += 0.12
            escalate_threshold += 0.08

        if calibrated_prob < escalate_threshold:
            return DeferralDecision.ESCALATE
        if calibrated_prob < risk_threshold:
            return DeferralDecision.DEFER
        return DeferralDecision.ROUTE

    def calibrate_result(
        self,
        llm_result: Optional[IntentResult],
        rule_result: Optional[IntentResult],
    ) -> CalibratedResult:
        """
        对分类结果做完整校准。

        输入: 可选的 LLM 分类结果和规则分类结果 (至少一个非 None)
        输出: 校准后的分类结果, 含全类别概率向量和路由决策
        """
        llm_vec: Optional[Dict[IntentCategory, float]] = None
        rule_vec: Optional[Dict[IntentCategory, float]] = None

        if llm_result is not None:
            llm_vec = {}
            for cat in llm_result.matched_categories:
                llm_vec[cat] = self.calibrate_llm(llm_result.confidence, cat)
            # 剩余类别分配剩余概率
            remaining = 1.0 - sum(llm_vec.values())
            other_cats = [c for c in IntentCategory if c not in llm_vec]
            if other_cats and remaining > 0:
                per_cat = remaining / len(other_cats)
                for c in other_cats:
                    llm_vec[c] = per_cat

        if rule_result is not None:
            rule_vec = {}
            for cat in rule_result.matched_categories:
                rule_vec[cat] = self.calibrate_rule(rule_result.confidence, cat)
            remaining = 1.0 - sum(rule_vec.values())
            other_cats = [c for c in IntentCategory if c not in rule_vec]
            if other_cats and remaining > 0:
                per_cat = remaining / len(other_cats)
                for c in other_cats:
                    rule_vec[c] = per_cat

        fused = self.fuse(llm_vec, rule_vec)
        best_cat = max(fused, key=fused.get)
        best_prob = fused[best_cat]

        # 确定原始置信度
        if llm_result is not None:
            raw_conf = llm_result.confidence
        elif rule_result is not None:
            raw_conf = rule_result.confidence
        else:
            raw_conf = 0.3

        deferral = self.decide_deferral(best_prob, best_cat)
        risk_score = 1.0 - best_prob

        method = "temp_scale+platt"
        if llm_result is not None and rule_result is None:
            method = "temp_scale_only"
        elif rule_result is not None and llm_result is None:
            method = "platt_only"

        return CalibratedResult(
            category=best_cat,
            raw_confidence=raw_conf,
            calibrated_probability=best_prob,
            probability_vector=fused,
            deferral=deferral,
            risk_score=risk_score,
            calibration_method=method,
        )

    def update_config(self, **kwargs: Any) -> None:
        """在线调整校准参数 (用于自适应调优)。"""
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)


__all__ = [
    "DeferralDecision",
    "CalibratedResult",
    "CalibrationConfig",
    "ConfidenceCalibrator",
]
