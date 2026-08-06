"""
自愈分类器监控 (SHCM)。

SHML (arXiv:2411.00186) 提出诊断驱动的自愈范式:
监控→诊断→适配→验证。本模块将该范式适配到安全意图分类。
不同于通用 ML 的自愈, 此处监控的是 "分类器输出质量" 而非
"模型损失函数" —— 分类器是外部 LLM API 和规则引擎的组合,
无梯度可计算, 只能从输出统计量推断退化。

监控四维信号:
1. 置信度 EWMA: 检测置信度系统性偏移 (膨胀或坍缩)
2. 类别熵 CUSUM: 检测类别分布突变 (概念漂移)
3. 拒绝率: defer/escalate 比例的趋势变化
4. LLM-Rule 分歧度: 两分类器输出差距的扩大

诊断后触发定向恢复: 温度重校准 / 规则权重调整 / 提示适配建议。
"""

# File: self_healing.py  |  2026-07-28 create SHCM

from __future__ import annotations

import math
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

from .intent_route import IntentCategory


class DegradationType(Enum):
    NONE = "none"
    CONFIDENCE_INFLATION = "confidence_inflation"    # 置信度系统性偏高
    CONFIDENCE_DEFLATION = "confidence_deflation"    # 置信度系统性偏低
    CATEGORY_COLLAPSE = "category_collapse"          # 类别分布坍塌
    LLM_RULE_DIVERGENCE = "llm_rule_divergence"      # 双分类器分歧加剧
    DEFERRAL_SURGE = "deferral_surge"                # 拒绝率异常上升


@dataclass
class ClassifierSnapshot:
    """单次分类的快照, 用于统计追踪。"""
    llm_confidence: float
    rule_confidence: float
    llm_category: IntentCategory
    rule_category: IntentCategory
    deferral: str  # "route" | "defer" | "escalate"
    timestamp: float


@dataclass
class HealthReport:
    """分类器健康报告。"""
    degradation_detected: bool
    degradation_type: DegradationType
    severity: float               # [0, 1], 退化严重程度
    ewma_confidence: float         # 当前置信度 EWMA
    category_entropy: float        # 当前类别分布熵
    llm_rule_agreement: float      # LLM 与规则分类器的一致率
    deferral_rate: float           # 当前拒绝率
    recommended_action: str        # 恢复建议


class SelfHealingMonitor:
    """
    自愈监控器。

    使用 EWMA (指数加权移动平均) 追踪置信度趋势,
    CUSUM (累积和) 检测类别分布突变,
    滑动窗口计算 LLM-Rule 一致率和拒绝率。

    EWMA: S_t = α * x_t + (1-α) * S_{t-1}
    α = 0.1 对短期波动不敏感, 适合检测趋势性退化。
    """

    def __init__(
        self,
        window_size: int = 80,
        ewma_alpha: float = 0.10,
        inflation_threshold: float = 0.12,
        deflation_threshold: float = 0.12,
        divergence_threshold: float = 0.25,
    ):
        self._snapshots: Deque[ClassifierSnapshot] = deque(maxlen=window_size)
        self._alpha = ewma_alpha
        self._ewma_conf: Optional[float] = None
        self._cusum_high: float = 0.0   # CUSUM 上界
        self._cusum_low: float = 0.0    # CUSUM 下界
        self._baseline_entropy: Optional[float] = None
        self._inflate_thresh = inflation_threshold
        self._deflate_thresh = deflation_threshold
        self._diverge_thresh = divergence_threshold
        self._last_health: Optional[HealthReport] = None

    def record(
        self,
        llm_conf: float, rule_conf: float,
        llm_cat: IntentCategory, rule_cat: IntentCategory,
        deferral: str,
    ) -> Optional[HealthReport]:
        """
        记录一次分类快照, 返回健康报告 (如有退化)。
        仅在窗口半满 (≥ 40 条) 后开始产出报告。
        """
        snap = ClassifierSnapshot(
            llm_confidence=llm_conf, rule_confidence=rule_conf,
            llm_category=llm_cat, rule_category=rule_cat,
            deferral=deferral, timestamp=time.time(),
        )
        self._snapshots.append(snap)

        # 更新 EWMA
        if self._ewma_conf is None:
            self._ewma_conf = llm_conf
        else:
            self._ewma_conf = self._alpha * llm_conf + (1 - self._alpha) * self._ewma_conf

        if len(self._snapshots) < 40:
            return None

        return self._diagnose()

    def _diagnose(self) -> HealthReport:
        snaps = list(self._snapshots)
        n = len(snaps)

        # 1. 置信度 EWMA 检查
        confs = [s.llm_confidence for s in snaps]
        mean_conf = sum(confs) / n
        if self._ewma_conf is not None:
            conf_delta = self._ewma_conf - mean_conf
        else:
            conf_delta = 0.0

        # 2. 类别熵
        cats = [s.llm_category for s in snaps]
        counter = Counter(cats)
        entropy = 0.0
        for count in counter.values():
            p = count / n
            entropy -= p * math.log2(p)
        max_ent = math.log2(len(IntentCategory))
        norm_entropy = entropy / max_ent if max_ent > 0 else 0.0

        if self._baseline_entropy is None:
            self._baseline_entropy = norm_entropy

        # CUSUM 更新 — 检测熵的持续性偏移
        entropy_deviation = norm_entropy - self._baseline_entropy
        k = 0.05  # 允许的漂移范围
        self._cusum_high = max(0, self._cusum_high + entropy_deviation - k)
        self._cusum_low = max(0, self._cusum_low - entropy_deviation - k)

        # 3. LLM-Rule 一致率
        agreements = sum(1 for s in snaps[-30:] if s.llm_category == s.rule_category)
        agreement_rate = agreements / min(30, n)

        # 4. 拒绝率
        deferrals = sum(1 for s in snaps[-30:] if s.deferral != "route")
        deferral_rate = deferrals / min(30, n)

        # 诊断决策树
        degradation = DegradationType.NONE
        severity = 0.0
        if conf_delta > self._inflate_thresh:
            degradation = DegradationType.CONFIDENCE_INFLATION
            severity = conf_delta / 0.25
        elif conf_delta < -self._deflate_thresh and self._ewma_conf is not None and self._ewma_conf < 0.5:
            degradation = DegradationType.CONFIDENCE_DEFLATION
            severity = abs(conf_delta) / 0.25

        # CUSUM 检测类别分布突变
        if self._cusum_high > 0.15 or self._cusum_low > 0.15:
            if degradation == DegradationType.NONE:
                degradation = DegradationType.CATEGORY_COLLAPSE
                severity = max(self._cusum_high, self._cusum_low) / 0.30
            else:
                severity = max(severity, max(self._cusum_high, self._cusum_low) / 0.30)

        if agreement_rate < (1.0 - self._diverge_thresh):
            if degradation == DegradationType.NONE:
                degradation = DegradationType.LLM_RULE_DIVERGENCE
                severity = (1.0 - agreement_rate) / 0.5
            else:
                severity = max(severity, (1.0 - agreement_rate) / 0.5)

        if deferral_rate > 0.40:
            if degradation == DegradationType.NONE:
                degradation = DegradationType.DEFERRAL_SURGE
                severity = deferral_rate / 0.7

        severity = min(1.0, severity)

        # 恢复建议
        if degradation == DegradationType.CONFIDENCE_INFLATION:
            action = "提高温度缩放参数 T, 当前 EWMA 高于历史均值, 建议 T += 0.5"
        elif degradation == DegradationType.CONFIDENCE_DEFLATION:
            action = "降低温度缩放参数 T, 或检查 LLM API 模型版本是否变更"
        elif degradation == DegradationType.CATEGORY_COLLAPSE:
            action = "类别分布坍塌, 检查近期查询是否集中于少数领域, 或规则关键词需更新"
        elif degradation == DegradationType.LLM_RULE_DIVERGENCE:
            action = "LLM 与规则分类器分歧加剧, 运行规则提取器检查过时规则, 或 LLM prompt 需要调整"
        elif degradation == DegradationType.DEFERRAL_SURGE:
            action = "拒绝率异常, 检查校准参数是否需要在线重标定"
        else:
            action = "无需恢复动作"

        report = HealthReport(
            degradation_detected=degradation != DegradationType.NONE,
            degradation_type=degradation,
            severity=round(severity, 4),
            ewma_confidence=round(self._ewma_conf or mean_conf, 4),
            category_entropy=round(norm_entropy, 4),
            llm_rule_agreement=round(agreement_rate, 4),
            deferral_rate=round(deferral_rate, 4),
            recommended_action=action,
        )
        self._last_health = report
        return report

    @property
    def last_health(self) -> Optional[HealthReport]:
        return self._last_health

    def reset_baseline(self) -> None:
        """重置基线 — 在环境变更后调用。"""
        self._ewma_conf = None
        self._baseline_entropy = None
        self._cusum_high = 0.0
        self._cusum_low = 0.0


__all__ = [
    "DegradationType",
    "ClassifierSnapshot",
    "HealthReport",
    "SelfHealingMonitor",
]
