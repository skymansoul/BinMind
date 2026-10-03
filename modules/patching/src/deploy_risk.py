# 重构：从加权几何平均升级为序贯概率比检验

"""Deployment Risk Scorer — 基于序贯概率比检验的部署决策。

旧版使用加权几何平均融合6个信号（本质是固定权重的线性评分）。
问题：几何平均对所有信号平等对待——一个极端差的信号可能被其他信号
      的"平均效应"掩盖。生产环境中，单一维度的严重问题应阻断部署。

新版：序贯概率比检验
  对每个信号建立两个假设：
    H₀: 补丁是安全的（应部署）
    H₁: 补丁是有风险的（应阻止）

  按信号重要性降序检验。累积似然比超过上界 → 拒绝H₀（阻止部署）。
  累积似然比低于下界 → 接受H₀（批准部署）。
  在上下界之间 → 继续采集更多信号。

  此方法保证：
    - 第一类错误 (误拒安全补丁) ≤ α
    - 第二类错误 (误批风险补丁) ≤ β
    且平均所需的信号数少于固定样本量方法。

SPRT 优于加权平均：
  加权平均可能因"其他信号尚可"而批准了 ABI 不兼容的补丁。
  SPRT 按重要性排序后，ABI 不兼容作为第一信号即触发拒绝。
"""

import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

_log = logging.getLogger(__name__)


class DeployDecision(str, Enum):
    APPROVE = "approve"
    REVIEW = "review"
    REJECT = "reject"
    BLOCKED = "blocked"


@dataclass
class RiskSignals:
    patch_id: str = ""
    provenance_trust: float = 0.5
    temporal_reliability: float = 0.5
    current_efficacy: float = 0.5
    debt_score: float = 0.0
    performance_overhead_pct: float = 0.0
    abi_compatible: bool = True
    memory_safe: bool = True
    concurrency_safe: bool = True
    no_uarch_leakage: bool = True
    deployment_urgency: str = "normal"
    target_criticality: str = "medium"


@dataclass
class RiskReport:
    patch_id: str = ""
    composite_risk: float = 0.0
    decision: DeployDecision = DeployDecision.REVIEW
    hard_blockers: List[str] = field(default_factory=list)
    signals_tested: int = 0
    log_likelihood_ratio: float = 0.0
    threshold_upper: float = 0.0
    threshold_lower: float = 0.0
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id, 'risk_score': round(self.composite_risk, 3),
            'decision': self.decision.value, 'blockers': self.hard_blockers,
            'signals_tested': self.signals_tested,
            'llr': round(self.log_likelihood_ratio, 3),
            'recommendation': self.recommendation,
        }


# SPRT 引擎

class SPRTDecisionEngine:
    """序贯概率比检验决策引擎。

    参数:
      alpha: 误拒安全补丁的概率上限 (Type I error)
      beta:  误批风险补丁的概率上限 (Type II error)
    """

    def __init__(self, alpha: float = 0.05, beta: float = 0.10):
        self.alpha = alpha
        self.beta = beta
        # SPRT 边界
        self.A = (1 - beta) / alpha          # 上界: 拒绝 H₀
        self.B = beta / (1 - alpha)           # 下界: 接受 H₀

    def evaluate(self, signals: RiskSignals) -> RiskReport:
        report = RiskReport(patch_id=signals.patch_id)
        report.threshold_upper = math.log(self.A)
        report.threshold_lower = math.log(self.B)

        # 硬约束（先行检查，不参与SPRT）
        blockers = []
        if not signals.abi_compatible:
            blockers.append("ABI不兼容")
        if not signals.memory_safe:
            blockers.append("内存安全认证失败")
        if not signals.concurrency_safe:
            blockers.append("并发安全检查失败")
        if not signals.no_uarch_leakage:
            blockers.append("微架构泄漏")
        report.hard_blockers = blockers

        if blockers:
            report.decision = DeployDecision.BLOCKED
            report.composite_risk = 1.0
            report.recommendation = "硬约束阻断: " + '; '.join(blockers)
            return report

        # 信号序列（按重要性排序）
        ordered_signals = [
            ('efficacy', signals.current_efficacy, 0.25),
            ('debt', 1.0 - signals.debt_score, 0.20),
            ('temporal', signals.temporal_reliability, 0.20),
            ('provenance', signals.provenance_trust, 0.15),
            ('performance', 1.0 - min(signals.performance_overhead_pct / 100.0, 1.0), 0.20),
        ]

        llr = 0.0
        tested = 0
        for name, value, _ in ordered_signals:
            tested += 1
            # 每个信号的似然比
            # P(value | H₁=risky) / P(value | H₀=safe)
            # 假设: safe补丁的信号集中在高值 (>0.7)，risky补丁的信号集中在低值 (<0.3)
            lr = self._signal_likelihood_ratio(value)
            llr += math.log(max(lr, 1e-6))
            report.log_likelihood_ratio = llr

            if llr >= report.threshold_upper:
                report.decision = DeployDecision.REJECT
                report.signals_tested = tested
                report.composite_risk = min(1.0, 0.3 + llr / (report.threshold_upper * 2))
                report.recommendation = "SPRT上界触发 (信号%d: %s=%.2f)——累积风险证据充分" % (tested, name, value)
                return report

            if llr <= report.threshold_lower:
                report.decision = DeployDecision.APPROVE
                report.signals_tested = tested
                report.composite_risk = max(0.0, 0.1 - abs(llr) / (abs(report.threshold_lower) * 2))
                report.recommendation = "SPRT下界触发 (信号%d)——累积安全性证据充分" % tested
                return report

        # 所有信号耗尽仍未达边界 → 不确定
        report.signals_tested = tested
        report.decision = DeployDecision.REVIEW
        report.composite_risk = 0.5
        report.recommendation = "SPRT未达边界 (%d个信号)——证据不足以决策，需人工审查" % tested
        return report

    def _signal_likelihood_ratio(self, value: float) -> float:
        """计算单个信号的似然比 P(v|H₁) / P(v|H₀)。

        使用简化的双指数分布模型：
          H₀ (safe):   值集中在高区，lambda=3 (mean≈0.67)
          H₁ (risky):  值集中在低区，lambda=3 但方向相反 (mean≈0.33)
        """
        v = max(0.001, min(0.999, value))
        # 双指数 (Laplace) 分布的对数似然比
        # H₀: f(v) ∝ exp(-3*(1-v))  → 高值密度大
        # H₁: f(v) ∝ exp(-3*v)      → 低值密度大
        ll_h0 = -3.0 * (1.0 - v)
        ll_h1 = -3.0 * v
        # 似然比 = exp(ll_h1) / exp(ll_h0) = exp(ll_h1 - ll_h0)
        return math.exp(ll_h1 - ll_h0)


# 便捷接口

class BayesianRiskFuser:
    """保持旧接口兼容性的SPRT封装器。"""

    def __init__(self, alpha: float = 0.05, beta: float = 0.10):
        self._sprt = SPRTDecisionEngine(alpha, beta)

    def fuse(self, signals: RiskSignals) -> RiskReport:
        return self._sprt.evaluate(signals)
