# stub_deploy_gate.py — 部署门控引擎
# 创建于 2026-07-30
# 修改于 2026-08-04: 移除虚假SHAP类比，特征贡献正确描述为加权分解
#
# 聚合全部质量/验证/回归信号，输出 PROMOTE / HOLD / ROLLBACK 决策。
# 每条决策附带加权贡献分解，支持 CI/CD 管道集成。
#
# 方案 — 加权门控评分 + 贡献分解:
#   1. 从各子系统采集 7 个门控信号
#   2. 加权聚合为 deploy_score (0~1):
#      IRL(0.25) + regression_inverse(0.20) + verification(0.18)
#      + incoherence_inverse(0.15) + provenance(0.10)
#      + type_safety(0.07) + documentation(0.05)
#   3. 决策: >=0.70->PROMOTE, [0.40,0.70)->HOLD, <0.40->ROLLBACK
#   4. 每条决策附带加权贡献分解 (contribution_i = signal_value_i * weight_i)
#      — 这是简单的乘法分解，非SHAP/LIME等博弈论解释方法。
#      其作用是让运维人员看到各信号对最终决策的贡献量级。
#
# 区别于 的 LLM 应用自测试门控:
#   该论文针对 LLM 应用的非确定性输出设计门控维度。
#   本模块针对桩实现的确定性质量信号设计门控维度。
import os as _os
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


class GateDecision:
    PROMOTE = 'PROMOTE'
    HOLD = 'HOLD'
    ROLLBACK = 'ROLLBACK'


@_dc
class GateSignal:
    """单个门控信号。"""
    name: str
    value: float = 0.0      # 归一化到 [0,1], 1=最好
    weight: float = 0.0
    contribution: float = 0.0  # value × weight
    source: str = ''          # 信号来源描述
    detail: str = ''


@_dc
class GateResult:
    """一次部署门控决策的完整结果。"""
    module_name: str
    deploy_score: float = 0.0
    decision: str = GateDecision.HOLD
    signals: list = _field(default_factory=list)  # list[GateSignal]
    # 阻断因素
    blockers: list = _field(default_factory=list)
    # 通过但需关注的事项
    warnings: list = _field(default_factory=list)
    # 决策解释
    explanation: str = ''


class DeployGate:
    """部署门控引擎。

    权重设计原则:
      - IRL 权重最高 (0.25): 实现就绪度是部署决策的核心依据
      - 回归检测 (0.20): 新版本不能比旧版本差
      - 验证通过 (0.18): 基础功能正确性
      - 非相干性 (0.15): 多策略一致性是高质量信号
      - 溯源完整性 (0.10): 有历史记录 → 可审计 → 可信任
      - 类型安全 (0.07): 补充信号
      - 文档化 (0.05): 补充信号
    """

    WEIGHTS = {
        'irl': 0.25,
        'regression': 0.20,
        'verification': 0.18,
        'incoherence': 0.15,
        'provenance': 0.10,
        'type_safety': 0.07,
        'documentation': 0.05,
    }

    PROMOTE_THRESHOLD = 0.70
    HOLD_THRESHOLD = 0.40

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir

    def evaluate(self, module_name: str) -> GateResult:
        """评估指定模块是否可以部署。"""
        result = GateResult(module_name=module_name)

        signals = [
            self._signal_irl(module_name),
            self._signal_regression(module_name),
            self._signal_verification(module_name),
            self._signal_incoherence(module_name),
            self._signal_provenance(module_name),
            self._signal_type_safety(module_name),
            self._signal_documentation(module_name),
        ]

        # 计算贡献
        total = 0.0
        for sig in signals:
            sig.contribution = round(sig.value * sig.weight, 4)
            total += sig.contribution

        result.signals = [s for s in signals if s is not None]
        result.deploy_score = round(total, 3)

        # 判定
        if result.deploy_score >= self.PROMOTE_THRESHOLD:
            result.decision = GateDecision.PROMOTE
        elif result.deploy_score >= self.HOLD_THRESHOLD:
            result.decision = GateDecision.HOLD
        else:
            result.decision = GateDecision.ROLLBACK

        # 阻断因素: 任一关键信号 < 0.3
        critical_signals = ['irl', 'regression', 'verification']
        for sig in result.signals:
            if sig.name in critical_signals and sig.value < 0.3:
                result.blockers.append(
                    f'{sig.name}={sig.value:.2f} (threshold=0.30)')

        # 警告: 非关键信号 < 0.5
        for sig in result.signals:
            if sig.name not in critical_signals and sig.value < 0.5:
                result.warnings.append(
                    f'{sig.name}={sig.value:.2f} below 0.50')

        result.explanation = self._explain(result)
        return result

# 信号采集
    def _signal_irl(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='irl', weight=self.WEIGHTS['irl'],
                        source='QualityScorer')
        try:
            from modules.stubs.stub_quality_scorer import QualityScorer
            qs = QualityScorer(stubs_dir=self.stubs_dir)
            r = qs.score(module_name)
            sig.value = r.composite
            sig.detail = f'IRL={r.irl} ({r.irl_label})'
        except ImportError:
            sig.value = 0.3
            sig.detail = 'IRL unavailable'
        return sig

    def _signal_regression(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='regression', weight=self.WEIGHTS['regression'],
                        source='RegressionDetector')
        try:
            from modules.stubs.stub_regression_detector import RegressionDetector
            rd = RegressionDetector()
            r = rd.detect(module_name)
            sig.value = 0.0 if r.is_regression else 1.0
            sig.detail = f'regression={r.is_regression}, checks={r.regression_count}'
        except ImportError:
            sig.value = 0.5
            sig.detail = 'regression check unavailable'
        return sig

    def _signal_verification(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='verification',
                        weight=self.WEIGHTS['verification'],
                        source='ProvenanceChain')
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            last = pc.find_last_verified(module_name)
            if last and last.verification_ok:
                sig.value = 1.0
                sig.detail = f'last_verified={last.entry_id}'
            elif last:
                sig.value = 0.2
                sig.detail = 'last verification failed'
            else:
                sig.value = 0.1
                sig.detail = 'no verification record'
        except ImportError:
            sig.value = 0.3
        return sig

    def _signal_incoherence(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='incoherence',
                        weight=self.WEIGHTS['incoherence'],
                        source='ProvenanceChain')
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            chain = pc.history(module_name)
            last = chain[-1] if chain else None
            if last and last.incoherence_rate >= 0:
                inc = last.incoherence_rate
                sig.value = max(0.0, 1.0 - inc * 5)
                sig.detail = f'incoherence={inc:.3f}'
            else:
                sig.value = 0.4
                sig.detail = 'no incoherence data'
        except ImportError:
            sig.value = 0.4
        return sig

    def _signal_provenance(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='provenance',
                        weight=self.WEIGHTS['provenance'],
                        source='ProvenanceChain')
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            vr = pc.verify(module_name)
            chain_len = vr.get('total_entries', 0)
            sig.value = min(chain_len / 3.0, 1.0) if vr.get('valid') else 0.2
            sig.detail = f'chain_len={chain_len}, valid={vr.get("valid")}'
        except ImportError:
            sig.value = 0.0
        return sig

    def _signal_type_safety(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='type_safety',
                        weight=self.WEIGHTS['type_safety'],
                        source='QualityScorer')
        try:
            from modules.stubs.stub_quality_scorer import QualityScorer
            qs = QualityScorer(stubs_dir=self.stubs_dir)
            r = qs.score(module_name)
            sig.value = r.scores.type_safety
            sig.detail = f'type_safety={r.scores.type_safety:.2f}'
        except ImportError:
            sig.value = 0.3
        return sig

    def _signal_documentation(self, module_name: str) -> GateSignal:
        sig = GateSignal(name='documentation',
                        weight=self.WEIGHTS['documentation'],
                        source='QualityScorer')
        try:
            from modules.stubs.stub_quality_scorer import QualityScorer
            qs = QualityScorer(stubs_dir=self.stubs_dir)
            r = qs.score(module_name)
            sig.value = r.scores.documentation
            sig.detail = f'documentation={r.scores.documentation:.2f}'
        except ImportError:
            sig.value = 0.2
        return sig

    @staticmethod
    def _explain(result: GateResult) -> str:
        top_contributors = sorted(result.signals,
                                 key=lambda s: -s.contribution)[:3]
        parts = [f'{s.name}({s.contribution:.3f})' for s in top_contributors]
        base = f'Top contributors: {", ".join(parts)}. '
        if result.blockers:
            base += f'Blockers: {"; ".join(result.blockers)}. '
        if result.warnings:
            base += f'Warnings: {len(result.warnings)} items.'
        return base

# 序贯决策优化
    # 按信号采集成本排序，逐阶段评估。若剩余信号无论取何值都无法改变决策，
    # 则提前退出，节省后续信号的计算开销。
    #
    # 成本估计 (毫秒):
    #   irl: 15 (需运行QualityScorer), regression: 5, verification: 2,
    #   incoherence: 2, provenance: 1, type_safety: 0(已包含在irl中), documentation: 0
    SIGNAL_COST = {
        'documentation': 0, 'type_safety': 0, 'provenance': 1,
        'incoherence': 2, 'verification': 2, 'regression': 5, 'irl': 15,
    }

    _SIGNAL_METHODS = {
        'documentation': '_signal_documentation',
        'type_safety': '_signal_type_safety',
        'provenance': '_signal_provenance',
        'incoherence': '_signal_incoherence',
        'verification': '_signal_verification',
        'regression': '_signal_regression',
        'irl': '_signal_irl',
    }

    def evaluate_sequential(self, module_name: str) -> GateResult:
        """序贯评估: 低成本信号优先，可决策时提前退出。

        与 evaluate() 结果相同，但在明确案例中跳过昂贵信号。
        例如: 前3个信号总分已达0.75，剩余4个信号即使全0也能PROMOTE → 提前退出。
        """
        result = GateResult(module_name=module_name)
        signals = []
        total_weight = sum(self.WEIGHTS.values())
        current_score = 0.0
        remaining_weight = total_weight

        # 按成本升序排列信号
        ordered = sorted(self.WEIGHTS.keys(),
                        key=lambda k: self.SIGNAL_COST.get(k, 99))

        for name in ordered:
            # 获取信号
            method_name = self._SIGNAL_METHODS.get(name)
            if method_name is None:
                continue
            sig = getattr(self, method_name)(module_name)
            if sig is None:
                remaining_weight -= self.WEIGHTS[name]
                continue

            sig.contribution = round(sig.value * sig.weight, 4)
            current_score += sig.contribution
            remaining_weight -= sig.weight
            signals.append(sig)

            # 序贯退出判定
            best_case = current_score + remaining_weight
            worst_case = current_score

            if best_case < self.HOLD_THRESHOLD:
                # 即使剩余全部满分也无法HOLD → ROLLBACK
                break
            if worst_case >= self.PROMOTE_THRESHOLD:
                # 即使剩余全部零分也已PROMOTE → 提前退出
                break

        result.signals = [s for s in signals if s is not None]
        result.deploy_score = round(current_score, 3)

        if result.deploy_score >= self.PROMOTE_THRESHOLD:
            result.decision = GateDecision.PROMOTE
        elif result.deploy_score >= self.HOLD_THRESHOLD:
            result.decision = GateDecision.HOLD
        else:
            result.decision = GateDecision.ROLLBACK

        # 阻断和警告与 evaluate() 一致
        critical_signals = ['irl', 'regression', 'verification']
        for sig in result.signals:
            if sig.name in critical_signals and sig.value < 0.3:
                result.blockers.append(
                    f'{sig.name}={sig.value:.2f}')
        for sig in result.signals:
            if sig.name not in critical_signals and sig.value < 0.5:
                result.warnings.append(
                    f'{sig.name}={sig.value:.2f}')

        result.explanation = self._explain(result)
        return result

# CI/CD 集成
    def ci_check(self, module_name: str, sequential: bool = False) -> tuple[int, dict]:
        """CI/CD gate check. sequential=True uses early-exit optimization."""
        result = self.evaluate_sequential(module_name) if sequential else self.evaluate(module_name)
        exit_map = {GateDecision.PROMOTE: 0,
                   GateDecision.HOLD: 1,
                   GateDecision.ROLLBACK: 2}
        return exit_map.get(result.decision, 2), {
            'module': module_name,
            'decision': result.decision,
            'score': result.deploy_score,
            'blockers': result.blockers,
            'signals_evaluated': len(result.signals),
            'explanation': result.explanation,
        }


__all__ = ['GateDecision', 'GateSignal', 'GateResult', 'DeployGate']
