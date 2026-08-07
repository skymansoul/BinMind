# stub_difficulty_estimator.py — 贝叶斯实现难度预估
# 创建于 2026-07-30
# 修改于 2026-08-05: 从静态加权和改为Beta-Binomial贝叶斯更新
#
# 用Beta-Binomial共轭模型预估实现难度。
# 先验来自合约特征，后验从历史实现结果更新。
# 随项目经验积累，预估越来越准。
#
# 模型:
#   难度 ~ Beta(α, β)
#   α = α₀ + successes_observed
#   β = β₀ + failures_observed
#
#   先验参数 α₀, β₀ 从合约特征计算:
#     feature_score = 0.35×复杂度 + 0.25×类型不确定性
#                   + 0.20×依赖深度 + 0.12×规模 + 0.08×历史基线
#     α₀ = 5 × (1.0 - feature_score)   # 强先验: 等效5次观测
#     β₀ = 5 × feature_score
#
#   后验均值 = α/(α+β) = 成功率估计
#   难度 = 1 - 后验均值
#
#   后验方差 = αβ / ((α+β)²(α+β+1)) → 估计不确定性
#   高方差 → 需要更多数据 → 建议"尝试实现以收集信息"
#
# 贝叶斯更新的非显而易见性:
#   传统难度估计(如McCabe圈复杂度)是静态的。
#   本模块的估计随项目经验自改进 — 每次实现尝试（成功/失败）
#   更新Beta分布参数，使后续预估更准确。
#   这是勘探-利用权衡在代码生成中的具体应用。
import math as _math
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
)


@_dc
class DifficultyEstimate:
    """一次难度预估的结果。"""
    module_name: str
    # Beta后验
    alpha: float = 5.0           # 后验 α (含先验)
    beta: float = 5.0            # 后验 β (含先验)
    success_prob: float = 0.5    # α/(α+β)
    difficulty: float = 0.5      # 1 - success_prob
    posterior_variance: float = 0.0  # 估计不确定性
    # 先验来源
    prior_alpha: float = 5.0
    prior_beta: float = 5.0
    # 似然（历史数据）
    observed_successes: int = 0
    observed_failures: int = 0
    # 特征分解
    complexity_factor: float = 0.0
    type_uncertainty: float = 0.0
    depth_factor: float = 0.0
    scale_factor: float = 0.0
    # 决策
    level: str = 'unknown'
    recommended_strategy: str = ''
    auto_feasible: bool = True
    # 信息价值: 高方差 → 尝试实现的信息价值高
    info_value: float = 0.0


class DifficultyEstimator:
    """Beta-Binomial贝叶斯难度预估器。

    先验强度 = 5 (等效于5次虚拟观测)。
    这意味着需要约10次实际观测才能显著改变先验。
    """

    PRIOR_STRENGTH = 5.0

    WEIGHTS = {
        'complexity': 0.35,
        'type_uncertainty': 0.25,
        'depth': 0.20,
        'scale': 0.12,
        'history_baseline': 0.08,
    }

    LEVELS = [
        (0.00, 'TRIVIAL'),
        (0.25, 'EASY'),
        (0.50, 'MODERATE'),
        (0.70, 'HARD'),
        (0.85, 'EXTREME'),
    ]

    def estimate(self, module_name: str,
                 contract: _StubContract = None) -> DifficultyEstimate:
        if contract is None:
            try:
                from modules.stubs.stub_contract import get_contractor
                contract = get_contractor().get(module_name)
            except ImportError:
                pass

        est = DifficultyEstimate(module_name=module_name)

        if contract is None:
            est.difficulty = 1.0
            est.level = 'EXTREME'
            est.recommended_strategy = 'manual'
            est.auto_feasible = False
            return est

        w = self.WEIGHTS
        est.complexity_factor = self._complexity_factor(contract)
        est.type_uncertainty = self._type_uncertainty(contract)
        est.depth_factor = self._depth_factor(module_name)
        est.scale_factor = min(len(contract.functions) / 10.0, 1.0)
        hist_base = self._history_baseline()

        feature_score = (
            w['complexity'] * est.complexity_factor +
            w['type_uncertainty'] * est.type_uncertainty +
            w['depth'] * est.depth_factor +
            w['scale'] * est.scale_factor +
            w['history_baseline'] * hist_base)

        # Beta先验
        est.prior_alpha = self.PRIOR_STRENGTH * (1.0 - feature_score)
        est.prior_beta = self.PRIOR_STRENGTH * feature_score

        # 加载历史似然
        successes, failures = self._load_history(module_name)
        est.observed_successes = successes
        est.observed_failures = failures

        # 后验
        est.alpha = est.prior_alpha + successes
        est.beta = est.prior_beta + failures
        total = est.alpha + est.beta
        est.success_prob = round(est.alpha / max(total, 0.01), 3)
        est.difficulty = round(1.0 - est.success_prob, 3)

        # 后验方差
        if total > 0:
            est.posterior_variance = round(
                (est.alpha * est.beta) / (total * total * (total + 1)), 4)

        # 信息价值: 方差越大→越值得尝试（勘探价值）
        est.info_value = round(est.posterior_variance, 4)

        est.level = self._to_level(est.difficulty)
        est.auto_feasible = est.difficulty < 0.85
        est.recommended_strategy = self._recommend_strategy(est)
        return est

# 先验因子
    @staticmethod
    def _complexity_factor(contract: _StubContract) -> float:
        if not contract.functions:
            return 0.0
        c_weights = {'high': 1.0, 'medium': 0.5, 'low': 0.1}
        return sum(c_weights.get(f.complexity, 0.5)
                  for f in contract.functions) / max(len(contract.functions), 1)

    @staticmethod
    def _type_uncertainty(contract: _StubContract) -> float:
        if not contract.functions:
            return 1.0
        total, annotated = 0, 0
        for fc in contract.functions:
            params = [p for p in fc.params
                     if p.kind not in ('varargs', 'varkw')]
            total += len(params)
            annotated += sum(1 for p in params
                           if p.annotation and p.annotation.strip())
        return round(1.0 - annotated / max(total, 1), 3)

    @staticmethod
    def _depth_factor(module_name: str) -> float:
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph()
            g.build()
            node = g.nodes.get(module_name)
            return min((node.topo_depth if node else 0) / 5.0, 1.0)
        except ImportError:
            return 0.0

    @staticmethod
    def _history_baseline() -> float:
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            failures = total = 0
            for mod in getattr(pc, '_chains', {}):
                for entry in pc.history(mod):
                    total += 1
                    if not entry.verification_ok:
                        failures += 1
            return failures / max(total, 1) if total >= 5 else 0.5
        except ImportError:
            return 0.5

# 贝叶斯更新（似然）
    @staticmethod
    def _load_history(module_name: str) -> tuple[int, int]:
        """从ProvenanceChain加载该模块的历史实现结果。"""
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            successes = failures = 0
            for entry in pc.history(module_name):
                if entry.verification_ok:
                    successes += 1
                else:
                    failures += 1
            return successes, failures
        except ImportError:
            return 0, 0

    @classmethod
    def _to_level(cls, difficulty: float) -> str:
        for threshold, label in reversed(cls.LEVELS):
            if difficulty >= threshold:
                return label
        return 'TRIVIAL'

    @staticmethod
    def _recommend_strategy(est: DifficultyEstimate) -> str:
        if est.difficulty < 0.25:
            return 'template_only'
        if est.difficulty < 0.5:
            return 'template_first_llm_fallback'
        if est.difficulty < 0.7:
            return 'hybrid_composer'
        if est.difficulty < 0.85:
            return 'llm_required_with_review'
        return 'manual_only'

    def estimate_all(self) -> list[DifficultyEstimate]:
        try:
            from modules.stubs.stub_contract import StubContractor
            ctor = StubContractor()
            contracts = ctor.scan_all()
        except ImportError:
            return []
        estimates = []
        for name in contracts:
            if name.startswith('stub_'):
                continue
            estimates.append(self.estimate(name, contracts[name]))
        estimates.sort(key=lambda e: -e.difficulty)
        return estimates


__all__ = ['DifficultyEstimate', 'DifficultyEstimator']
