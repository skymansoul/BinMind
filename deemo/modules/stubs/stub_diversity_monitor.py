# stub_diversity_monitor.py — 生态系统多样性监控（含Bootstrap+稀疏化）
# 创建于 2026-07-31
# 修改于 2026-08-05: 增加Bootstrap置信区间、Simpson指数、稀疏化曲线
#
# 度量桩生态中策略/验证/模式的多样性。
# 低多样性 = 过度依赖单一方法 = 系统性风险。
#
# 三重度量:
#   1. Shannon熵 H' = -Σ p_i ln(p_i)       — 对稀有类别敏感
#   2. Simpson指数 D = 1 - Σ p_i²           — 对优势类别敏感
#   3. Bootstrap 95%CI                       — 变化是否统计显著
#   4. 稀疏化曲线                            — 校正样本量偏差
#
# Bootstrap的必要性:
#   小样本下Shannon熵的估计偏差不可忽略。
#   例如3次template+1次llm的H'=0.56，但95%CI=[0.0, 0.69] —
#   若下次观测变为2次template+2次llm，H'=0.69在CI内，
#   不能判定为"多样性显著提升"。
import math as _math
import random as _random
from collections import Counter as _Ctr
from dataclasses import dataclass as _dc, field as _field


@_dc
class DiversityEstimate:
    """带置信区间的多样性估计。"""
    shannon: float = 0.0
    shannon_ci_low: float = 0.0
    shannon_ci_high: float = 0.0
    simpson: float = 0.0
    simpson_ci_low: float = 0.0
    simpson_ci_high: float = 0.0
    n_observations: int = 0
    n_categories: int = 0
    # 稀疏化: 在基准样本量下的期望多样性
    rarefied_shannon: float = 0.0
    rarefaction_base_n: int = 10


@_dc
class DiversityReport:
    """多样性分析报告。"""
    strategy: DiversityEstimate = None
    verification: dict = _field(default_factory=dict)
    pattern: DiversityEstimate = None
    composite: float = 0.0
    overall_alert: str = 'ok'
    recommendation: str = ''


class DiversityMonitor:
    """生态系统多样性监控。

    Bootstrap方法:
      从观测数据中有放回重采样B=1000次，每次计算Shannon/Simpson指数。
      取2.5%和97.5%分位数作为95%置信区间。

    稀疏化:
      对样本量n, 随机下采样到base_n, 重复100次取平均多样性。
      消除"样本量大的组看起来更多样"的偏差。
    """

    B = 1000
    RAREFACTION_REPS = 100

    LOW_THRESHOLD = 0.4
    CRITICAL_THRESHOLD = 0.2

    def assess(self) -> DiversityReport:
        r = DiversityReport()

        # 1. 策略多样性（含Bootstrap）
        strat_labels = self._collect_strategy_labels()
        r.strategy = self._estimate(strat_labels, 'strategy')

        # 2. 验证多样性
        r.verification = self._verification_coverage()

        # 3. 模式多样性
        pattern_labels = self._collect_pattern_labels()
        r.pattern = self._estimate(pattern_labels, 'pattern')

        # 综合: 策略和模式各半
        r.composite = round(
            0.5 * r.strategy.shannon +
            0.3 * r.verification.get('multi_stage_ratio', 0.0) +
            0.2 * r.pattern.shannon, 3)

        r.overall_alert = self._alert_level(r.composite)
        r.recommendation = self._recommend(r)
        return r

    @staticmethod
    def _collect_strategy_labels() -> list[str]:
        labels = []
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            for mod_name in list(getattr(pc, '_chains', {})):
                for entry in pc.history(mod_name):
                    if entry.strategy:
                        labels.append(entry.strategy)
        except ImportError:
            pass
        return labels

    @staticmethod
    def _collect_pattern_labels() -> list[str]:
        import re
        prefix_pat = re.compile(
            r'^(detect|extract|parse|is_|has_|get_|set_|check_|'
            r'validate|analyze|scan|find|search|generate|create|'
            r'compute|process|encode|decode|load|save|convert|filter)')
        labels = []
        try:
            from modules.stubs.stub_contract import StubContractor
            ctor = StubContractor()
            for contract in ctor.scan_all().values():
                for fc in contract.functions:
                    m = prefix_pat.match(fc.name)
                    if m:
                        labels.append(m.group(1))
        except ImportError:
            pass
        return labels

    @staticmethod
    def _verification_coverage() -> dict:
        stage_counts = _Ctr()
        total = 0
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            for mod_name in list(getattr(pc, '_chains', {})):
                for entry in pc.history(mod_name):
                    total += 1
                    stages = 0
                    if entry.verification_ok:
                        stages += 1
                    if entry.incoherence_rate >= 0:
                        stages += 1
                    stage_counts[min(stages, 3)] += 1
        except ImportError:
            pass
        multi = sum(c for s, c in stage_counts.items() if s >= 2)
        return {
            'total_verifications': total,
            'multi_stage_ratio': round(multi / max(total, 1), 3),
            'stage_distribution': dict(stage_counts),
        }

    @classmethod
    def _estimate(cls, labels: list[str], name: str) -> DiversityEstimate:
        est = DiversityEstimate()
        est.n_observations = len(labels)
        if not labels:
            est.shannon = 0.0
            est.simpson = 0.0
            return est

        counts = _Ctr(labels)
        est.n_categories = len(counts)
        est.shannon = round(cls._shannon(list(counts.values())), 3)
        est.simpson = round(cls._simpson(list(counts.values())), 3)

        # Bootstrap
        if len(labels) >= 3:
            shan_vals, simp_vals = [], []
            n = len(labels)
            for _ in range(cls.B):
                sample = [_random.choice(labels) for _ in range(n)]
                sc = _Ctr(sample)
                shan_vals.append(cls._shannon(list(sc.values())))
                simp_vals.append(cls._simpson(list(sc.values())))
            shan_vals.sort()
            simp_vals.sort()
            lo = int(cls.B * 0.025)
            hi = int(cls.B * 0.975)
            est.shannon_ci_low = round(shan_vals[lo], 3)
            est.shannon_ci_high = round(shan_vals[hi], 3)
            est.simpson_ci_low = round(simp_vals[lo], 3)
            est.simpson_ci_high = round(simp_vals[hi], 3)

        # 稀疏化: 下采样到base_n
        base_n = min(cls.RAREFACTION_REPS, len(labels))
        if len(labels) > base_n and base_n >= 2:
            rarefied = []
            for _ in range(cls.RAREFACTION_REPS):
                subsample = _random.sample(labels, base_n)
                sc = _Ctr(subsample)
                rarefied.append(cls._shannon(list(sc.values())))
            est.rarefied_shannon = round(sum(rarefied) / len(rarefied), 3)
            est.rarefaction_base_n = base_n

        return est

    @staticmethod
    def _shannon(counts: list[int]) -> float:
        total = sum(counts)
        if total == 0:
            return 0.0
        return -sum((c / total) * _math.log(c / total)
                   for c in counts if c > 0)

    @staticmethod
    def _simpson(counts: list[int]) -> float:
        total = sum(counts)
        if total == 0:
            return 0.0
        return 1.0 - sum((c / total) ** 2 for c in counts)

    @classmethod
    def _alert_level(cls, score: float) -> str:
        if score < cls.CRITICAL_THRESHOLD:
            return 'critical'
        if score < cls.LOW_THRESHOLD:
            return 'low'
        return 'ok'

    @staticmethod
    def _recommend(r: DiversityReport) -> str:
        if r.overall_alert == 'critical':
            if r.strategy and r.strategy.shannon_ci_high < 0.3:
                return ('CRITICAL: strategy diversity CI entirely below 0.3. '
                       'Single-methodology risk. Introduce alternate strategies.')
            return 'CRITICAL: ecosystem diversity critically low.'
        if r.overall_alert == 'low':
            ci_info = ''
            if r.strategy and r.strategy.n_observations < 10:
                ci_info = ' (low sample: CI may be wide)'
            return f'Low diversity.{ci_info} Consider increasing LLM usage or multi-stage verification.'
        return 'Diversity adequate. Ecosystem is robust.'


__all__ = ['DiversityEstimate', 'DiversityReport', 'DiversityMonitor']
