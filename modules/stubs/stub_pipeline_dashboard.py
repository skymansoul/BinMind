# stub_pipeline_dashboard.py — 管线级可观测性仪表盘
# 聚合全部子系统的指标，输出桩生态系统整体健康视图。
# 用于回答:"这个桩系统的总体状态如何？瓶颈在哪？"
#
# 指标分层:
#   L1 库存 — 总数/已实现/占位/幽灵/漂移
#   L2 质量 — IRL分布/平均IRL/部署就绪率
#   L3 策略 — 策略分布/预算使用/成功率
#   L4 健康 — 热点/衰减/废弃候选
#   L5 管线 — 吞吐/瓶颈/反馈闭环效率
import os as _os
import time as _time
from dataclasses import dataclass as _dc, field as _field


@_dc
class PipelineMetrics:
    """管线级聚合指标。"""
    # L1 库存
    total_modules: int = 0
    implemented: int = 0
    placeholders: int = 0
    ghosts: int = 0
    drifted: int = 0
    # L2 质量
    avg_irl: float = 0.0
    irl_distribution: dict = _field(default_factory=dict)
    deploy_ready: int = 0
    # L3 策略
    strategy_distribution: dict = _field(default_factory=dict)
    llm_budget_utilization: float = 0.0
    # L4 健康
    hotspots: int = 0
    decaying_modules: int = 0
    deprecation_candidates: int = 0
    # L5 管线
    feedback_events: int = 0
    feedback_resolution_rate: float = 0.0
    regression_count: int = 0
    # 综合
    ecosystem_health_score: float = 0.0
    bottleneck: str = ''
    summary: str = ''


class PipelineDashboard:
    """管线级可观测性仪表盘。

    从所有现有子系统采集指标，计算综合健康评分:
      health = 0.25×(IRL均值) + 0.20×(实现率)
             + 0.15×(1-幽灵率) + 0.15×(1-漂移率)
             + 0.15×(反馈解决率) + 0.10×(策略多样性)
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir

    def collect(self) -> PipelineMetrics:
        m = PipelineMetrics()

        # L1
        self._collect_inventory(m)
        # L2
        self._collect_quality(m)
        # L3
        self._collect_strategy(m)
        # L4
        self._collect_health(m)
        # L5
        self._collect_pipeline(m)

        # 综合
        impl_rate = m.implemented / max(m.total_modules, 1)
        ghost_rate = m.ghosts / max(m.total_modules, 1)
        drift_rate = m.drifted / max(m.total_modules, 1)
        strat_diversity = len([v for v in m.strategy_distribution.values()
                              if v > 0]) / 4.0

        m.ecosystem_health_score = round(
            0.25 * m.avg_irl +
            0.20 * impl_rate +
            0.15 * (1.0 - ghost_rate) +
            0.15 * (1.0 - drift_rate) +
            0.15 * m.feedback_resolution_rate +
            0.10 * strat_diversity, 3)

        m.bottleneck = self._identify_bottleneck(m)
        m.summary = self._summarize(m)
        return m

    def _collect_inventory(self, m: PipelineMetrics) -> None:
        try:
            from modules.stubs.stub_contract import (
                StubContractor, ImplementationStatus)
            ctor = StubContractor(stubs_dir=self.stubs_dir)
            contracts = ctor.scan_all()
            m.total_modules = len(contracts)
            for c in contracts.values():
                if c.status in (ImplementationStatus.IMPLEMENTED.value,
                               ImplementationStatus.MIXED.value):
                    m.implemented += 1
                elif c.status in (ImplementationStatus.PLACEHOLDER.value,
                                 ImplementationStatus.MISSING.value):
                    m.placeholders += 1
        except ImportError:
            pass

        try:
            from modules.stubs.stub_ghost_detector import GhostDetector
            reports = GhostDetector(stubs_dir=self.stubs_dir).detect()
            m.ghosts = sum(1 for r in reports if r.is_ghost)
        except ImportError:
            pass

        try:
            from modules.stubs.stub_drift_detector import DriftDetector
            drs = DriftDetector(stubs_dir=self.stubs_dir).detect_all()[:1]
            m.drifted = sum(1 for d in drs if d.is_drifted) if drs else 0
        except ImportError:
            pass

    def _collect_quality(self, m: PipelineMetrics) -> None:
        try:
            from modules.stubs.stub_quality_scorer import QualityScorer
            qs = QualityScorer(stubs_dir=self.stubs_dir)
            reports = qs.score_all()
            if reports:
                m.avg_irl = round(
                    sum(r.composite for r in reports) / len(reports), 3)
                for r in reports:
                    label = r.irl_label
                    m.irl_distribution[label] = m.irl_distribution.get(label, 0) + 1
                m.deploy_ready = sum(1 for r in reports if r.irl >= 4)
        except ImportError:
            pass

    def _collect_strategy(self, m: PipelineMetrics) -> None:
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            for s in ['template', 'llm', 'manual', 'hybrid']:
                rate = pc.strategy_success_rate(s)
                m.strategy_distribution[s] = rate.get('total_attempts', 0)
        except ImportError:
            pass

    def _collect_health(self, m: PipelineMetrics) -> None:
        try:
            from modules.stubs.stub_hotspot_analyzer import HotspotAnalyzer
            nodes, _ = HotspotAnalyzer().analyze()
            m.hotspots = sum(1 for n in nodes if n.is_hotspot)
        except ImportError:
            pass
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            cands = mon.evaluate_deprecation()
            m.deprecation_candidates = len(cands)
        except ImportError:
            pass

    def _collect_pipeline(self, m: PipelineMetrics) -> None:
        try:
            from modules.stubs.stub_feedback_loop import FeedbackLoop
            fl = FeedbackLoop()
            metrics = fl.metrics()
            m.feedback_events = metrics.get('total_events', 0)
            m.feedback_resolution_rate = metrics.get('resolution_rate', 0.0)
        except ImportError:
            pass

    @staticmethod
    def _identify_bottleneck(m: PipelineMetrics) -> str:
        """识别管线瓶颈: 哪一层的"未完成率"最高。"""
        if m.total_modules == 0:
            return 'no_data'
        impl_gap = m.placeholders / max(m.total_modules, 1)
        ghost_ratio = m.ghosts / max(m.total_modules, 1)
        deploy_gap = 1.0 - (m.deploy_ready / max(m.total_modules, 1))

        issues = []
        if impl_gap > 0.5:
            issues.append(('implementation_backlog', impl_gap))
        if ghost_ratio > 0.2:
            issues.append(('ghost_cleanup', ghost_ratio))
        if deploy_gap > 0.7:
            issues.append(('deployment_readiness', deploy_gap))

        if not issues:
            return 'none_significant'
        return max(issues, key=lambda x: x[1])[0]

    @staticmethod
    def _summarize(m: PipelineMetrics) -> str:
        if m.ecosystem_health_score >= 0.7:
            return 'healthy'
        if m.ecosystem_health_score >= 0.4:
            return 'needs_attention'
        return 'critical'

    def dashboard_report(self, m: PipelineMetrics = None) -> str:
        if m is None:
            m = self.collect()

        lines = [
            '# 管线可观测性仪表盘',
            f'采集时间: {_time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'综合健康: {m.ecosystem_health_score:.2f} ({m.summary})',
            f'瓶颈: {m.bottleneck}',
            '',
            '## L1 库存',
            f'总计 {m.total_modules} | 已实现 {m.implemented} | '
            f'占位 {m.placeholders} | 幽灵 {m.ghosts} | 漂移 {m.drifted}',
            '',
            '## L2 质量',
            f'平均IRL: {m.avg_irl:.2f} | 可部署: {m.deploy_ready}',
            f'IRL分布: {m.irl_distribution}',
            '',
            '## L3 策略',
            f'分布: {m.strategy_distribution}',
            '',
            '## L4 健康',
            f'热点: {m.hotspots} | 废弃候选: {m.deprecation_candidates}',
            '',
            '## L5 管线',
            f'反馈事件: {m.feedback_events} | '
            f'解决率: {m.feedback_resolution_rate:.0%}',
        ]
        return '\n'.join(lines)


__all__ = ['PipelineMetrics', 'PipelineDashboard']
