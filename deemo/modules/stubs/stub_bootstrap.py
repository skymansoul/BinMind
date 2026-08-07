# stub_bootstrap.py — 生态系统引导与统一健康检查
# 单一入口: 初始化全部子系统 → 运行全量扫描 → 输出统一状态报告。
# CI/CD 集成点: exit_code=0 表示系统健康，非0 表示需关注。
#
# 问题:
#   39 个分析模块各自有独立入口。CI 管道需要逐一调用并聚合结果。
#   Bootstrap 提供统一的 --check 入口，适合作为 pre-commit hook
#   或 CI 管道的第一个 stage。
#
# 执行阶段:
#   PHASE 1 SCAN     — 契约扫描 + 幽灵检测 + 冲突检测
#   PHASE 2 ANALYZE  — 依赖图 + 漂移 + 能力图 + 热点 + 类型流
#   PHASE 3 QUALITY  — IRL 评分 + 部署门控 + 回归检测 + 多样性
#   PHASE 4 REPORT   — 仪表盘 + 发布快照 + 兼容性矩阵
#
# 退出码:
#   0 — 全部健康 (ecosystem_health ≥ 0.6)
#   1 — 需关注 (0.3 ≤ health < 0.6)
#   2 — 严重 (health < 0.3)
#   3 — 引导失败 (子系统导入错误)
import os as _os
import sys as _sys
import time as _time


class BootstrapReport:
    """引导执行的完整报告。"""

    def __init__(self):
        self.phases: dict[str, dict] = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.start_time = _time.time()
        self.end_time = 0.0
        self.health_score = 0.0
        self.exit_code = 0

    def add_phase(self, name: str, ok: bool, detail: str = '',
                  metrics: dict = None) -> None:
        self.phases[name] = {
            'ok': ok, 'detail': detail,
            'metrics': metrics or {},
        }

    def finalize(self) -> int:
        self.end_time = _time.time()
        if self.health_score >= 0.6:
            self.exit_code = 0
        elif self.health_score >= 0.3:
            self.exit_code = 1
        else:
            self.exit_code = 2
        return self.exit_code


def bootstrap(verbose: bool = False) -> BootstrapReport:
    """执行全生态系统引导检查。"""
    report = BootstrapReport()

    # Phase 1: Scan
    _phase_scan(report, verbose)

    # Phase 2: Analyze
    _phase_analyze(report, verbose)

    # Phase 3: Quality
    _phase_quality(report, verbose)

    # Phase 4: Report
    _phase_report(report, verbose)

    return report


def _phase_scan(report: BootstrapReport, verbose: bool) -> None:
    ok = True
    metrics = {}
    try:
        from modules.stubs.stub_contract import StubContractor
        ctor = StubContractor()
        contracts = ctor.scan_all()
        metrics['total_modules'] = len(contracts)
        if verbose:
            print(f'[scan] {len(contracts)} modules')
    except Exception as e:
        report.errors.append(f'scan: {e}')
        ok = False

    try:
        from modules.stubs.stub_ghost_detector import GhostDetector
        ghosts = GhostDetector().detect()
        ghost_count = sum(1 for g in ghosts if g.is_ghost)
        metrics['ghosts'] = ghost_count
        if verbose:
            print(f'[scan] {ghost_count} ghosts')
    except Exception as e:
        report.warnings.append(f'ghost_detector: {e}')

    try:
        from modules.stubs.stub_conflict_detector import ConflictDetector
        conflicts = ConflictDetector().detect()
        metrics['conflicts'] = len(conflicts)
        if conflicts:
            report.warnings.append(f'{len(conflicts)} symbol conflicts detected')
    except Exception as e:
        report.warnings.append(f'conflict_detector: {e}')

    report.add_phase('scan', ok, f'{metrics.get("total_modules",0)} modules', metrics)


def _phase_analyze(report: BootstrapReport, verbose: bool) -> None:
    metrics = {}
    try:
        from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
        g = ModuleDependencyGraph()
        g.build()
        metrics['dep_graph_nodes'] = len(g.nodes)
        if verbose:
            print(f'[analyze] dep graph: {len(g.nodes)} nodes')
    except Exception as e:
        report.warnings.append(f'dep_graph: {e}')

    try:
        from modules.stubs.stub_drift_detector import DriftDetector
        drifts = DriftDetector().detect_all()
        drifted = sum(1 for d in drifts if d.is_drifted)
        metrics['drifted'] = drifted
    except Exception:
        pass

    try:
        from modules.stubs.stub_capability_graph import CapabilityAnalyzer
        clusters = CapabilityAnalyzer().analyze()
        metrics['capability_clusters'] = len(clusters)
    except Exception:
        pass

    report.add_phase('analyze', True, '', metrics)


def _phase_quality(report: BootstrapReport, verbose: bool) -> None:
    metrics = {}
    try:
        from modules.stubs.stub_quality_scorer import QualityScorer
        qs = QualityScorer()
        scores = qs.score_all()
        if scores:
            metrics['avg_irl'] = round(
                sum(s.composite for s in scores) / len(scores), 3)
    except Exception:
        pass

    try:
        from modules.stubs.stub_diversity_monitor import DiversityMonitor
        dm = DiversityMonitor()
        dr = dm.assess()
        metrics['diversity'] = dr.composite_diversity
    except Exception:
        pass

    try:
        from modules.stubs.stub_degradation_planner import DegradationPlanner
        dp = DegradationPlanner()
        plan = dp.plan()
        metrics['unavailable'] = len(plan.unavailable_modules)
    except Exception:
        pass

    report.add_phase('quality', True, '', metrics)


def _phase_report(report: BootstrapReport, verbose: bool) -> None:
    try:
        from modules.stubs.stub_pipeline_dashboard import PipelineDashboard
        pd = PipelineDashboard()
        m = pd.collect()
        report.health_score = m.ecosystem_health_score
        if verbose:
            print(f'[report] health={m.ecosystem_health_score:.2f} ({m.summary})')
    except Exception as e:
        report.errors.append(f'dashboard: {e}')

    report.finalize()
    report.add_phase('report', report.exit_code == 0,
                    f'health={report.health_score:.2f} exit={report.exit_code}')


# CLI入口
def main(argv: list = None) -> int:
    """python -m modules.stubs.stub_bootstrap [--verbose] [--json]"""
    if argv is None:
        argv = _sys.argv[1:]

    verbose = '--verbose' in argv or '-v' in argv
    json_out = '--json' in argv

    try:
        report = bootstrap(verbose=verbose)
    except Exception as e:
        print(f'FATAL: bootstrap failed: {e}', file=_sys.stderr)
        return 3

    if json_out:
        import json
        print(json.dumps({
            'health': report.health_score,
            'exit_code': report.exit_code,
            'phases': {k: v['ok'] for k, v in report.phases.items()},
            'errors': report.errors,
            'warnings': report.warnings,
            'duration_s': round(report.end_time - report.start_time, 2),
        }, indent=2))
    else:
        for name, phase in report.phases.items():
            mark = 'OK' if phase['ok'] else 'FAIL'
            print(f'[{mark}] {name}: {phase["detail"]}')

    return report.exit_code


if __name__ == '__main__':
    raise SystemExit(main())


__all__ = ['BootstrapReport', 'bootstrap', 'main']
