# main__.py — 桩管理系统统一CLI入口
# python -m modules.stubs <command> [options]
#
# 命令:
#   scan       — 扫描全部桩模块，输出契约+幽灵+冲突摘要
#   implement  — 按优先级渐进实现前N个模块
#   verify     — 运行全量验证（签名+IO+MR+沙箱）
#   quality    — IRL评分 + 部署门控
#   report     — 管线仪表盘 + 发布快照
#   bootstrap  — 四阶段生态系统引导检查（CI/CD入口）
import os as _os
import sys as _sys


def _cmd_scan(args: list) -> int:
    from modules.stubs.stub_contract import StubContractor
    from modules.stubs.stub_ghost_detector import GhostDetector
    from modules.stubs.stub_conflict_detector import ConflictDetector

    ctor = StubContractor()
    contracts = ctor.scan_all()
    ghosts = GhostDetector().detect()
    conflicts = ConflictDetector().detect()

    impl = sum(1 for c in contracts.values() if c.status == 'implemented')
    ghost_n = sum(1 for g in ghosts if g.is_ghost)

    print(f'Modules: {len(contracts)} (implemented={impl}, '
          f'placeholder={len(contracts)-impl})')
    print(f'Ghosts: {ghost_n}')
    print(f'Conflicts: {len(conflicts)}')
    if conflicts:
        for c in conflicts[:5]:
            mods = ', '.join(m for m, _ in c.modules)
            print(f'  [{c.risk}] {c.symbol_name}: {mods} — {c.detail}')
    return 0


def _cmd_implement(args: list) -> int:
    n = 5
    for i, a in enumerate(args):
        if a == '--top' and i + 1 < len(args):
            n = int(args[i + 1])
    from modules.stubs.stub_gradual_engine import GradualEngine, GradualConfig
    eng = GradualEngine(config=GradualConfig(dry_run='--dry-run' in args))
    results = eng.implement_top(n)
    for gen in results:
        mark = 'OK' if gen.status == 'generated' else 'FAIL'
        print(f'[{mark}] {gen.module_name}: {gen.status} ({gen.strategy})')
    return 0


def _cmd_verify(args: list) -> int:
    module = args[0] if args else None
    if not module:
        print('Usage: verify <module_name> [--sandbox]')
        return 1

    from modules.stubs.stub_contract import get_contractor
    from modules.stubs.stub_gradual_engine import TemplateGenerator, ContractVerifier

    contract = get_contractor().get(module)
    if contract is None:
        print(f'Module not found: {module}')
        return 1

    src = TemplateGenerator().generate(contract)
    cv = ContractVerifier(run_io_checks=True)
    result = cv.verify(src, contract)
    print(f'Verification: {'OK' if result.ok else 'FAIL'} — {result.feedback}')
    if result.signature_violations:
        for v in result.signature_violations[:5]:
            print(f'  SIG: {v}')
    if result.io_violations:
        for v in result.io_violations[:5]:
            print(f'  IO: {v}')

    if '--sandbox' in args:
        from modules.stubs.stub_sandbox import SandboxExecutor
        se = SandboxExecutor()
        for fc in contract.functions:
            r = se.execute(src, module, fc.name)
            print(f'  Sandbox({fc.name}): safe={r.safe} crashed={r.crashed}')
    return 0 if result.ok else 1


def _cmd_quality(args: list) -> int:
    module = args[0] if args else None
    from modules.stubs.stub_quality_scorer import QualityScorer
    from modules.stubs.stub_deploy_gate import DeployGate

    if module:
        r = QualityScorer().score(module)
        dg = DeployGate().evaluate(module)
        print(f'{module}: IRL={r.irl}({r.irl_label}) composite={r.composite}')
        print(f'  Deploy: {dg.decision} (score={dg.deploy_score})')
        if dg.blockers:
            print(f'  Blockers: {'; '.join(dg.blockers)}')
    else:
        qs = QualityScorer()
        scores = qs.score_all()
        for s in scores[:10]:
            print(f'{s.module_name}: IRL={s.irl}({s.irl_label})')
    return 0


def _cmd_report(args: list) -> int:
    from modules.stubs.stub_pipeline_dashboard import PipelineDashboard
    pd = PipelineDashboard()
    print(pd.dashboard_report())
    return 0


def _cmd_bootstrap(args: list) -> int:
    from modules.stubs.stub_bootstrap import bootstrap
    br = bootstrap(verbose='--verbose' in args or '-v' in args)
    for name, phase in br.phases.items():
        mark = 'OK' if phase['ok'] else 'FAIL'
        print(f'[{mark}] {name}: {phase['detail']}')
    if br.errors:
        print(f'Errors: {'; '.join(br.errors[:3])}')
    if br.warnings:
        print(f'Warnings: {len(br.warnings)}')
    return br.exit_code


_COMMANDS = {
    'scan': _cmd_scan,
    'implement': _cmd_implement,
    'verify': _cmd_verify,
    'quality': _cmd_quality,
    'report': _cmd_report,
    'bootstrap': _cmd_bootstrap,
}


def main(argv: list = None) -> int:
    if argv is None:
        argv = _sys.argv[1:]

    if not argv or argv[0] in ('-h', '--help'):
        print('StubGradual CLI — python -m modules.stubs <command>')
        for name in sorted(_COMMANDS):
            print(f'  {name}')
        return 0

    cmd = argv[0]
    if cmd not in _COMMANDS:
        print(f'Unknown command: {cmd}')
        return 1

    return _COMMANDS[cmd](argv[1:])


if __name__ == '__main__':
    raise SystemExit(main())


__all__ = ['main']
