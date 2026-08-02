#!/usr/bin/env python3
"""Patching CLI — provisional implementation, pending rewrite."""

import argparse, sys, os, json, logging

_curdir = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_curdir)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from patching.src.config import config, load_config

logger = logging.getLogger(__name__)


def setup_logging(level=None, log_file=None):
    lvl = level or getattr(config, 'LOG_LEVEL', 'INFO')
    lf = log_file or getattr(config, 'LOG_FILE', None)
    fmt = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    handlers = [logging.StreamHandler(sys.stderr)]
    if lf:
        try:
            os.makedirs(os.path.dirname(lf), exist_ok=True)
            handlers.append(logging.FileHandler(lf, encoding='utf-8'))
        except Exception:
            pass
    logging.basicConfig(level=getattr(logging, lvl.upper(), logging.INFO), format=fmt, handlers=handlers)


def cmd_analyze(args):
    print(f"[*] analyzing: {args.binary}")
    from patching.src.auto_patcher import AutoPatcher
    patcher = AutoPatcher(args.binary)
    result = patcher.analyze_and_patch()
    if result.analysis_success:
        print(f"[+] done. {len(result.patches)} patches, {len(result.vulnerabilities)} vulns found")
        if args.output:
            patcher.save_patched_binary(args.output)
            print(f"[+] patched binary saved to: {args.output}")
    else:
        print(f"[-] analysis failed: {result.warnings}")
        return 1
    if args.json:
        import json as _json
        print(_json.dumps({'success': result.analysis_success, 'vuln_count': len(result.vulnerabilities),
            'patch_count': len(result.patches), 'hardening_count': len(result.hardenings),
            'warnings': result.warnings}, indent=2))
    return 0


def cmd_diff(args):
    print(f"[*] diffing: {args.original} -> {args.patched}")
    from patching.src.patch_diff_locator import analyze_patch_diff
    result = analyze_patch_diff(args.original, args.patched, output_dir=args.output, use_ai=not args.no_ai)
    if result.error:
        print(f"[-] diff failed: {result.error}")
        return 1
    print(f"[+] {len(result.function_diffs)} function diffs, {len(result.security_patches)} security patches")
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        report_path = os.path.join(args.output, 'patch_diff_report.txt')
        with open(report_path, 'w', encoding='utf-8') as fh:
            fh.write(result.diff_report)
        print(f"[+] report saved to: {report_path}")
    return 0


def cmd_root_cause(args):
    print(f"[*] analyzing crash: {args.crash}")
    from patching.src.auto_root_cause import AutoRootCauseAnalyzer, format_root_cause_report
    analyzer = AutoRootCauseAnalyzer()
    report = analyzer.analyze(args.crash)
    formatted = format_root_cause_report(report)
    print(formatted)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(formatted)
            fh.write('\n')
            fh.write(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        print(f"[+] report saved to: {args.output}")
    return 0


def cmd_quality(args):
    print(f"[*] evaluating patch quality: {args.patch_data}")
    from patching.src.patch_quality_evaluator import PatchQualityEvaluator
    with open(args.patch_data, 'r', encoding='utf-8') as fh:
        patch_data = json.load(fh)
    evaluator = PatchQualityEvaluator()
    assessment = evaluator.evaluate(patch_data)
    result = assessment.to_dict()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_rules(args):
    from patching.src.rule_engine import RuleEngine
    engine = RuleEngine(args.rules_dir)
    engine.load_rules()
    if args.list:
        for rule in engine.rules:
            status = 'v' if rule.enabled else 'x'
            print(f"  [{status}] {rule.id}: {rule.name} ({rule.severity})")
    elif args.rule_id:
        if args.enable:
            engine.enable_rule(args.rule_id)
            print(f"[+] enabled: {args.rule_id}")
        elif args.disable:
            engine.disable_rule(args.rule_id)
            print(f"[+] disabled: {args.rule_id}")
    return 0


def cmd_impact(args):
    print(f"[*] analyzing impact: {args.before} -> {args.after}")
    from patching.src.patch_impact_analyzer import analyze_patch_impact
    result = analyze_patch_impact(args.before, args.after)
    if result.get('success'):
        report = result['report']
        print(f"  risk level: {report.get('risk_level', 'unknown')}")
        print(f"  risk score: {report.get('overall_risk_score', 0)}")
        print(f"  changes: {len(report.get('changes', []))}")
    else:
        print(f"[-] impact analysis failed")
        return 1
    return 0


def cmd_self_heal(args):
    print(f"[*] self-healing: {args.binary}")
    from patching.self_healing_rewriter import apply_self_healing_protection
    result = apply_self_healing_protection(binary_path=args.binary, cve_id=args.cve_id, framework=args.framework)
    if result.get('success'):
        print(f"[+] framework: {result.get('framework')}")
        print(f"[+] rules applied: {len(result.get('rules_applied', []))}")
        print(f"[+] overhead: {result.get('performance_overhead', 0):.2f}%")
        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result.get('instrumented_code', ''))
            print(f"[+] script saved to: {args.output}")
    else:
        print(f"[-] self-healing failed: {result.get('error', 'unknown')}")
        return 1
    return 0


def cmd_recompile(args):
    print(f"[*] recompile check: {args.source}")
    from patching.recompiler_check import RecompilerVerifier
    if args.source == '-':
        source_code = sys.stdin.read()
    else:
        with open(args.source, 'r', encoding='utf-8') as fh:
            source_code = fh.read()
    verifier = RecompilerVerifier(compiler_path=args.compiler or config.get('compiler_path', 'gcc'))
    if args.function:
        func_info = verifier.verify_function(args.function, source_code)
        print(f"  function: {func_info.name}")
        print(f"  compiled: {'PASS' if func_info.compiled_success else 'FAIL'}")
        print(f"  equivalence: {func_info.equivalence_score:.2f} ({func_info.equivalence_level.value})")
    else:
        func_info = verifier.verify_function('main', source_code)
        print(f"  compiled: {'PASS' if func_info.compiled_success else 'FAIL'}")
        print(f"  equivalence: {func_info.equivalence_score:.2f} ({func_info.equivalence_level.value})")
    return 0


def cmd_predict(args):
    print(f"[*] reliability prediction (arch={args.arch}, allocator={args.allocator})")
    from patching.reliability_predictor import create_reliability_predictor
    predictor = create_reliability_predictor(arch=args.arch)
    predictor.allocator = args.allocator
    capabilities = {}
    if args.capabilities:
        for cap in args.capabilities.split(','):
            cap = cap.strip()
            if cap:
                capabilities[cap] = True
    result = predictor.run(capabilities=capabilities if capabilities else None)
    if result.success:
        print(f"  survival rate:     {result.success_rate:.4f}")
        print(f"  95% CI:            +-{result.confidence_interval:.4f}")
        print(f"  exploitability:    {result.exploitability_score:.4f}")
        print(f"  patch difficulty:  {result.patch_difficulty}")
        print(f"  iterations:        {result.iterations}")
    else:
        print(f"[-] prediction failed")
        return 1
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog='patching', description='Binary patch analysis & auto-fix toolchain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='examples:\n  patching analyze --binary app.bin --output app_patched.bin\n  patching self-heal --binary app.bin --cve-id CVE-2017-5123\n  patching recompile --source decompiled.c\n  patching predict --arch x86_64')
    parser.add_argument('--config', '-c', help='path to config file (yaml)')
    parser.add_argument('--log-level', default=None, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('--log-file', default=None, help='log file path')
    subs = parser.add_subparsers(dest='command', help='sub-commands')

    p_analyze = subs.add_parser('analyze', help='analyze binary & apply patches')
    p_analyze.add_argument('--binary', '-b', required=True, help='target binary')
    p_analyze.add_argument('--output', '-o', help='output patched binary')
    p_analyze.add_argument('--json', action='store_true', help='JSON output')

    p_diff = subs.add_parser('diff', help='diff two binaries')
    p_diff.add_argument('--original', '-a', required=True, help='original binary')
    p_diff.add_argument('--patched', '-b', required=True, help='patched binary')
    p_diff.add_argument('--output', '-o', help='output directory')
    p_diff.add_argument('--no-ai', action='store_true', help='disable AI analysis')

    p_rc = subs.add_parser('root-cause', help='root cause analysis')
    p_rc.add_argument('--crash', '-f', required=True, help='crash file or text')
    p_rc.add_argument('--output', '-o', help='output report file')

    p_qual = subs.add_parser('quality', help='evaluate patch quality')
    p_qual.add_argument('--patch-data', '-p', required=True, help='patch data JSON')

    p_rules = subs.add_parser('rules', help='manage detection rules')
    p_rules.add_argument('--rules-dir', help='rules directory')
    p_rules.add_argument('--list', action='store_true', help='list all rules')
    p_rules.add_argument('--rule-id', help='rule ID to operate on')
    p_rules.add_argument('--enable', action='store_true', help='enable rule')
    p_rules.add_argument('--disable', action='store_true', help='disable rule')

    p_impact = subs.add_parser('impact', help='analyze patch impact')
    p_impact.add_argument('--before', required=True, help='binary before patch')
    p_impact.add_argument('--after', required=True, help='binary after patch')

    p_heal = subs.add_parser('self-heal', help='apply self-healing protection')
    p_heal.add_argument('--binary', '-b', required=True, help='target binary')
    p_heal.add_argument('--cve-id', '-c', help='CVE identifier')
    p_heal.add_argument('--framework', '-f', default='frida', choices=['frida', 'dynamorio', 'bpftime'])
    p_heal.add_argument('--output', '-o', help='output script file')

    p_rec = subs.add_parser('recompile', help='verify decompiled code')
    p_rec.add_argument('--source', '-s', required=True, help='source file (- for stdin)')
    p_rec.add_argument('--function', '-f', help='function name (optional)')
    p_rec.add_argument('--compiler', help='compiler path (default: gcc)')

    p_pred = subs.add_parser('predict', help='predict patch reliability')
    p_pred.add_argument('--arch', default='x86_64', help='target architecture')
    p_pred.add_argument('--allocator', default='glibc', help='allocator')
    p_pred.add_argument('--capabilities', help='comma-separated exploit capabilities')

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.config:
        load_config(args.config)
    setup_logging(args.log_level, args.log_file)
    if not args.command:
        parser.print_help()
        return 0
    handlers = {
        'analyze': cmd_analyze, 'diff': cmd_diff, 'root-cause': cmd_root_cause,
        'quality': cmd_quality, 'rules': cmd_rules, 'impact': cmd_impact,
        'self-heal': cmd_self_heal, 'recompile': cmd_recompile, 'predict': cmd_predict,
    }
    handler = handlers.get(args.command)
    if handler:
        try:
            return handler(args)
        except Exception as e:
            logger.exception("command '%s' failed", args.command)
            print(f"[-] error: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
