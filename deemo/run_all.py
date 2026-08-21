# BinMind 统一入口 - 一键运行: 编译→扫描→交叉验证→统计→报告。
# 用法: python run_all.py [--timeout N] [--samples DIR]

import os, sys, json, time, argparse

def main():
    ap = argparse.ArgumentParser(description='BinMind Unified Pipeline')
    ap.add_argument('--timeout', type=int, default=120)
    ap.add_argument('--samples', default=None)
    args = ap.parse_args()

    print('=' * 60)
    print('BinMind 统一检测流水线')
    print('=' * 60)

    # 阶段1: 编译
    print('\n[1/5] Compiling samples...')
    from tests.compile_samples import compile_all
    bins = compile_all(args.samples)
    ok = sum(1 for v in bins.values() if isinstance(v, dict) and v.get('success'))
    total = len([v for v in bins.values() if isinstance(v, dict)])
    print(f'  Compiled: {ok}/{total}')

    if ok == 0:
        print('  No binaries produced. Check gcc installation.')
        return

    # 阶段2: 扫描
    print('\n[2/5] Running scans...')
    from tests.run_scanner import run_all as scan_all
    results = scan_all(bins, args.timeout)
    print(f'  Scanned: {len(results)} samples')

    # 阶段3: 收集统计
    print('\n[3/5] Collecting results...')
    from tests.collect_results import collect, print_summary
    report = collect(results)
    print_summary(report)

    # 阶段4: 交叉验证
    print('\n[4/5] Cross-validating detectors...')
    from tests.cross_validate import cross_validate
    heap_findings = []
    uaf_findings = []
    fmt_findings = []
    for sr in results:
        if not sr.get('success'):
            continue
        try:
            data = json.loads(sr.get('stdout', '{}'))
            if data.get('stack', {}).get('overflowable'):
                heap_findings.append({'function': sr['sample'], **data['stack']})
            if isinstance(data.get('fmt'), list):
                fmt_findings.extend(data['fmt'])
            if isinstance(data.get('heap'), dict):
                for c in data['heap'].get('uaf_candidates', []):
                    uaf_findings.append({'function': sr['sample'], **c})
        except (json.JSONDecodeError, KeyError):
            pass
    xv = cross_validate(heap_findings, uaf_findings, fmt_findings)
    high_consensus = [r for r in xv if r.consensus_score > 0.5]
    print(f'  Cross-validated: {len(xv)} functions, {len(high_consensus)} high-consensus')

    # 阶段5: 保存报告
    print('\n[5/5] Saving report...')
    final = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'compile': {'ok': ok, 'total': total},
        'scan': {'total': len(results)},
        'detection': report,
        'cross_validation': {
            'total_functions': len(xv),
            'high_consensus': len(high_consensus),
            'top_functions': [
                {'name': r.func_name, 'score': r.consensus_score}
                for r in xv[:5]
            ],
        },
    }
    report_path = os.path.join(os.path.dirname(__file__), 'final_report.json')
    with open(report_path, 'w') as f:
        json.dump(final, f, indent=2, ensure_ascii=False)
    print(f'  Report: {report_path}')
    print('\nPipeline complete.')
    return final


if __name__ == '__main__':
    main()
