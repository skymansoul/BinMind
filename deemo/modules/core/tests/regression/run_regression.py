#!/usr/bin/env python3
# coding: utf-8
"""
一键回归测试主入口 — 编译→扫描→收集→报告, 全自动执行.

用法:
  python run_regression.py                          # 基础模式
  python run_regression.py --mode deep              # 深度模式 (六层过滤)
  python run_regression.py --output-dir ./results   # 指定输出目录
"""

import os, sys, json, time, argparse
from pathlib import Path

# 添加模块路径
_MODULE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(_MODULE_ROOT))


def main():
    ap = argparse.ArgumentParser(description='Heap Overflow Regression Test Suite')
    ap.add_argument('--mode', default='minimal', choices=['minimal', 'deep'],
                    help='检测模式 (默认 minimal)')
    ap.add_argument('--samples-root', help='样本目录路径')
    ap.add_argument('--output-dir', help='结果输出目录')
    ap.add_argument('--ground-truth', help='ground truth JSON 路径')
    ap.add_argument('--skip-compile', action='store_true', help='跳过编译步骤')
    ap.add_argument('--format', default='markdown',
                    choices=['markdown', 'csv', 'json'])
    args = ap.parse_args()

    # 路径设置
    base_dir = Path(__file__).resolve().parent.parent
    samples_root = args.samples_root or str(base_dir / 'samples')
    output_dir = args.output_dir or str(base_dir / 'regression' / 'output')
    gt_path = args.ground_truth or str(Path(samples_root) / 'ground_truth.json')

    os.makedirs(output_dir, exist_ok=True)

    print('=' * 60)
    print('Heap Overflow Regression Test Suite')
    print(f'  Mode: {args.mode}')
    print(f'  Samples: {samples_root}')
    print(f'  Output: {output_dir}')
    print('=' * 60)

    # 编译
    compile_json = os.path.join(output_dir, 'compile_results.json')
    if not args.skip_compile:
        print('\nCompiling samples...')
        from tests.regression.compile_samples import compile_all
        _, summary = compile_all(samples_root, output_json=compile_json)
        print(f'  Compiled: {summary["success"]}/{summary["total"]} success')
        if summary['failed']:
            for e in summary['errors']:
                print(f'    FAIL: {e["dir"]} — {e["error"]}')
        elf_paths = summary['elf_paths']
    else:
        with open(compile_json) as f:
            summary = json.load(f)
        elf_paths = summary['elf_paths']

    if not elf_paths:
        print('ERROR: No ELF files compiled. Aborting.')
        sys.exit(1)

    # 扫描
        print(f'\nScanning {len(elf_paths)} ELF files...')
    scan_json = os.path.join(output_dir, 'scan_results.json')

    from tests.regression.run_scanner import scan_all
    scan_results = scan_all(elf_paths, mode=args.mode)

    # 保存原始结果
    scan_output = {
        'mode': args.mode,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total': len(scan_results),
        'results': [
            {
                'sample_id': r.sample_id,
                'success': r.success,
                'candidates': len(r.candidates),
                'exploitable': sum(1 for c in r.candidates if c.get('exploitable')),
                'wall_time_ms': r.wall_time_ms,
                'error': r.error,
                'layer_stats': r.layer_stats,
            }
            for r in scan_results
        ],
    }
    with open(scan_json, 'w') as f:
        json.dump(scan_output, f, indent=2, default=str)

    # 结果收集
        print('\nCollecting results vs ground truth...')
    from tests.regression.collect_results import collect, report_to_markdown, report_to_csv

    report = collect(scan_output['results'], gt_path)

    if args.format == 'markdown':
        out = report_to_markdown(report)
        ext = '.md'
    elif args.format == 'csv':
        out = report_to_csv(report)
        ext = '.csv'
    else:
        import json as _j
        out = _j.dumps({
            'summary': {
                'tp': report.tp, 'fp': report.fp, 'tn': report.tn, 'fn': report.fn,
                'precision': report.precision, 'recall': report.recall,
                'f1': report.f1, 'fp_rate': report.fp_rate,
            },
        }, indent=2)
        ext = '.json'

    report_path = os.path.join(output_dir, f'regression_report{ext}')
    with open(report_path, 'w') as f:
        f.write(out)

    # 终端输出汇总
    print('\n' + '=' * 60)
    print('RESULTS')
    print('=' * 60)
    print(f'  TP={report.tp}  FP={report.fp}  TN={report.tn}  FN={report.fn}')
    print(f'  Precision: {report.precision:.2%}')
    print(f'  Recall:    {report.recall:.2%}')
    print(f'  F1 Score:  {report.f1:.3f}')
    print(f'  FP Rate:   {report.fp_rate:.2%}')
    print(f'  Avg Time:  {report.avg_time_ms:.1f}ms')
    print(f'\nFull report: {report_path}')

    # Exit code
    sys.exit(0 if report.fn == 0 and report.fp_rate < 0.3 else 1)


if __name__ == '__main__':
    main()
