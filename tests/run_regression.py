#!/usr/bin/env python3
"""
自动化回归测试入口 — 编译→扫描→评估完整管线.

用法: python tests/run_regression.py [--compiler gcc|clang] [--detector all|stack|format|heap]

输出: tests/results/ 目录下 JSON 格式的详细结果和汇总报告.
"""

import json
import os
import sys
import time
from pathlib import Path

def main():
    import argparse
    parser = argparse.ArgumentParser(description='BinMind vulnerability detection regression test')
    parser.add_argument('--compiler', default='gcc', choices=['gcc', 'clang'],
                        help='C compiler to use')
    parser.add_argument('--detector', default='all',
                        choices=['all', 'stack', 'format', 'heap'],
                        help='detector type to run')
    parser.add_argument('--output-dir', default=None,
                        help='output directory for results')
    args = parser.parse_args()

    base_dir = Path(__file__).parent
    sample_dir = base_dir / 'vuln_samples'
    output_dir = Path(args.output_dir) if args.output_dir else (base_dir / 'results')
    output_dir.mkdir(parents=True, exist_ok=True)

    print('=' * 60)
    print('BinMind Regression Test Suite')
    print(f'  Compiler: {args.compiler}')
    print(f'  Detector: {args.detector}')
    print(f'  Samples:  {sample_dir}')
    print(f'  Output:   {output_dir}')
    print('=' * 60)

    # 阶段1: 编译
    print('\n[Phase 1/3] Compiling samples...')
    sys.path.insert(0, str(base_dir.parent))
    from tests.test_harness.compile_samples import build_all
    compile_results = build_all(str(sample_dir), args.compiler)
    ok = sum(1 for r in compile_results if r['success'])
    print(f'  Compiled {ok}/{len(compile_results)} samples')

    # 阶段2: 扫描
    print(f'\n[Phase 2/3] Scanning with detector={args.detector}...')
    from tests.test_harness.scan_scheduler import scan_directory
    scan_results = scan_directory(str(sample_dir), args.detector)
    with open(output_dir / 'scan_results.json', 'w') as f:
        json.dump(scan_results, f, indent=2, default=str)
    print(f'  Scanned {len(scan_results)} binaries')

    # 阶段3: 评估
    print('\n[Phase 3/3] Evaluating results...')
    from tests.test_harness.result_parser import evaluate, print_report
    eval_result = evaluate(scan_results)
    with open(output_dir / 'evaluation_report.json', 'w') as f:
        json.dump(eval_result, f, indent=2, default=str)
    print_report(eval_result)

    # 汇总文件
    summary = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'compiler': args.compiler,
        'detector': args.detector,
        'compile': {'total': len(compile_results), 'success': ok},
        'evaluation': eval_result['summary'],
    }
    with open(output_dir / 'summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(f'\nResults saved to {output_dir}')

if __name__ == '__main__':
    main()
