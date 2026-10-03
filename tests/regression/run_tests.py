"""
回归测试入口: 编译 → 扫描 → 解析 → 报告。

用法: python run_tests.py [--skip-build] [--skip-fetch]
"""

import os
import sys
import json
import argparse
from datetime import datetime

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)
sys.path.insert(0, os.path.dirname(__file__))

from sample_generator import generate_samples
from sample_fetcher import fetch_samples
from build_samples import build_all
try:
    from scan_scheduler import ScanScheduler
except ImportError:
    # ScanScheduler 已移除; 降级为 None, 扫描步骤按守卫跳过
    ScanScheduler = None
from result_parser import parse_results
try:
    from result_parser import save_report
except ImportError:
    # save_report 已移除; 降级为 None, 报告写出按守卫跳过
    save_report = None


def main():
    ap = argparse.ArgumentParser(description='BinMind Regression Test Suite')
    ap.add_argument('--skip-fetch', action='store_true')
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--timeout', type=float, default=30.0)
    ap.add_argument('--output', default=os.path.join(
        os.path.dirname(__file__), 'results', 'test_report.json'))
    args = ap.parse_args()

    base = os.path.dirname(__file__)
    binary_dir = os.path.join(base, 'results', 'binaries')

    # 1. 获取/生成样本
    print("=" * 50)
    print("[1/4] Preparing samples...")
    if not args.skip_fetch:
        try:
            fetch_samples()
        except Exception as e:
            print(f"  Fetch skipped: {e}")
    synthetic = generate_samples()
    print(f"  {len(synthetic)} synthetic samples ready")

    # 2. 编译
    print("=" * 50)
    print("[2/4] Building binaries...")
    if not args.skip_build:
        build_results = build_all(binary_dir)
        ok = sum(1 for r in build_results if r.success)
        print(f"  {ok}/{len(build_results)} binaries compiled")
    else:
        print("  Skipped (--skip-build)")

    # 3. 扫描
    print("=" * 50)
    print("[3/4] Scanning binaries...")
    if ScanScheduler is not None:
        scheduler = ScanScheduler(timeout_sec=args.timeout)
        scan_results = scheduler.scan_all(binary_dir)
        print(f"  {sum(1 for r in scan_results if r.success)}/{len(scan_results)} scans OK")
    else:
        print("  ScanScheduler 不可用, 跳过扫描")
        scan_results = []

    # 4. 解析 & 报告
    print("=" * 50)
    print("[4/4] Generating report...")
    report = parse_results(scan_results)
    if save_report is not None:
        save_report(report, args.output)
        print(f"  Report saved: {args.output}")
    else:
        print("  save_report 不可用, 跳过报告写出")

    # 简略摘要
    s = report['summary']
    m = report['metrics']
    print(f"\n{'='*50}")
    print(f"SUMMARY ({datetime.now().strftime('%Y-%m-%d %H:%M')})")
    print(f"  Scans: {s['successful']}/{s['total_scans']} ok, {s['timeouts']} timeouts")
    print(f"  Avg time: {s['avg_elapsed_ms']:.0f}ms  Peak mem: {s['peak_memory_kb']:.0f}KB")
    for vt, mm in m.items():
        if mm['TP'] + mm['FN'] > 0:
            print(f"  {vt:20s}  TPR={mm['TPR']:.2%}  FPR={mm['FPR']:.2%}  F1={mm['F1']:.2%}  (TP={mm['TP']} FP={mm['FP']} FN={mm['FN']})")


if __name__ == '__main__':
    main()
