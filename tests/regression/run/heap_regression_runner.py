"""
堆溢出回归测试主调度器 — 编译 → 扫描 → 收集 → 报告, 一键运行.

用法:
  python tests/regression/run/heap_regression_runner.py
  python tests/regression/run/heap_regression_runner.py --sample-dir samples/cve
  python tests/regression/run/heap_regression_runner.py --output results.json
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


# 添加项目根目录到 path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def find_sample_dirs(sample_root: str) -> List[str]:
    """查找所有包含 vuln.c 或 *.c 的样本目录."""
    dirs = []
    root = Path(sample_root)
    if not root.exists():
        return dirs
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        if list(d.glob("vuln.c")) or list(d.glob("*.c")):
            dirs.append(str(d))
    return dirs


def run_pipeline(sample_dirs: List[str]) -> Dict[str, Any]:
    """运行完整检测管道: 扫描 → 过滤 → 分类."""
    from tests.regression.run.scan_scheduler import scan_sample
    from tests.regression.run.result_parser import collect_results, print_summary

    scan_results = []
    for d in sample_dirs:
        for c_file in Path(d).glob("vuln.c"):
            r = scan_sample(str(c_file))
            scan_results.append(r)
            break  # 每个目录只取 vuln.c
        else:
            for c_file in Path(d).glob("*.c"):
                r = scan_sample(str(c_file))
                scan_results.append(r)
                break

    report = collect_results(scan_results)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Heap Overflow Regression Test Runner")
    parser.add_argument(
        "--sample-dir", default="",
        help="Root directory of samples (default: samples/cve and samples/heap_overflow)")
    parser.add_argument(
        "--output", default="", help="Output JSON path")
    parser.add_argument(
        "--csv", default="", help="Output CSV path")
    args = parser.parse_args()

    # 确定样本目录
    base = _PROJECT_ROOT
    sample_roots = []
    if args.sample_dir:
        sample_roots.append(args.sample_dir)
    else:
        for d in ["samples/cve", "samples/heap_overflow"]:
            p = base / d
            if p.exists():
                sample_roots.append(str(p))

    all_dirs = []
    for root in sample_roots:
        dirs = find_sample_dirs(root)
        all_dirs.extend(dirs)
        print(f"  Found {len(dirs)} samples in {root}")

    if not all_dirs:
        print("No samples found. Run from project root.")
        return 1

    print(f"\nRunning regression on {len(all_dirs)} samples...\n")

    t0 = time.time()
    report = run_pipeline(all_dirs)
    report["total_time_sec"] = round(time.time() - t0, 2)

    from tests.regression.run.result_parser import print_summary, write_json, write_csv
    print_summary(report)

    output_base = args.output or str(base / "tests" / "regression" / "results" / "heap_regression")
    json_path = output_base + ".json"
    csv_path = args.csv or output_base + ".csv"

    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    write_json(report, json_path)
    write_csv(report, csv_path)

    print(f"Report saved: {json_path}")
    print(f"CSV saved: {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
