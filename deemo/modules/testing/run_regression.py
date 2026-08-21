"""一键回归测试主控脚本 — 编译 → 扫描 → 收集 → 报告.

使用: python run_regression.py [--samples-dir PATH] [--jobs N]

输出:
  - scan_results.json: 原始扫描结果
  - metrics_report.json: 指标汇总
  - metrics_report.csv: CSV 格式指标
  - 终端打印完整报告
"""

import argparse
import os
import sys
import time

# 复用同目录下的模块
from .compile_samples import compile_all, print_summary as print_compile
from run_scanner import scan_sample, BinaryScanner
from collect_results import (
    collect_from_json, print_report, export_csv,
    FullReport, SAMPLE_LABELS, MetricsByType)


def find_binaries(samples_dir: str) -> list:
    """查找所有已编译的二进制文件."""
    binaries = []
    for entry in sorted(os.listdir(samples_dir)):
        sample_path = os.path.join(samples_dir, entry)
        for name in ("vuln.exe", "vuln"):
            binary = os.path.join(sample_path, name)
            if os.path.isdir(sample_path) and os.path.isfile(binary):
                binaries.append((entry, binary))
                break
    return binaries


def run_full_regression(samples_dir: str, jobs: int = 4,
                        use_ppahav: bool = True):
    """执行完整回归测试管线."""
    print("=" * 70)
    print("  BinMind Heap Overflow Detection — Regression Test Suite")
    print("=" * 70)

    # 阶段1: 编译
    print("\n[Phase 1/3] Compiling samples ...")
    compile_results = compile_all(samples_dir, jobs)
    print_compile(compile_results)
    ok = sum(1 for r in compile_results if r.success)
    if ok == 0:
        print("[!] No samples compiled successfully. Aborting.")
        return None

    # 阶段2: 扫描
    print(f"\n[Phase 2/3] Scanning {ok} binaries ...")
    binaries = find_binaries(samples_dir)
    all_results = []
    for name, binary in binaries:
        print(f"  [*] {name} ...")
        results = scan_sample(binary, name, use_ppahav=use_ppahav)
        all_results.extend(results)

    # 保存原始结果
    import json
    output_data = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ppahav_enabled": use_ppahav,
        "total_samples": len(binaries),
        "results": [
            {
                "sample": r.sample_name,
                "detector": r.detector,
                "n_findings": r.n_total,
                "n_heap_overflow": r.n_heap_overflow,
                "n_uaf": r.n_uaf,
                "n_format_string": r.n_format_string,
                "n_integer_overflow": r.n_integer_overflow,
                "elapsed_ms": round(r.elapsed_ms, 1),
                "findings": r.findings,
                "error": r.error,
            }
            for r in all_results
        ],
    }

    scan_path = os.path.join(samples_dir, "..", "scan_results.json")
    with open(scan_path, "w") as f:
        json.dump(output_data, f, indent=2)

    # 阶段3: 收集与分析
    print(f"\n[Phase 3/3] Analyzing results ...")
    report = collect_from_json(scan_path, SAMPLE_LABELS)

    # 生成汇总报告 (多检测器聚合)
    # 使用 ppahav 检测器的结果作为主要指标 (若启用)
    print_report(report)

    # 导出 CSV
    csv_path = os.path.join(samples_dir, "..", "metrics_report.csv")
    export_csv(report, csv_path)
    print(f"\n[*] CSV report: {csv_path}")

    # 导出 JSON
    import json as _json
    report_path = os.path.join(samples_dir, "..", "metrics_report.json")
    report_data = {
        "detector": report.detector_name,
        "total_samples": report.total_samples,
        "total_elapsed_ms": report.total_elapsed_ms,
        "ppahav_enabled": use_ppahav,
        "metrics": [
            {"type": m.vuln_type, "tp": m.tp, "fp": m.fp, "fn": m.fn,
             "tn": m.tn, "precision": round(m.precision, 4),
             "recall": round(m.recall, 4), "f1": round(m.f1, 4),
             "fp_rate": round(m.fp_rate, 4)}
            for m in report.metrics
        ],
    }
    with open(report_path, "w") as f:
        _json.dump(report_data, f, indent=2)
    print(f"[*] JSON report: {report_path}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="BinMind Heap Overflow Regression Test Suite")
    parser.add_argument("--samples-dir", default=None,
                        help="Path to heap_samples directory")
    parser.add_argument("--jobs", type=int, default=4,
                        help="Parallel compile jobs")
    parser.add_argument("--no-ppahav", action="store_true",
                        help="Disable PPA-HAV enhancement")
    args = parser.parse_args()

    samples_dir = args.samples_dir or os.path.join(
        os.path.dirname(__file__), "heap_samples")

    t0 = time.perf_counter()
    report = run_full_regression(
        samples_dir, args.jobs, not args.no_ppahav)
    total = time.perf_counter() - t0

    if report:
        print(f"\n[OK] Regression test completed in {total:.1f}s")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
