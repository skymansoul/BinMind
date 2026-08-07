"""
增强版多工具对比基准测试 — 堆溢出专项.

对 test_samples 中的所有样本分别运行:
  1. BinMind (heap_overflow_pipeline + unified_fp_filter)
  2. Angr (CFGFast + 危险函数标记)
  3. Ghidra headless (自动化堆分析脚本)
  4. QEMU user mode + 模拟 ground truth

输出统一 CSV: tool, sample_id, detected, false_positive, false_negative, time_ms, mem_mb
"""

import argparse
import csv
import json
import sys
from pathlib import Path

from eval.benchmark_enhanced_tools import (
    get_compiled_binaries, run_binmind, run_angr,
    run_ghidra, run_qemu, compute_metrics,
)

EVAL_DIR = Path(__file__).parent



def main():
    parser = argparse.ArgumentParser(
        description="Run multi-tool heap overflow benchmark")
    parser.add_argument("--output", "-o", default="benchmark_results.csv",
                        help="Output CSV file")
    parser.add_argument("--json", default="benchmark_metrics.json",
                        help="Output JSON metrics file")
    parser.add_argument("--skip-angr", action="store_true",
                        help="Skip Angr (slow)")
    parser.add_argument("--skip-ghidra", action="store_true",
                        help="Skip Ghidra headless")
    args = parser.parse_args()

    binaries = get_compiled_binaries()
    if not binaries:
        print("No compiled binaries found. Run compile_all.py first.")
        return 1

    print(f"Running benchmark on {len(binaries)} binaries...")
    all_results = []

    # 期望: 从 README 推断 (is_vulnerable = not FP)
    expected = {}
    for r in binaries:
        name = r["sample"]
        # FP samples: cve_09, cve_10, cve_13, cve_17
        is_vuln = not any(
            fp_id in name for fp_id in
            ["cve_09", "cve_10", "cve_13", "cve_17"]
        )
        expected[name] = is_vuln

    for b in binaries:
        path = b["binary"]
        name = b["sample"]
        print(f"\n  Processing {name}...")

        # BinMind
        print(f"    BinMind...", end=" ")
        r = run_binmind(path, name)
        all_results.append(r)
        print(f"{r['alerts']} alerts ({r['scan_time_ms']:.0f}ms)")

        # Angr
        if not args.skip_angr:
            print(f"    Angr...", end=" ")
            r = run_angr(path, name)
            all_results.append(r)
            print(f"{r['alerts']} alerts ({r['scan_time_ms']:.0f}ms)")

        # Ghidra
        if not args.skip_ghidra:
            print(f"    Ghidra...", end=" ")
            r = run_ghidra(path, name)
            all_results.append(r)
            print(f"{r['alerts']} alerts ({r['scan_time_ms']:.0f}ms)")

        # QEMU/GT
        print(f"    QEMU/GT...", end=" ")
        r = run_qemu(path, name)
        all_results.append(r)
        print(f"{'OK' if not r.get('error') else r['error'][:40]}")

    # 计算指标
    metrics = compute_metrics(all_results, expected)

    # 写入 CSV
    csv_path = EVAL_DIR / args.output
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "tool", "samples", "true_positive", "false_positive",
            "true_negative", "false_negative",
            "recall", "fp_rate", "precision", "avg_time_ms",
        ])
        writer.writeheader()
        writer.writerows(metrics)
    print(f"\nCSV written to {csv_path}")

    # 写入 JSON
    json_path = EVAL_DIR / args.json
    with open(json_path, "w") as f:
        json.dump({"metrics": metrics, "raw_results": all_results}, f, indent=2)
    print(f"JSON written to {json_path}")

    # 打印摘要
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY — Heap Overflow Detection")
    print("=" * 70)
    for m in metrics:
        print(f"  {m['tool']:12s} | Recall={m['recall']:.1%} "
              f"FP_Rate={m['fp_rate']:.1%} "
              f"Precision={m['precision']:.1%} "
              f"Time={m['avg_time_ms']:.0f}ms")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
