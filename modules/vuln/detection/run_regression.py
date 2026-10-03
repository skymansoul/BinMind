#!/usr/bin/env python3
"""一键回归测试入口 - 编译样本 - 运行扫描 - 收集结果 - 生成报告.

用途: 一行命令完成完整回归测试管线, 确保改动算法后可以一键验证效果。
      集成了 DP-TVRA 三阶段过滤作为核心检测后端。

管线:
  1. compile   - 用 gcc 编译所有 C 样本为 ELF
  2. scan      - 对每个 ELF 运行 DP-TVRA 检测
  3. collect   - 聚合结果, 计算 precision/recall/F1
  4. report    - 生成 Markdown 报告 + JSON 摘要
  5. benchmark - 多工具对比 (BinMind/Angr/QEMU/Ghidra)
  6. plot      - 生成对比图表

使用方式:
  python run_regression.py              # 全部阶段
  python run_regression.py --compile    # 仅编译
  python run_regression.py --scan       # 仅扫描
  python run_regression.py --quick      # 快速模式 (跳过外部工具对比)
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# 路径设置
BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "tests" / "samples"
REGRESSION_DIR = BASE_DIR / "tests" / "regression"
BUILD_DIR = BASE_DIR / "tests" / "build"
RESULTS_DIR = BASE_DIR / "tests" / "results"
EVAL_DIR = BASE_DIR / "eval"

# 将 src 加入路径
SRC_DIR = BASE_DIR / "src" / "heap"
sys.path.insert(0, str(SRC_DIR))


@dataclass
class PipelineResult:
    """完整回归测试管线的结果."""
    timestamp: str = ""
    # 编译
    n_samples_compiled: int = 0
    n_samples_failed_compile: int = 0
    # 扫描
    n_scanned: int = 0
    n_detected: int = 0
    n_clean: int = 0
    # 指标
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    fp_rate: float = 0.0
    fp_reduction_pct: float = 0.0
    # 性能
    total_time_s: float = 0.0
    avg_time_per_sample_s: float = 0.0
    # 详情
    per_sample: List[dict] = field(default_factory=list)
    # 多工具对比
    comparison_csv: str = ""


def compile_samples() -> Tuple[int, int]:
    """编译所有测试样本."""
    print("=" * 60)
    print("PHASE 1: Compiling test samples")
    print("=" * 60)

    if not SAMPLES_DIR.is_dir():
        print(f"[!] Samples dir not found: {SAMPLES_DIR}")
        return 0, 0

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    compiled = 0
    failed = 0

    for sample_dir in sorted(SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue

        sample_id = sample_dir.name
        makefile = sample_dir / "Makefile"
        c_files = list(sample_dir.glob("*.c"))

        if not c_files:
            continue

        out_dir = BUILD_DIR / sample_id
        out_dir.mkdir(parents=True, exist_ok=True)
        out_bin = out_dir / sample_id

        print(f"  [{sample_id}] ", end="")

        # 如果已有 Makefile, 优先使用
        if makefile.exists():
            try:
                proc = subprocess.run(
                    ["make", "-C", str(sample_dir),
                     f"OUTPUT={out_bin}", "clean", "all"],
                    capture_output=True, text=True, timeout=60,
                    env={**os.environ, "CC": "gcc"})
                if proc.returncode == 0 and out_bin.is_file():
                    print("OK (Makefile)")
                    compiled += 1
                    continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # 回退: 直接用 gcc 编译所有 .c 文件
        try:
            cmd = ["gcc", "-O0", "-g", "-fno-stack-protector",
                   "-no-pie", "-o", str(out_bin)] + [str(c) for c in c_files]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                # 验证是否为 ELF
                with open(out_bin, "rb") as f:
                    magic = f.read(4)
                if magic[:4] == b'\x7fELF':
                    print("OK")
                    compiled += 1
                    continue
                else:
                    # Windows PE 格式
                    print("OK (PE)")
                    compiled += 1
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        print(f"FAIL: {proc.stderr[:80] if 'proc' in dir() else 'unknown'}")
        failed += 1

    print(f"\n  Compiled: {compiled}, Failed: {failed}\n")
    return compiled, failed


def scan_samples() -> List[dict]:
    """对所有编译好的样本运行 DP-TVRA 检测."""
    print("=" * 60)
    print("PHASE 2: Scanning compiled samples")
    print("=" * 60)

    results = []
    t0_total = time.time()

    # 导入核心检测
    from orchestrator import analyze_heap

    for sample_dir in sorted(BUILD_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue

        sample_id = sample_dir.name

        # 找 ELF/PE: 无后缀 (ELF) 或 .exe (PE/Windows gcc)
        binaries = [f for f in sample_dir.iterdir()
                    if f.is_file() and (not f.suffix or f.suffix == '.exe')]

        if not binaries:
            continue

        binary = binaries[0]
        t0 = time.time()

        try:
            report = analyze_heap(str(binary), timeout_s=60)
            elapsed = round(time.time() - t0, 3)

            # 判定: 存在 confirmed 或 likely 即视为检测到
            detected = report.confirmed > 0 or report.likely > 0

            sample_result = {
                "sample_id": sample_id,
                "detected": detected,
                "raw_findings": report.raw_findings,
                "confirmed": report.confirmed,
                "likely": report.likely,
                "uncertain": report.uncertain,
                "filtered_fp": report.filtered_fp,
                "fp_reduction_pct": report.fp_reduction_pct,
                "elapsed_sec": elapsed,
                "n_functions": report.n_functions,
                "findings": report.findings[:5],  # 只保留前 5 条
            }

            status = "DETECT" if detected else "CLEAN"
            print(f"  [{sample_id:30s}] {status:6s} "
                  f"({report.confirmed}+{report.likely} confirmed/likely, "
                  f"{report.filtered_fp} FP filtered, {elapsed:.2f}s)")

            results.append(sample_result)

        except Exception as e:
            print(f"  [{sample_id:30s}] ERROR: {e}")
            results.append({
                "sample_id": sample_id,
                "detected": False,
                "error": str(e),
                "elapsed_sec": round(time.time() - t0, 3),
            })

    total = round(time.time() - t0_total, 3)
    print(f"\n  Scanned: {len(results)} samples in {total}s\n")
    return results


def collect_results(scan_results: List[dict]) -> PipelineResult:
    """计算精度/召回/F1."""
    print("=" * 60)
    print("PHASE 3: Computing metrics")
    print("=" * 60)

    result = PipelineResult()
    result.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    if not scan_results:
        return result

    result.n_scanned = len(scan_results)
    result.n_detected = sum(1 for r in scan_results if r.get("detected"))
    result.n_clean = result.n_scanned - result.n_detected

    # ground truth: 所有测试样本都应该存在漏洞 (heuristic)
    # 实际 CVE 样本中可能有些是 Linux-only primitive 在 Windows 上不触发
    n_total = len(scan_results)
    n_detected = result.n_detected

    # 召回 = 检测到的 / 总数
    result.recall = round(n_detected / max(1, n_total) * 100, 1)

    # 精确度 = confirmed / (confirmed + uncertain)
    total_confirmed = sum(r.get("confirmed", 0) for r in scan_results)
    total_uncertain = sum(r.get("uncertain", 0) for r in scan_results)
    result.precision = round(
        total_confirmed / max(1, total_confirmed + total_uncertain) * 100, 1)

    # F1
    if result.precision + result.recall > 0:
        result.f1_score = round(
            2 * result.precision * result.recall
            / (result.precision + result.recall), 1)

    # FP rate
    total_raw = sum(r.get("raw_findings", 0) for r in scan_results)
    total_filtered = sum(r.get("filtered_fp", 0) for r in scan_results)
    result.fp_rate = round(
        (total_raw - total_filtered - total_confirmed)
        / max(1, total_raw) * 100, 1)
    result.fp_reduction_pct = round(
        total_filtered / max(1, total_raw) * 100, 1)

    # 计时
    result.total_time_s = sum(r.get("elapsed_sec", 0) for r in scan_results)
    result.avg_time_per_sample_s = round(result.total_time_s / max(1, n_total), 3)

    result.per_sample = scan_results

    print(f"  Samples scanned : {result.n_scanned}")
    print(f"  Detected        : {result.n_detected}")
    print(f"  Recall          : {result.recall}%")
    print(f"  Precision       : {result.precision}%")
    print(f"  F1 Score        : {result.f1_score}%")
    print(f"  FP Rate         : {result.fp_rate}%")
    print(f"  FP Reduction    : {result.fp_reduction_pct}%")
    print(f"  Total time      : {result.total_time_s:.2f}s")
    print(f"  Avg per sample  : {result.avg_time_per_sample_s:.3f}s")
    print()

    return result


def generate_report(result: PipelineResult) -> str:
    """生成 Markdown 回归测试报告."""
    print("=" * 60)
    print("PHASE 4: Generating report")
    print("=" * 60)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = RESULTS_DIR / "regression_report.md"

    lines = [
        "# Regression Test Report",
        "",
        f"**Generated**: {result.timestamp}",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Samples scanned | {result.n_scanned} |",
        f"| Detected | {result.n_detected} |",
        f"| Clean | {result.n_clean} |",
        f"| **Recall** | **{result.recall}%** |",
        f"| **Precision** | **{result.precision}%** |",
        f"| **F1 Score** | **{result.f1_score}%** |",
        f"| FP Rate | {result.fp_rate}% |",
        f"| FP Reduction | {result.fp_reduction_pct}% |",
        f"| Total time | {result.total_time_s:.2f}s |",
        f"| Avg time/sample | {result.avg_time_per_sample_s:.3f}s |",
        "",
        "## Per-Sample Results",
        "",
        "| Sample | Detected | Raw | Confirmed | Likely | Uncertain | FP Filtered | Time (s) |",
        "|--------|----------|-----|-----------|--------|-----------|-------------|----------|",
    ]

    for r in result.per_sample:
        lines.append(
            f"| {r.get('sample_id', '?')} "
            f"| {'✅' if r.get('detected') else '❌'} "
            f"| {r.get('raw_findings', 0)} "
            f"| {r.get('confirmed', 0)} "
            f"| {r.get('likely', 0)} "
            f"| {r.get('uncertain', 0)} "
            f"| {r.get('filtered_fp', 0)} "
            f"| {r.get('elapsed_sec', 0):.2f} |")

    lines += [
        "",
        "## Methodology",
        "",
        "Detection engine: **DP-TVRA** (Demand-Driven Path-Sensitive Taint-Value-Range Analysis)",
        "",
        "Pipeline: Phase 1 (Taint back-propagation) → Phase 2 (Path constraint narrowing) → Phase 3 (Allocator model verification)",
        "",
        "---",
        "",
        f"*Report generated by `run_regression.py`*",
    ]

    report_text = "\n".join(lines)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"  Report: {report_path}")

    # JSON 摘要
    json_path = RESULTS_DIR / "regression_summary.json"
    summary = asdict(result)
    summary.pop("per_sample", None)  # 太多太重
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"  JSON:   {json_path}")

    return str(report_path)


def run_benchmark() -> str:
    """运行多工具对比基准测试."""
    print("=" * 60)
    print("PHASE 5: Multi-tool benchmark")
    print("=" * 60)

    bench_script = EVAL_DIR / "run_benchmark.py"
    if not bench_script.exists():
        print(f"  [!] Benchmark script not found: {bench_script}")
        return ""

    # 修改 samples 路径指向 build 目录
    try:
        proc = subprocess.run(
            [sys.executable, str(bench_script), str(RESULTS_DIR)],
            capture_output=True, text=True, timeout=300)
        print(proc.stdout[-500:] if len(proc.stdout) > 500 else proc.stdout)
        if proc.stderr:
            print(f"  [stderr]: {proc.stderr[-200:]}")

        csv_path = str(RESULTS_DIR / "benchmark_results.csv")
        if os.path.isfile(csv_path):
            print(f"\n  [+] Benchmark CSV: {csv_path}")
            return csv_path
    except subprocess.TimeoutExpired:
        print("  [!] Benchmark timed out")
    except Exception as e:
        print(f"  [!] Benchmark error: {e}")

    return ""


def run_plots(csv_path: str) -> None:
    """生成对比图表."""
    print("=" * 60)
    print("PHASE 6: Generating comparison charts")
    print("=" * 60)

    plot_script = EVAL_DIR / "plot_comparison.py"
    if not plot_script.exists():
        print(f"  [!] Plot script not found: {plot_script}")
        return

    try:
        proc = subprocess.run(
            [sys.executable, str(plot_script),
             csv_path if csv_path else str(RESULTS_DIR)],
            capture_output=True, text=True, timeout=60)
        print(proc.stdout[-300:] if len(proc.stdout) > 300 else proc.stdout)
        if proc.stderr and "warning" not in proc.stderr.lower():
            print(f"  [stderr]: {proc.stderr[-200:]}")
    except Exception as e:
        print(f"  [!] Plot error: {e}")


def main():
    global RESULTS_DIR

    parser = argparse.ArgumentParser(
        description="BinMind 一键回归测试")
    parser.add_argument("--compile-only", action="store_true",
                        help="只编译样本")
    parser.add_argument("--scan-only", action="store_true",
                        help="只运行扫描")
    parser.add_argument("--quick", action="store_true",
                        help="快速模式: 跳过外部工具对比和绘图")
    parser.add_argument("--output", type=str, default=str(RESULTS_DIR),
                        help="结果输出目录")
    args = parser.parse_args()

    RESULTS_DIR = Path(args.output)

    t_start = time.time()

    # Phase 1: 编译
    if not args.scan_only:
        compiled, failed = compile_samples()
    else:
        compiled, failed = 0, 0
        print("[scan-only] Skipping compilation")

    # Phase 2: 扫描
    if not args.compile_only:
        scan_results = scan_samples()
    else:
        scan_results = []
        print("[compile-only] Skipping scan")

    if not scan_results:
        print("\n[!] No scan results. Build samples first with: "
              "python run_regression.py --compile-only")
        return

    # Phase 3: 指标计算
    result = collect_results(scan_results)

    # Phase 4: 报告生成
    report_path = generate_report(result)

    # Phase 5-6: 外部对比
    if not args.quick:
        csv_path = run_benchmark()
        if csv_path:
            run_plots(csv_path)

    total_s = round(time.time() - t_start, 1)
    print(f"\n{'=' * 60}")
    print(f"Pipeline complete in {total_s}s")
    print(f"  Report: {report_path}")
    print(f"  Recall: {result.recall}% | Precision: {result.precision}% "
          f"| F1: {result.f1_score}% | FP Rate: {result.fp_rate}%")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
