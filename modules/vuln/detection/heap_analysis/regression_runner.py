"""一键回归测试 — 编译→扫描→指标计算→报告生成.

设计决策:
  每个阶段独立可调用, 也支持一键全管线。
  输出同时包含Markdown报告和JSON摘要,
  确保'改动算法后可以一键验证效果'。
"""
import os, sys, json, time, subprocess, argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.vuln.detection.heap_analysis import analyze_heap

# 路径 — 相对于项目根
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
SAMPLES_DIR = BASE_DIR / "samples" / "heap_overflow"
RESULTS_DIR = BASE_DIR / "modules" / "vuln" / "detection" / "tests" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class RegressionResult:
    """回归测试汇总结果."""
    timestamp: str = ""
    n_total: int = 0
    n_detected: int = 0
    n_clean: int = 0
    total_raw: int = 0
    total_confirmed: int = 0
    total_likely: int = 0
    total_filtered: int = 0
    recall_pct: float = 0.0
    precision_pct: float = 0.0
    f1_pct: float = 0.0
    fp_reduction_pct: float = 0.0
    total_time_s: float = 0.0
    avg_time_ms: float = 0.0
    per_sample: List[dict] = field(default_factory=list)


def scan_all() -> RegressionResult:
    """扫描所有堆溢出样本, 返回汇总结果."""
    rr = RegressionResult()
    rr.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    if not SAMPLES_DIR.is_dir():
        print(f"[!] Samples dir not found: {SAMPLES_DIR}")
        return rr

    t0 = time.time()

    for sample_dir in sorted(SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        exe_files = list(sample_dir.glob("*.exe"))
        if not exe_files:
            continue

        binary = exe_files[0]
        t_sample = time.time()
        try:
            r = analyze_heap(str(binary))
            elapsed = round(time.time() - t_sample, 3)

            detected = r.confirmed > 0 or r.likely > 0
            n_uncertain = sum(
                1 for f in r.findings if f.get("confidence") == "uncertain")
            entry = {
                "sample_id": sample_dir.name,
                "detected": detected,
                "raw_findings": r.raw_findings,
                "confirmed": r.confirmed,
                "likely": r.likely,
                "uncertain": n_uncertain,
                "filtered_fp": r.filtered_fp,
                "fp_reduction_pct": r.fp_reduction_pct,
                "elapsed_sec": elapsed,
                "findings": r.findings[:5],
            }

            status = "DETECT" if detected else "CLEAN"
            print(f"  [{status:6s}] {sample_dir.name:40s} "
                  f"C={r.confirmed} L={r.likely} F={r.filtered_fp} "
                  f"({elapsed:.2f}s)")

            rr.per_sample.append(entry)

        except Exception as e:
            print(f"  [ERROR ] {sample_dir.name:40s} {e}")
            rr.per_sample.append({
                "sample_id": sample_dir.name,
                "detected": False,
                "error": str(e),
                "elapsed_sec": round(time.time() - t_sample, 3),
            })

    rr.total_time_s = round(time.time() - t0, 2)
    rr.n_total = len(rr.per_sample)
    rr.n_detected = sum(1 for s in rr.per_sample if s.get("detected"))
    rr.n_clean = rr.n_total - rr.n_detected

    rr.total_raw = sum(s.get("raw_findings", 0) for s in rr.per_sample)
    rr.total_confirmed = sum(s.get("confirmed", 0) for s in rr.per_sample)
    rr.total_likely = sum(s.get("likely", 0) for s in rr.per_sample)
    rr.total_filtered = sum(s.get("filtered_fp", 0) for s in rr.per_sample)

    # 召回 = detected / total (all samples are expected to be vulnerable)
    rr.recall_pct = round(rr.n_detected / max(1, rr.n_total) * 100, 1)

    # 精度 = confirmed / (confirmed + uncertain)
    total_uncertain = sum(s.get("uncertain", 0) for s in rr.per_sample)
    rr.precision_pct = round(
        rr.total_confirmed / max(1, rr.total_confirmed + total_uncertain) * 100, 1)

    # F1
    p, r = rr.precision_pct / 100, rr.recall_pct / 100
    rr.f1_pct = round(2 * p * r / max(0.001, p + r) * 100, 1)

    # FP reduction
    total = max(1, rr.total_raw)
    rr.fp_reduction_pct = round(rr.total_filtered / total * 100, 1)

    rr.avg_time_ms = round(rr.total_time_s / max(1, rr.n_total) * 1000, 1)

    return rr


def generate_report(rr: RegressionResult) -> str:
    """生成Markdown报告 + JSON摘要."""
    md_path = RESULTS_DIR / "regression_report.md"

    lines = [
        "# Heap Overflow Detection — Regression Test Report",
        "",
        f"**Generated**: {rr.timestamp}",
        f"**Engine**: DP-TVRA (Demand-Driven Path-Sensitive Taint-Value-Range Analysis)",
        "",
        "## Summary Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Samples scanned | {rr.n_total} |",
        f"| Detected | {rr.n_detected} |",
        f"| Clean | {rr.n_clean} |",
        f"| **Recall** | **{rr.recall_pct}%** |",
        f"| **Precision** | **{rr.precision_pct}%** |",
        f"| **F1 Score** | **{rr.f1_pct}%** |",
        f"| FP Reduction | {rr.fp_reduction_pct}% |",
        f"| Total time | {rr.total_time_s:.2f}s |",
        f"| Avg time/sample | {rr.avg_time_ms:.1f}ms |",
        "",
        "## Per-Sample Results",
        "",
        "| Sample | Result | Raw | C | L | U | F | Time(ms) |",
        "|--------|--------|-----|---|---|---|---|----------|",
    ]

    for s in rr.per_sample:
        lines.append(
            f"| {s.get('sample_id', '?')} "
            f"| {'✅' if s.get('detected') else '❌'} "
            f"| {s.get('raw_findings', 0)} "
            f"| {s.get('confirmed', 0)} "
            f"| {s.get('likely', 0)} "
            f"| {s.get('uncertain', 0)} "
            f"| {s.get('filtered_fp', 0)} "
            f"| {int(s.get('elapsed_sec', 0) * 1000)} |")

    lines += [
        "",
        "## Detection Engine",
        "",
        "**DP-TVRA** three-phase pipeline:",
        "1. **Phase 0 (Bound Check)**: Direct comparison of alloc size vs write size",
        "2. **Phase 1 (Taint)**: Sparse demand-driven taint propagation",
        "3. **Phase 2 (Path Narrowing)**: Path-sensitive interval narrowing via cmp/jcc",
        "4. **Phase 3 (Alloc Model)**: ptmalloc2 allocation model verification",
        "",
        "---",
        "*Generated by `heap_analysis/regression_runner.py`*",
    ]

    report = "\n".join(lines)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n  Report: {md_path}")

    # JSON
    json_path = RESULTS_DIR / "regression_summary.json"
    summary = {
        "timestamp": rr.timestamp,
        "engine": "DP-TVRA",
        "n_total": rr.n_total,
        "n_detected": rr.n_detected,
        "n_clean": rr.n_clean,
        "recall_pct": rr.recall_pct,
        "precision_pct": rr.precision_pct,
        "f1_pct": rr.f1_pct,
        "fp_reduction_pct": rr.fp_reduction_pct,
        "total_time_s": rr.total_time_s,
        "avg_time_ms": rr.avg_time_ms,
        "per_sample": rr.per_sample,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"  JSON:   {json_path}")
    return str(md_path)


def main():
    parser = argparse.ArgumentParser(description="DP-TVRA Regression Test")
    parser.add_argument("--quick", action="store_true",
                        help="Skip detailed findings in JSON")
    args = parser.parse_args()

    print("=" * 60)
    print("DP-TVRA Heap Overflow Detection — Regression Test")
    print("=" * 60)

    rr = scan_all()

    print(f"\n{'=' * 60}")
    print(f"Samples: {rr.n_total} | Detected: {rr.n_detected} | "
          f"Recall: {rr.recall_pct}% | Precision: {rr.precision_pct}% | "
          f"F1: {rr.f1_pct}%")
    print(f"FP Reduction: {rr.fp_reduction_pct}% | "
          f"Time: {rr.total_time_s}s ({rr.avg_time_ms}ms/sample)")
    print(f"{'=' * 60}")

    generate_report(rr)


if __name__ == "__main__":
    main()
