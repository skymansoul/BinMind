"""
综合基准测试框架 — 多工具、多样本、多指标的自动化对比。

用法: python -m eval.comprehensive_benchmark [--samples DIR] [--output DIR]
      python -m eval.comprehensive_benchmark --quick  # 快速模式

输出:
  - benchmark_results.json: 每个样本/工具的详细结果
  - benchmark_summary.csv / .json: 汇总统计 (TP/FP/FN/TN)
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

from .tool_runners import (
    run_binmind, run_angr_analysis, run_qemu_trace, run_ghidra_analysis,
    TOOL_RUNNERS,
)

DEFAULT_SAMPLES_DIR = "tests/heap_overflow_samples"
DEFAULT_OUTPUT_DIR = "eval/results"
TOOLS = ["binmind", "angr", "qemu", "ghidra"]


def _find_elf_files(samples_dir: str) -> List[Tuple[str, str, bool]]:
    """扫描样本目录, 返回 [(sample_id, elf_path, is_vulnerable), ...]。"""
    samples = []
    if not os.path.isdir(samples_dir):
        return samples

    for dirname in sorted(os.listdir(samples_dir)):
        dirpath = os.path.join(samples_dir, dirname)
        if not os.path.isdir(dirpath):
            continue

        elf = _locate_elf(dirpath)
        if elf is None:
            continue

        dn_lower = dirname.lower()
        is_vuln = any(kw in dn_lower for kw in
                       ('cve', 'tp_', 'vuln', 'overflow', 'tp-', 'heap-ovf',
                        'ho_'))
        samples.append((dirname, elf, is_vuln))

    return samples


def _locate_elf(dirpath: str) -> str | None:
    """在目录中查找可执行文件。"""
    for fname in os.listdir(dirpath):
        fpath = os.path.join(dirpath, fname)
        if fname.endswith('.exe') or fname == 'vuln':
            if os.access(fpath, os.X_OK) or fname.endswith('.exe'):
                return fpath
        try:
            with open(fpath, 'rb') as f:
                if f.read(4) == b'\x7fELF':
                    return fpath
        except Exception:
            pass
    makefile = os.path.join(dirpath, 'Makefile')
    if os.path.exists(makefile):
        try:
            subprocess.run(['make', '-C', dirpath], timeout=30,
                           capture_output=True)
            for fname in os.listdir(dirpath):
                fpath = os.path.join(dirpath, fname)
                if fname == 'vuln' and os.access(fpath, os.X_OK):
                    return fpath
        except Exception:
            pass
    return None


def _compute_metrics(
    results: List[dict], samples: List[Tuple[str, str, bool]],
) -> Dict[str, Any]:
    """计算 TP/FP/FN/TN。"""
    by_tool: Dict[str, List[dict]] = {}
    for r in results:
        by_tool.setdefault(r.get("tool", "unknown"), []).append(r)

    sample_vuln_map = {sid: is_vuln for sid, _, is_vuln in samples}
    metrics = {}

    for tool, tool_results in by_tool.items():
        tp = fp = fn = tn = 0
        total_vuln = total_safe = 0

        for r in tool_results:
            sid = r.get("sample", "")
            is_vuln = sample_vuln_map.get(sid, False)
            if is_vuln:
                total_vuln += 1
            else:
                total_safe += 1

            found = _has_findings(tool, r)
            if is_vuln and found:
                tp += 1
            elif is_vuln and not found:
                fn += 1
            elif not is_vuln and found:
                fp += 1
            else:
                tn += 1

        recall = tp / max(1, tp + fn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * recall * precision / max(0.001, recall + precision)
        fpr = fp / max(1, fp + tn)

        metrics[tool] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "f1": round(f1, 3),
            "false_positive_rate": round(fpr, 3),
            "total_vuln_samples": total_vuln,
            "total_safe_samples": total_safe,
        }

    return metrics


def _has_findings(tool: str, r: dict) -> bool:
    """判断工具是否在样本中发现了危险模式。"""
    if tool == "BinMind":
        return r.get("findings_confirmed", 0) > 0
    elif tool == "Angr":
        return r.get("dangerous_calls", 0) > 0
    elif tool == "QEMU-user":
        return r.get("instructions_executed", 0) > 0
    else:
        return r.get("success", False)


def run_benchmark(
    samples_dir: str = DEFAULT_SAMPLES_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    quick: bool = False,
) -> Dict[str, Any]:
    """主基准测试流程。"""
    os.makedirs(output_dir, exist_ok=True)
    samples = _find_elf_files(samples_dir)

    if quick:
        samples = samples[:5]

    if not samples:
        print("No ELF samples found.")
        return {"error": "no_samples"}

    print(f"Benchmark: {len(samples)} samples | Tools: {', '.join(TOOLS)}")
    print("-" * 60)

    runner_map = {
        "binmind": run_binmind, "angr": run_angr_analysis,
        "qemu": run_qemu_trace, "ghidra": run_ghidra_analysis,
    }
    all_results: List[dict] = []

    for i, (sample_id, elf_path, is_vuln) in enumerate(samples):
        label = "VULN" if is_vuln else "SAFE"
        print(f"[{i+1}/{len(samples)}] {sample_id} ({label})")

        for tool_name in TOOLS:
            runner = runner_map.get(tool_name)
            if runner is None:
                continue
            r = runner(elf_path, sample_id)
            all_results.append(r)
            findings = r.get("findings_confirmed",
                             r.get("dangerous_calls",
                                   r.get("instructions_executed", "?")))
            dur = r.get("duration_s", 0)
            print(f"  {tool_name}: {findings} findings, {dur:.1f}s")

    metrics = _compute_metrics(all_results, samples)

    # 写入 JSON
    results_path = os.path.join(output_dir, "benchmark_results.json")
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, default=str)

    summary_path = os.path.join(output_dir, "benchmark_summary.json")
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump({"samples_dir": samples_dir, "total_samples": len(samples),
                   "tools": TOOLS, "metrics": metrics}, f, indent=2)

    # 写入 CSV
    csv_path = os.path.join(output_dir, "benchmark_summary.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Tool", "TP", "FP", "FN", "TN", "Recall",
                          "Precision", "F1", "FPR", "Vuln", "Safe"])
        for tool, m in metrics.items():
            writer.writerow([tool, m["TP"], m["FP"], m["FN"], m["TN"],
                             m["recall"], m["precision"], m["f1"],
                             m["false_positive_rate"],
                             m["total_vuln_samples"], m["total_safe_samples"]])

    print("-" * 60 + "\nSummary:")
    for tool, m in metrics.items():
        print(f"  {tool}: R={m['recall']:.1%} P={m['precision']:.1%} "
              f"F1={m['f1']:.3f} FPR={m['false_positive_rate']:.1%}")

    return {"metrics": metrics, "results_file": results_path,
            "summary_file": summary_path, "csv_file": csv_path}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default=DEFAULT_SAMPLES_DIR)
    parser.add_argument("--output", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    run_benchmark(args.samples, args.output, args.quick)
