# coding: utf-8
"""
结果收集与对比 + 一键入口.

职责:
  1. 调用样本加载/扫描完成全量回归
  2. 按 检出/漏报/误报/真负 分类聚合
  3. 计算 Precision/Recall/F1/FPR
  4. 输出逐样本明细 (CSV + 控制台)
  5. 提供 HOSV-only 与 HOSV+写模式扩展的对比
"""

import csv
import json
import os
import sys
import time
from typing import Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from ._load_samples import load_samples, SAMPLES_DIR  # noqa: E402
from _scan import HosvScanScheduler  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))


def _compute_metrics(outcomes: List) -> Dict:
    tp = sum(1 for o in outcomes if o.is_true_positive)
    fp = sum(1 for o in outcomes if o.is_false_positive)
    fn = sum(1 for o in outcomes if o.is_false_negative)
    tn = sum(1 for o in outcomes if o.is_true_negative)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def _print_table(outcomes: List) -> None:
    print("%-22s %-6s %-7s %-7s %s" % ("sample", "expect", "verdict", "mode",
                                        "reason"))
    print("-" * 100)
    for o in outcomes:
        if o.expected == "VULN":
            verdict = "VULN" if o.any_heap_vuln else ("FN" if not o.error else "ERR")
        else:
            verdict = "FP" if o.any_heap_vuln else "SAFE"
        reason = o.vuln_reasons[0][:70] if o.vuln_reasons else \
            (o.error or "-")
        print("%-22s %-6s %-7s %-7s %s" % (
            o.sample_id, o.expected, verdict, "ext" if o.ext_vuln else "-",
            reason))


def run(out_path: str = None) -> Dict:
    """一键运行完整回归."""
    specs = load_samples()
    scheduler = HosvScanScheduler()
    outcomes = []
    for spec in specs:
        source = open(spec.src_path, "r", encoding="utf-8",
                      errors="replace").read()
        outcomes.append(scheduler.scan_source(
            spec.sample_id, spec.verdict, source))
    metrics = _compute_metrics(outcomes)
    _print_table(outcomes)

    # HOSV-only vs HOSV+写模式扩展对比
    hosv_only = []
    for o in outcomes:
        o2 = _copy_skip_ext(o)
        hosv_only.append(o2)
    metrics_hosv = _compute_metrics(hosv_only)

    print("\n=== HOSV only ===")
    print(metrics_hosv)
    print("=== HOSV + 写模式扩展 ===")
    print(metrics)

    result = {
        "metrics": metrics,
        "metrics_hosv_only": metrics_hosv,
        "per_sample": [
            {
                "sample": o.sample_id, "expected": o.expected,
                "any_vuln": o.any_heap_vuln, "hosv_vuln": o.hosv_vuln,
                "ext_vuln": o.ext_vuln,
                "time_ms": round(o.time_ms, 2),
                "reasons": o.vuln_reasons[:3],
            }
            for o in outcomes
        ],
    }
    if out_path is None:
        out_path = os.path.join(BASE, "regression_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("\nsaved:", out_path)
    return result


def _copy_skip_ext(o) -> "ScanOutcome":
    """构造仅含 HOSV 判定的副本."""
    from _scan import ScanOutcome
    return ScanOutcome(
        sample_id=o.sample_id, expected=o.expected,
        any_heap_vuln=o.hosv_vuln, hosv_vuln=o.hosv_vuln,
        ext_vuln=False, vuln_reasons=o.vuln_reasons,
        time_ms=o.time_ms, error=o.error)


def write_csv(outcomes: List, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "any_vuln", "hosv_vuln",
                    "ext_vuln", "time_ms", "reasons"])
        for o in outcomes:
            w.writerow([o.sample_id, o.expected, o.any_heap_vuln,
                        o.hosv_vuln, o.ext_vuln,
                        round(o.time_ms, 2), "|".join(o.vuln_reasons)])


if __name__ == "__main__":
    run()
