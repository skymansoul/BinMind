"""结果收集与对比模块 — 汇总编译+扫描结果, 生成对比报告.

创建: 2026-07-04
用途: 读取 compile_report.json + scan_report.json,
      结合预期结果 (ground truth), 计算检出率/误报率/漏报率,
      输出人类可读的汇总报告和机器可读的JSON。
"""
import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict


# 每个样本的 ground truth: 是否包含真正的堆溢出漏洞
# sample16 (safe_guarded) 和 sample17 (fp_test) 是阴性对照
GROUND_TRUTH = {
    "sample01_heap_overflow_basic": True,
    "sample02_off_by_one": True,
    "sample03_memcpy_no_check": True,
    "sample04_loop_overflow": True,
    "sample05_fmt_string_heap": True,
    "sample06_CVE-2022-24834": True,
    "sample07_CVE-2023-25139": True,
    "sample08_int_overflow_to_heap": True,
    "sample09_CVE-2015-0235_ghost": True,
    "sample10_CVE-2020-10713": True,
    "sample11_realloc_misuse": True,
    "sample12_multi_free_heap": True,
    "sample13_struct_field_overflow": True,
    "sample14_nested_loop_heap": True,
    "sample15_CVE-2017-1000112": True,
    "sample16_safe_guarded": False,       # 阴性对照 — 安全代码
    "sample17_false_positive_test": False, # 阴性对照 — 合法padding访问
}


@dataclass
class PerSampleResult:
    sample_name: str
    is_vulnerable: bool           # ground truth
    detected: bool                # 是否检出
    finding_count: int = 0
    confirmed_count: int = 0
    is_false_positive: bool = False  # 检出但 ground truth 是 safe
    is_missed: bool = False         # 未检出但 ground truth 是 vulnerable
    elapsed_ms: float = 0.0


@dataclass
class AggregateReport:
    total_samples: int = 0
    vulnerable_samples: int = 0
    safe_samples: int = 0
    true_positives: int = 0       # 检出且确实有漏洞
    false_positives: int = 0      # 检出但实际安全
    true_negatives: int = 0       # 未检出且确实安全
    false_negatives: int = 0      # 未检出但确实有漏洞
    detection_rate: float = 0.0   # TP / (TP + FN) = recall
    false_positive_rate: float = 0.0  # FP / (FP + TN)
    precision: float = 0.0        # TP / (TP + FP)
    f1_score: float = 0.0
    avg_elapsed_ms: float = 0.0
    per_sample: List[PerSampleResult] = field(default_factory=list)


def collect(compile_path: str, scan_path: str) -> AggregateReport:
    """收集编译和扫描结果, 生成汇总报告."""
    compile_info = {}
    scan_info = {}

    if os.path.exists(compile_path):
        with open(compile_path) as f:
            compile_info = json.load(f)
    if os.path.exists(scan_path):
        with open(scan_path) as f:
            scan_info = json.load(f)

    details = scan_info.get("details", [])
    report = AggregateReport()
    report.total_samples = len(GROUND_TRUTH)

    for sample_name, is_vuln in sorted(GROUND_TRUTH.items()):
        ps = PerSampleResult(
            sample_name=sample_name, is_vulnerable=is_vuln)

        # 查找对应的扫描结果
        scan_detail = None
        for d in details:
            if d.get("sample", "") == sample_name:
                scan_detail = d
                break

        if scan_detail:
            ps.finding_count = scan_detail.get("findings", 0)
            ps.confirmed_count = scan_detail.get("confirmed", 0)
            ps.elapsed_ms = scan_detail.get("elapsed_ms", 0)
            ps.detected = ps.finding_count > 0
        else:
            ps.detected = False

        # 分类
        if is_vuln and ps.detected:
            report.true_positives += 1
        elif is_vuln and not ps.detected:
            report.false_negatives += 1
            ps.is_missed = True
        elif not is_vuln and ps.detected:
            report.false_positives += 1
            ps.is_false_positive = True
        elif not is_vuln and not ps.detected:
            report.true_negatives += 1

        report.per_sample.append(ps)

    report.vulnerable_samples = sum(
        1 for v in GROUND_TRUTH.values() if v)
    report.safe_samples = report.total_samples - report.vulnerable_samples

    # 计算指标
    tp, fp, tn, fn = (report.true_positives, report.false_positives,
                       report.true_negatives, report.false_negatives)

    report.detection_rate = tp / max(1, tp + fn)
    report.false_positive_rate = fp / max(1, fp + tn)
    report.precision = tp / max(1, tp + fp)
    if report.precision + report.detection_rate > 0:
        report.f1_score = (2 * report.precision * report.detection_rate
                          / max(0.001, report.precision + report.detection_rate))

    elapsed_times = [ps.elapsed_ms for ps in report.per_sample
                     if ps.elapsed_ms > 0]
    report.avg_elapsed_ms = (sum(elapsed_times) / max(1, len(elapsed_times)))

    return report


def format_report(report: AggregateReport) -> str:
    """格式化汇总报告为人类可读文本."""
    lines = []
    lines.append("=" * 70)
    lines.append("  HEAP OVERFLOW DETECTION — REGRESSION TEST REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Total Samples:        {report.total_samples}")
    lines.append(f"  Vulnerable (GT=YES):  {report.vulnerable_samples}")
    lines.append(f"  Safe (GT=NO):         {report.safe_samples}")
    lines.append("")
    lines.append("  CONFUSION MATRIX:")
    lines.append(f"    True Positives:     {report.true_positives}")
    lines.append(f"    False Positives:    {report.false_positives}")
    lines.append(f"    True Negatives:     {report.true_negatives}")
    lines.append(f"    False Negatives:    {report.false_negatives}")
    lines.append("")
    lines.append("  METRICS:")
    lines.append(f"    Detection Rate (Recall):  {report.detection_rate:.1%}")
    lines.append(f"    False Positive Rate:      {report.false_positive_rate:.1%}")
    lines.append(f"    Precision:                {report.precision:.1%}")
    lines.append(f"    F1 Score:                 {report.f1_score:.3f}")
    lines.append(f"    Avg Scan Time:            {report.avg_elapsed_ms:.0f}ms")
    lines.append("")
    lines.append("  PER-SAMPLE DETAILS:")
    lines.append(f"    {'Sample':<35} {'GT':>5} {'Detected':>9} {'Status':>15}")
    lines.append(f"    {'-'*35} {'-'*5} {'-'*9} {'-'*15}")
    for ps in report.per_sample:
        gt_str = "VULN" if ps.is_vulnerable else "SAFE"
        det_str = "YES" if ps.detected else "NO"
        if ps.is_false_positive:
            status = "FP (FALSE ALARM)"
        elif ps.is_missed:
            status = "FN (MISSED)"
        elif ps.is_vulnerable and ps.detected:
            status = "TP (CORRECT)"
        elif not ps.is_vulnerable and not ps.detected:
            status = "TN (CORRECT)"
        else:
            status = "???"
        lines.append(
            f"    {ps.sample_name:<35} {gt_str:>5} {det_str:>9} {status:>15}")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    compile_path = os.path.join(base, "compile_report.json")
    scan_path = os.path.join(base, "scan_report.json")

    report = collect(compile_path, scan_path)
    print(format_report(report))

    # 保存JSON报告
    json_report = {
        "confusion_matrix": {
            "TP": report.true_positives, "FP": report.false_positives,
            "TN": report.true_negatives, "FN": report.false_negatives,
        },
        "metrics": {
            "detection_rate": round(report.detection_rate, 4),
            "fp_rate": round(report.false_positive_rate, 4),
            "precision": round(report.precision, 4),
            "f1_score": round(report.f1_score, 4),
            "avg_elapsed_ms": round(report.avg_elapsed_ms, 1),
        },
        "per_sample": [
            {
                "sample": ps.sample_name,
                "gt_vulnerable": ps.is_vulnerable,
                "detected": ps.detected,
                "findings": ps.finding_count,
                "confirmed": ps.confirmed_count,
                "is_fp": ps.is_false_positive,
                "is_fn": ps.is_missed,
            }
            for ps in report.per_sample
        ],
    }
    out_path = os.path.join(base, "results_report.json")
    with open(out_path, "w") as f:
        json.dump(json_report, f, indent=2)
    print(f"\nJSON report written to {out_path}")
