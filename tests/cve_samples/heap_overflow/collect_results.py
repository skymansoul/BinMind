"""
收集扫描结果并与预期对比, 生成检出/误报/漏报统计.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


RESULTS_DIR = Path(__file__).parent / "scan_results"
SCAN_OUTPUT = RESULTS_DIR / "scan_output.json"
REPORT_FILE = Path(__file__).parent / "regression_report.json"

# 预期结果: sample_name → (is_vulnerable, expected_findings_min)
# is_vulnerable: True = 应该有溢出检出, False = 不应检出 (安全代码)
EXPECTED = {
    "cve_01_simple_overflow":      (True,  1, "base overflow"),
    "cve_02_off_by_one":            (True,  1, "off-by-one"),
    "cve_03_int_overflow_calc":     (True,  1, "integer overflow calc"),
    "cve_04_strcpy_overflow":       (True,  1, "strcpy overflow"),
    "cve_05_loop_overflow":         (True,  1, "loop overflow"),
    "cve_06_user_controlled_size":  (True,  1, "user-controlled size"),
    "cve_07_realloc_overflow":      (True,  1, "realloc overflow"),
    "cve_08_calloc_overflow":       (True,  1, "calloc overflow"),
    "cve_09_safe_but_triggers_fp":  (False, 0, "FP — alignment safety"),
    "cve_10_input_constrained_safe":(False, 0, "FP — constrained input"),
    "cve_11_memcpy_arith_size":     (True,  1, "memcpy arith overflow"),
    "cve_12_alignment_edge":        (True,  1, "alignment edge"),
    "cve_13_struct_field_pattern":  (False, 0, "FP — struct field in bounds"),
    "cve_14_multi_chunk":           (True,  1, "multi-chunk overflow"),
    "cve_15_constrained_input":     (True,  1, "constrained but overflowed"),
    "cve_16_real_world_pattern":    (True,  1, "real-world pattern"),
    "cve_17_multi_field_struct":    (False, 0, "FP — multi-field stride safe"),
}


def load_scan_results() -> Dict:
    if SCAN_OUTPUT.exists():
        with open(SCAN_OUTPUT) as f:
            return json.load(f)
    return {"results": []}


def evaluate_results(scan_data: Dict) -> Dict:
    """评估扫描结果: 计算 TP, FP, FN, TN."""
    metrics = {
        "total_samples": 0,
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
        "detection_rate": 0.0,
        "false_positive_rate": 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "per_sample": [],
    }

    scan_results = {r["sample"]: r for r in scan_data.get("results", [])}

    for sample_name, (is_vuln, min_findings, desc) in EXPECTED.items():
        metrics["total_samples"] += 1
        sr = scan_results.get(sample_name, {})
        findings = sr.get("findings", [])
        has_error = bool(sr.get("error"))
        scan_time = sr.get("scan_time_ms", 0)

        n_findings = len(findings)
        detected = n_findings >= min_findings if min_findings > 0 else n_findings > 0

        # 判定
        if is_vuln and detected:
            verdict = "TP"
            metrics["true_positive"] += 1
        elif is_vuln and not detected:
            verdict = "FN"
            metrics["false_negative"] += 1
        elif not is_vuln and not detected:
            verdict = "TN"
            metrics["true_negative"] += 1
        elif not is_vuln and detected:
            verdict = "FP"
            metrics["false_positive"] += 1

        sample_result = {
            "sample": sample_name,
            "expected_vuln": is_vuln,
            "description": desc,
            "findings_count": n_findings,
            "verdict": verdict,
            "scan_time_ms": scan_time,
            "error": sr.get("error"),
            "top_findings": [
                {
                    "confidence": f.get("confidence", 0),
                    "desc": f.get("description", "")[:80],
                }
                for f in findings[:3]
            ],
        }
        metrics["per_sample"].append(sample_result)

    # 计算指标
    tp, fp, tn, fn = (metrics["true_positive"], metrics["false_positive"],
                       metrics["true_negative"], metrics["false_negative"])
    total = tp + fp + tn + fn

    metrics["detection_rate"] = tp / max(1, tp + fn)
    metrics["false_positive_rate"] = fp / max(1, fp + tn)
    metrics["precision"] = tp / max(1, tp + fp)
    metrics["recall"] = tp / max(1, tp + fn)

    return metrics


def main():
    if not SCAN_OUTPUT.exists():
        print("No scan results found. Run run_scanner.py first.")
        # 生成一个基于 compile_results 的占位报告
        compile_results = Path(__file__).parent / "compile_results.json"
        if compile_results.exists():
            print(f"Found compile results at {compile_results}")
            print("Run 'python run_scanner.py' to scan, then re-run this script.")
        return 1

    scan_data = load_scan_results()
    metrics = evaluate_results(scan_data)

    # 打印摘要
    print("=" * 60)
    print("HEAP OVERFLOW REGRESSION TEST RESULTS")
    print("=" * 60)
    print(f"Total samples:          {metrics['total_samples']}")
    print(f"True Positive:          {metrics['true_positive']}")
    print(f"True Negative:          {metrics['true_negative']}")
    print(f"False Positive:         {metrics['false_positive']}")
    print(f"False Negative:         {metrics['false_negative']}")
    print(f"-" * 40)
    print(f"Recall (Detection Rate): {metrics['recall']:.1%}")
    print(f"FP Rate:                 {metrics['false_positive_rate']:.1%}")
    print(f"Precision:               {metrics['precision']:.1%}")
    print("=" * 60)

    for s in metrics["per_sample"]:
        marker = {
            "TP": "+", "TN": ".", "FP": "!", "FN": "-",
        }.get(s["verdict"], "?")
        print(f"  [{marker}] {s['sample']:35s} {s['verdict']:3s} "
              f"findings={s['findings_count']} {s['scan_time_ms']:.0f}ms")

    # 写入报告
    with open(REPORT_FILE, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nFull report: {REPORT_FILE}")

    # 返回码: FP+FN > 0 则非零
    issues = metrics["false_positive"] + metrics["false_negative"]
    return min(issues, 1)


if __name__ == "__main__":
    sys.exit(main())
