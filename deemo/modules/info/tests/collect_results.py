# tests/collect_results — 结果收集与对比模块
# 读取扫描日志, 计算每个样本的检出/误报/漏报状态,
# 输出 CSV 和 JSON 格式的对比报告。
#
# 判定逻辑:
#   - 正样本 (CVE-*): 置信度 ≥ 0.35 的检出算 true positive (检出);
#     无检出算 false negative (漏报)
#   - 负样本 (NEG-*): 置信度 ≥ 0.35 的检出算 false positive (误报);
#     无检出算 true negative (正确过滤)
#   - 置信度分档: high(≥0.7), medium(0.35-0.7), low(<0.35)

import os, json, csv
from pathlib import Path
from datetime import datetime
from typing import Dict, List

SCAN_LOG = Path(__file__).parent / "regression" / "scan_results.json"
REPORT_DIR = Path(__file__).parent / "regression" / "reports"


def classify_sample(sample_name: str) -> str:
    """判断样本类型: 'positive' | 'negative' | 'unknown'。"""
    if sample_name.startswith("CVE-"):
        return "positive"
    if sample_name.startswith("NEG-"):
        return "negative"
    if "heap" in sample_name.lower() or "overflow" in sample_name.lower():
        return "positive"
    if "safe" in sample_name.lower():
        return "negative"
    return "unknown"


def analyze_scan_results(scan_data: dict) -> dict:
    """分析扫描结果, 计算各指标。"""
    results = scan_data.get("results", [])
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {},
        "by_sample": [],
        "by_method": {},
    }

    # 按方法分组
    for method_name in ("AC3-v1", "PSVR-HLM-v2"):
        method_results = [r for r in results if r.get("method") == method_name]
        if not method_results:
            continue

        tp, fp, tn, fn = 0, 0, 0, 0
        total_positive, total_negative = 0, 0
        elapsed_total = 0.0
        detail_rows = []

        for r in method_results:
            sample = r["sample"]
            stype = classify_sample(sample)
            result = r.get("result", {})
            findings = result.get("findings", [])
            stats = result.get("stats", {})
            is_detected = stats.get("total", 0) > 0

            high_conf = any(f.get("confidence", 0) >= 0.7 for f in findings)

            if stype == "positive":
                total_positive += 1
                if high_conf or is_detected:
                    tp += 1
                else:
                    fn += 1
            elif stype == "negative":
                total_negative += 1
                if high_conf or is_detected:
                    fp += 1
                else:
                    tn += 1

            elapsed_total += r.get("elapsed_ms", 0)

            detail_rows.append({
                "sample": sample,
                "type": stype,
                "findings": stats.get("total", 0),
                "high_conf": stats.get("high_conf", 0),
                "medium_conf": stats.get("medium_conf", 0),
                "low_conf": stats.get("low_conf", 0),
                "avg_confidence": stats.get("avg_confidence", 0),
                "elapsed_ms": r.get("elapsed_ms", 0),
                "peak_memory_kb": r.get("peak_memory_kb", 0),
                "detected": is_detected,
            })

        recall = tp / max(tp + fn, 1)
        precision = tp / max(tp + fp, 1)
        fpr = fp / max(total_negative, 1)  # false positive rate on negatives
        f1 = 2 * precision * recall / max(precision + recall, 0.01)
        avg_elapsed = elapsed_total / max(len(method_results), 1)

        report["by_method"][method_name] = {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "total_positive_samples": total_positive,
            "total_negative_samples": total_negative,
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "false_positive_rate": round(fpr, 3),
            "f1_score": round(f1, 3),
            "avg_elapsed_ms": round(avg_elapsed, 1),
            "details": detail_rows,
        }

    # 计算 v2 vs v1 的改善
    if "AC3-v1" in report["by_method"] and "PSVR-HLM-v2" in report["by_method"]:
        v1 = report["by_method"]["AC3-v1"]
        v2 = report["by_method"]["PSVR-HLM-v2"]
        fp_reduction = (1.0 - v2["false_positives"] / max(v1["false_positives"], 1)) * 100
        report["improvement"] = {
            "fp_reduction_pct": round(fp_reduction, 1),
            "recall_delta": round(v2["recall"] - v1["recall"], 3),
            "f1_delta": round(v2["f1_score"] - v1["f1_score"], 3),
        }

    report["by_sample"] = detail_rows
    return report


def export_csv(report: dict, output_path: Path = None):
    """导出 CSV 格式的逐样本对比。"""
    if output_path is None:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = REPORT_DIR / f"comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    rows = report.get("by_sample", [])
    if not rows:
        print("No data to export")
        return

    fieldnames = ["sample", "type", "findings", "high_conf", "medium_conf",
                   "low_conf", "avg_confidence", "elapsed_ms", "peak_memory_kb",
                   "detected"]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"CSV exported: {output_path}")


def export_json(report: dict, output_path: Path = None):
    """导出 JSON 格式的完整报告。"""
    if output_path is None:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(f"JSON exported: {output_path}")


def print_summary(report: dict):
    """打印可读的汇总报告。"""
    print("\n" + "=" * 60)
    print("BINMIND HEAP OVERFLOW DETECTION — COMPARISON REPORT")
    print("=" * 60)
    for method, data in report.get("by_method", {}).items():
        print(f"\n--- {method} ---")
        print(f"  Samples:       {data['total_positive_samples']}pos + {data['total_negative_samples']}neg")
        print(f"  TP={data['true_positives']}  FP={data['false_positives']}  "
              f"TN={data['true_negatives']}  FN={data['false_negatives']}")
        print(f"  Recall:        {data['recall']:.1%}")
        print(f"  Precision:     {data['precision']:.1%}")
        print(f"  FP Rate:       {data['false_positive_rate']:.1%}")
        print(f"  F1 Score:      {data['f1_score']:.3f}")
        print(f"  Avg Time:      {data['avg_elapsed_ms']:.1f}ms")

    imp = report.get("improvement", {})
    if imp:
        print(f"\n--- PSVR-HLM v2 vs AC3 v1 ---")
        print(f"  FP Reduction:  {imp['fp_reduction_pct']:.1f}%")
        print(f"  Recall Delta:  {imp['recall_delta']:+.3f}")
        print(f"  F1 Delta:      {imp['f1_delta']:+.3f}")
    print("=" * 60)


def run_analysis():
    """主入口: 读取扫描日志, 分析并输出报告。"""
    if not SCAN_LOG.exists():
        print(f"Scan log not found: {SCAN_LOG}")
        print("Run tests/run_scanner.py first.")
        return

    with open(SCAN_LOG, "r") as f:
        scan_data = json.load(f)

    report = analyze_scan_results(scan_data)
    export_json(report)
    export_csv(report)
    print_summary(report)
    return report


if __name__ == "__main__":
    run_analysis()
