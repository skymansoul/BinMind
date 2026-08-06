# 创建: 2025-09-26 10:00
# 结果解析模块 — 解析扫描结果并计算检测指标

"""结果解析模块: 聚合扫描结果、计算检出率/误报率/耗时等指标。

输入: scan_scheduler.py生成的scan_results_*.json
输出:
  1. 终端文本报告 (summary table)
  2. metrics.json (结构化指标，供绘图脚本消费)
  3. paper_table.tex (LaTeX表格片段)

指标定义:
  TP (True Positive):  引擎报告了漏洞 且 样本确实有该漏洞
  FP (False Positive): 引擎报告了漏洞 但 样本无该漏洞
  FN (False Negative): 引擎未报告漏洞 但 样本确实有该漏洞
  TN (True Negative):  引擎未报告漏洞 且 样本确实无该漏洞

  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)
  F1        = 2 * P * R / (P + R)
"""

import os
import sys
import json
import time

SAMPLE_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/cve_samples"

# 样本的标注信息 (ground truth)
GROUND_TRUTH = {
    "CVE-2016-10191_heap_overflow":    {"type": "heap_overflow",   "has_vuln": True},
    "CVE-2019-15947_uaf":              {"type": "use_after_free",  "has_vuln": True},
    "CVE-2012-0809_format_string":     {"type": "format_string",   "has_vuln": True},
    "CVE-2020-10757_stack_overflow":   {"type": "stack_overflow",  "has_vuln": True},
}


def load_results(json_path: str) -> dict:
    with open(json_path, "r") as f:
        return json.load(f)


def compute_metrics(scan_report: dict) -> dict:
    """从扫描报告计算 TP/FP/FN/TN 和 F1。"""
    results = scan_report.get("results", [])
    tp = fp = fn = tn = 0
    details = []

    for r in results:
        sample_name = r["sample"]
        gt = GROUND_TRUTH.get(sample_name, {"has_vuln": False, "type": "unknown"})

        # 引擎判定: 检查是否报告了漏洞
        autopatcher_found = r.get("engines", {}).get("autopatcher", {}).get("vulnerabilities_found", 0) > 0
        taint_active = r.get("engines", {}).get("taint", {}).get("tainted_regs", 0) > 0

        engine_reports_vuln = autopatcher_found or taint_active

        if gt["has_vuln"] and engine_reports_vuln:
            tp += 1; verdict = "TP"
        elif not gt["has_vuln"] and engine_reports_vuln:
            fp += 1; verdict = "FP"
        elif gt["has_vuln"] and not engine_reports_vuln:
            fn += 1; verdict = "FN"
        else:
            tn += 1; verdict = "TN"

        details.append({"sample": sample_name, "type": gt["type"],
                       "verdict": verdict, "autopatcher": autopatcher_found,
                       "taint": taint_active})

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / max(tp + fp + fn + tn, 1), 4),
        "details": details
    }


def generate_latex_table(metrics: dict, tool_name: str = "BinMind") -> str:
    """生成LaTeX表格片段。"""
    m = metrics
    return r"""\begin{table}[t]
\centering
\caption{Detection Results: %s on CVE Sample Set}
\label{tab:detection_results}
\begin{tabular}{lcccccc}
\toprule
\textbf{Tool} & \textbf{Samples} & \textbf{Precision} & \textbf{Recall} & \textbf{F1} & \textbf{Accuracy} & \textbf{Time(s)} \\
\midrule
%s & %d & %.3f & %.3f & %.3f & %.3f & %.1f \\
\bottomrule
\end{tabular}
\end{table}""" % (tool_name, tool_name,
    m.get("total_samples", 0), m["precision"], m["recall"],
    m["f1"], m["accuracy"], m.get("elapsed_secs", 0))


def generate_text_report(metrics: dict) -> str:
    """生成终端可读的文本报告。"""
    m = metrics
    lines = [
        "=" * 60,
        "  BinMind Detection Regression Test Report",
        "=" * 60,
        f"  Total Samples:  {m.get('total_samples', 0)}",
        f"  TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  TN={m['tn']}",
        f"  Precision:      {m['precision']:.3f}",
        f"  Recall:         {m['recall']:.3f}",
        f"  F1 Score:       {m['f1']:.3f}",
        f"  Accuracy:       {m['accuracy']:.3f}",
        f"  Elapsed:        {m.get('elapsed_secs', 0):.1f}s",
        "-" * 60,
    ]
    for d in m.get("details", []):
        lines.append(f"  [{d['verdict']}] {d['sample']} ({d['type']})")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    results_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(SAMPLE_ROOT), "scan_results_debug.json")

    if not os.path.exists(results_path):
        print(f"结果文件不存在: {results_path}")
        print("请先运行 scan_scheduler.py 生成扫描结果")
        sys.exit(1)

    scan_report = load_results(results_path)
    metrics = compute_metrics(scan_report)
    metrics["total_samples"] = scan_report.get("total_samples", 0)
    metrics["elapsed_secs"] = scan_report.get("elapsed_secs", 0)

    # 输出三种格式
    print(generate_text_report(metrics))

    metrics_path = os.path.join(os.path.dirname(SAMPLE_ROOT), "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    latex = generate_latex_table(metrics)
    latex_path = os.path.join(os.path.dirname(SAMPLE_ROOT), "paper_table.tex")
    with open(latex_path, "w") as f:
        f.write(latex)

    print(f"\nMetrics saved: {metrics_path}")
    print(f"LaTeX table:   {latex_path}")
