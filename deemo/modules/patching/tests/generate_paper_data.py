# 创建: 2026-06-08 14:10
# 论文数据导出 — 将实验数据转为论文所需的 CSV/JSON 格式

"""论文数据导出器。

从 experiment_results.json 和 metrics.json 中提取数据，
生成论文所需格式:
  1. paper_table.csv — 导入LaTeX/Excel的表格数据
  2. paper_data.json — 结构化JSON (供外部工具消费)
  3. detection_by_sample.csv — 每个样本的逐工具检测结果

用法: python generate_paper_data.py
"""

import os
import sys
import json
import csv
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_DIR = os.path.dirname(BASE_DIR)


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def generate_comparison_csv(experiment_data: dict, output: str):
    """生成工具对比CSV: 每个工具一行的汇总统计。"""
    results = experiment_data.get("results", [])

    # 按工具聚合
    tool_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                                       "times": [], "errors": 0, "total": 0})
    for r in results:
        tool = r["tool"]
        tool_stats[tool]["total"] += 1
        tool_stats[tool]["times"].append(r.get("time_secs", 0))
        if r.get("error"):
            tool_stats[tool]["errors"] += 1
            continue
        # 简化: 所有CVE样本都有漏洞
        has_vuln = True
        detected = r.get("detected", False)
        if has_vuln and detected:
            tool_stats[tool]["tp"] += 1
        elif has_vuln and not detected:
            tool_stats[tool]["fn"] += 1

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Tool", "Samples", "TP", "FN", "Recall", "AvgTime(s)",
                         "Errors", "PeakMem(MB)"])
        for tool in ["BinMind", "Angr", "QEMU+ASAN", "Ghidra"]:
            s = tool_stats.get(tool)
            if not s or s["total"] == 0:
                continue
            tp, fn = s["tp"], s["fn"]
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            avg_time = sum(s["times"]) / len(s["times"]) if s["times"] else 0.0
            writer.writerow([tool, s["total"], tp, fn, round(recall, 3),
                           round(avg_time, 2), s["errors"], "N/A"])


def generate_detailed_csv(experiment_data: dict, output: str):
    """生成逐样本逐工具检测结果。"""
    results = experiment_data.get("results", [])
    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Sample", "Tool", "Detected", "Time(s)", "Error"])
        for r in sorted(results, key=lambda x: (x["sample"], x["tool"])):
            writer.writerow([r["sample"], r["tool"],
                           int(r.get("detected", False)),
                           r.get("time_secs", 0),
                           r.get("error", "")[:100] if r.get("error") else ""])


def generate_paper_json(experiment_data: dict, metrics: dict, output: str):
    """生成完整论文数据JSON。"""
    paper = {
        "metadata": {
            "title": "Lightweight Value-Domain Taint Analysis for Binary Vulnerability Detection",
            "date": "2025-09",
            "benchmark": "10 CVE samples (heap/UAF/format_string/stack/int_overflow/cmd_inject/race)",
        },
        "comparison": {},
        "by_vuln_type": metrics.get("by_vuln_type", {}),
        "config_impact": metrics.get("config_comparison", {}),
    }

    results = experiment_data.get("results", [])
    tool_data = defaultdict(lambda: {"detected": 0, "total": 0, "time_total": 0.0})
    for r in results:
        t = r["tool"]
        tool_data[t]["total"] += 1
        tool_data[t]["time_total"] += r.get("time_secs", 0)
        if r.get("detected"):
            tool_data[t]["detected"] += 1

    for tool, d in tool_data.items():
        paper["comparison"][tool] = {
            "detection_rate": round(d["detected"] / d["total"], 3) if d["total"] > 0 else 0.0,
            "avg_time_secs": round(d["time_total"] / d["total"], 2) if d["total"] > 0 else 0.0,
            "samples": d["total"],
        }

    with open(output, "w") as f:
        json.dump(paper, f, indent=2)


def main():
    exp_path = os.path.join(os.path.dirname(BASE_DIR), "experiment_results.json")
    metrics_path = os.path.join(os.path.dirname(BASE_DIR), "dashboard_report.json")

    exp_data = load_json(exp_path)
    metrics = load_json(metrics_path)

    if not exp_data:
        print("experiment_results.json not found — run experiment_launcher.py first")
        return 1

    out_dir = os.path.dirname(BASE_DIR)
    generate_comparison_csv(exp_data, os.path.join(out_dir, "paper_table.csv"))
    generate_detailed_csv(exp_data, os.path.join(out_dir, "detection_by_sample.csv"))
    generate_paper_json(exp_data, metrics, os.path.join(out_dir, "paper_data.json"))

    print("Paper data exported:")
    print(f"  {out_dir}/paper_table.csv")
    print(f"  {out_dir}/detection_by_sample.csv")
    print(f"  {out_dir}/paper_data.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
