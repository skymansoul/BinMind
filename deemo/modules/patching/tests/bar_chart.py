# 创建: 2026-08-09 14:30
# 对比实验柱状图 — matplotlib绘制检出率/误报率/耗时

"""对比实验可视化: 从experiment_results.json读取数据，生成论文级柱状图。

输出: comparison_bar.png (300 DPI, 适合论文投稿)
依赖: matplotlib (pip install matplotlib)
"""

import os
import sys
import json
import math
from collections import defaultdict

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ground truth: 哪些样本确实有漏洞
GROUND_TRUTH_VULN = {
    "CVE-2016-10191_heap_overflow": True,
    "CVE-2019-15947_uaf": True,
    "CVE-2012-0809_format_string": True,
    "CVE-2020-10757_stack_overflow": True,
}


def load_experiment_data(json_path: str = None) -> dict:
    if json_path is None:
        json_path = os.path.join(OUTPUT_DIR, "experiment_results.json")
    if not os.path.exists(json_path):
        print(f"experiment_results.json not found at {json_path}")
        print("Run experiment_launcher.py first.")
        sys.exit(1)
    with open(json_path, "r") as f:
        return json.load(f)


def compute_tool_metrics(data: dict) -> dict:
    """计算每个工具的检出率/误报率/平均耗时。"""
    results = data.get("results", [])
    tool_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "times": [], "errors": 0})

    for r in results:
        tool = r["tool"]
        sample = r["sample"]
        has_vuln = GROUND_TRUTH_VULN.get(sample, False)
        detected = r.get("detected", False)
        if r.get("error"):
            tool_stats[tool]["errors"] += 1
            continue
        tool_stats[tool]["times"].append(r.get("time_secs", 0))
        if has_vuln and detected:
            tool_stats[tool]["tp"] += 1
        elif not has_vuln and detected:
            tool_stats[tool]["fp"] += 1
        elif has_vuln and not detected:
            tool_stats[tool]["fn"] += 1
        else:
            tool_stats[tool]["tn"] += 1

    metrics = {}
    for tool, stats in tool_stats.items():
        tp, fp, fn, tn = stats["tp"], stats["fp"], stats["fn"], stats["tn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        avg_time = sum(stats["times"]) / len(stats["times"]) if stats["times"] else 0.0
        metrics[tool] = {
            "precision": precision, "recall": recall, "f1": f1,
            "avg_time_secs": avg_time, "errors": stats["errors"],
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }
    return metrics


def plot_comparison(metrics: dict, output_path: str = None):
    """绘制柱状图: 检出率(recall) + F1 + 平均耗时。"""
    if output_path is None:
        output_path = os.path.join(OUTPUT_DIR, "comparison_bar.png")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed. Install with: pip install matplotlib")
        print(f"Metrics data (skip plotting): {json.dumps(metrics, indent=2)}")
        return

    tools = list(metrics.keys())
    recalls = [metrics[t]["recall"] * 100 for t in tools]
    f1s = [metrics[t]["f1"] * 100 for t in tools]
    times = [metrics[t]["avg_time_secs"] for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))

    x = range(len(tools))
    width = 0.35
    bars1 = ax1.bar([i - width/2 for i in x], recalls, width, label="Recall %", color="#2c7bb6")
    bars2 = ax1.bar([i + width/2 for i in x], f1s, width, label="F1 Score", color="#fdae61")
    ax1.set_ylabel("Percentage (%)")
    ax1.set_title("Detection Rate by Tool")
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, rotation=15, ha="right")
    ax1.legend()
    ax1.set_ylim(0, 105)
    for bar in bars1:
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f"{bar.get_height():.0f}", ha="center", fontsize=9)

    colors = ["#2c7bb6", "#fdae61", "#d7191c", "#4daf4a"]
    bars3 = ax2.bar(x, times, color=[colors[i % len(colors)] for i in x])
    ax2.set_ylabel("Average Time (seconds)")
    ax2.set_title("Average Analysis Time per Sample")
    ax2.set_xticks(x)
    ax2.set_xticklabels(tools, rotation=15, ha="right")
    for bar in bars3:
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                f"{bar.get_height():.1f}s", ha="center", fontsize=9)

    fig.suptitle("Binary Vulnerability Detection — Tool Comparison (CVE Samples)",
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"Chart saved: {output_path}")


def generate_latex_comparison_table(metrics: dict) -> str:
    """生成完整的LaTeX对比表。"""
    rows = []
    for tool in ["BinMind", "Angr", "QEMU+ASAN", "Ghidra"]:
        m = metrics.get(tool, {})
        if not m:
            continue
        rows.append(
            f"{tool} & {m.get('tp',0)+m.get('fn',0)} & {m['recall']*100:.1f}\\% & "
            f"{m['precision']*100:.1f}\\% & {m['f1']*100:.1f}\\% & "
            f"{m['avg_time_secs']:.1f} & {m.get('fp',0)} & {m.get('fn',0)} \\\\"
        )

    return r"""\begin{table}[t]
\centering
\caption{Comparison of Binary Vulnerability Detection Tools on CVE Samples}
\label{tab:tool_comparison}
\begin{tabular}{lccccccc}
\toprule
\textbf{Tool} & \textbf{Samples} & \textbf{Recall} & \textbf{Precision} & \textbf{F1} & \textbf{Time(s)} & \textbf{FP} & \textbf{FN} \\
\midrule
%s
\bottomrule
\end{tabular}
\end{table}""" % "\n".join(rows)


if __name__ == "__main__":
    data = load_experiment_data()
    metrics = compute_tool_metrics(data)
    plot_comparison(metrics)
    latex = generate_latex_comparison_table(metrics)
    latex_path = os.path.join(OUTPUT_DIR, "comparison_table.tex")
    with open(latex_path, "w") as f:
        f.write(latex)
    print(f"LaTeX table: {latex_path}")
    print(json.dumps(metrics, indent=2))
