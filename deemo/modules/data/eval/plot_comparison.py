# 对比实验可视化 — matplotlib 柱状图, 检出率/误报率分组
# 输入: benchmark_results.csv  输出: comparison_chart.png
# 创建: 2026-04-28

import csv, os, sys

def plot_from_csv(csv_path: str, output_png: str, title: str = ""):
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed. pip install matplotlib")
        return

    tools, precisions, recalls, f1s = [], [], [], []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tools.append(row["Tool"])
            precisions.append(float(row["Precision"]))
            recalls.append(float(row["Recall"]))
            f1s.append(float(row["F1"]))

    if not tools:
        print("No data in CSV"); return

    x = np.arange(len(tools)); width = 0.22
    fig, ax = plt.subplots(figsize=(10, 6))

    colors = {"Precision": "#2196F3", "Recall": "#4CAF50", "F1": "#FF9800"}
    datasets = [("Precision", precisions, 0), ("Recall", recalls, 1), ("F1", f1s, 2)]
    for label, values, offset in datasets:
        bars = ax.bar(x + offset * width, values, width, label=label,
                      color=colors[label], edgecolor="white", linewidth=0.5)
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f"{val:.2f}", ha="center", va="bottom", fontsize=7)

    ax.set_ylabel("Score", fontsize=11)
    ax.set_title(title or "Heap Overflow Detection — Cross-Tool Comparison", fontsize=13, fontweight="bold")
    ax.set_xticks(x + width)
    ax.set_xticklabels(tools, fontsize=10)
    ax.legend(loc="upper right", fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    plt.tight_layout()
    plt.savefig(output_png, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Chart saved: {output_png}")

if __name__ == "__main__":
    csv_path = os.path.join(os.path.dirname(__file__), "benchmark_results.csv")
    png_path = os.path.join(os.path.dirname(__file__), "comparison_chart.png")
    if os.path.isfile(csv_path):
        plot_from_csv(csv_path, png_path,
                       "Heap Overflow Detection — False Positive Reduction via 3-Stage Filtering")
    else:
        print(f"No CSV at {csv_path}. Run run_benchmark.py first.")
