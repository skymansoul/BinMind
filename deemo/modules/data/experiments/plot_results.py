# 对比实验结果可视化 — matplotlib柱状图 + 输出PNG
# 创建: 2026-04-23

import json, os, sys

def plot_comparison(results_json: str, output_png: str):
    """从raw_results.json生成对比柱状图."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed. Install: pip install matplotlib")
        return

    with open(results_json) as f:
        data = json.load(f)

    tools = list(data.keys())
    metrics = {"Precision": [], "Recall": [], "F1": []}

    for tool in tools:
        results = data[tool]
        tp = sum(1 for r in results if r.get("detected"))
        fp = sum(1 for r in results if r.get("false_positive"))
        fn = sum(1 for r in results if not r.get("detected"))
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        metrics["Precision"].append(precision)
        metrics["Recall"].append(recall)
        metrics["F1"].append(f1)

    x = np.arange(len(tools))
    width = 0.25
    fig, ax = plt.subplots(figsize=(10, 6))

    colors = {'Precision': '#2196F3', 'Recall': '#4CAF50', 'F1': '#FF9800'}
    for i, (metric_name, values) in enumerate(metrics.items()):
        bars = ax.bar(x + i * width, values, width, label=metric_name,
                      color=colors[metric_name], edgecolor='white')
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                    f'{val:.2f}', ha='center', va='bottom', fontsize=8)

    ax.set_ylabel('Score')
    ax.set_title('Cross-Tool Vulnerability Detection Comparison')
    ax.set_xticks(x + width)
    ax.set_xticklabels(tools)
    ax.legend(loc='upper right')
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_png, dpi=150)
    plt.close()
    print(f"Chart saved to {output_png}")

if __name__ == "__main__":
    results = os.path.join(os.path.dirname(__file__), "output", "raw_results.json")
    output = os.path.join(os.path.dirname(__file__), "output", "comparison_chart.png")
    if os.path.isfile(results):
        plot_comparison(results, output)
    else:
        print(f"No results file at {results}. Run compare_runner.py first.")
