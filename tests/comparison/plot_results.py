# 对比实验绘图脚本 — matplotlib柱状图: 各工具检出率/误报率/平均耗时
import json, sys, os
from pathlib import Path

def plot_comparison(results_json, output_png="comparison_chart.png"):
    """从对比实验JSON生成柱状图."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed. Run: pip install matplotlib numpy")
        return False

    with open(results_json) as f:
        data = json.load(f)

    tools = list(next(iter(data.values())).keys())
    n_samples = len(data)
    metrics = {}
    for tool in tools:
        ok = sum(1 for r in data.values() if r[tool]["status"] == "ok")
        avg_t = sum(r[tool]["elapsed"] for r in data.values()) / max(n_samples, 1)
        detections = sum(r[tool]["findings"] for r in data.values())
        metrics[tool] = {"ok": ok, "avg_time": avg_t, "detections": detections}

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    # 柱状图1: 检出数对比
    ax1 = axes[0]
    x = np.arange(len(tools))
    det_vals = [metrics[t]["detections"] for t in tools]
    bars = ax1.bar(x, det_vals, color=['#2196F3','#FF9800','#4CAF50','#9C27B0'])
    ax1.set_xticks(x); ax1.set_xticklabels(tools, fontsize=10)
    ax1.set_ylabel('Total Detections'); ax1.set_title(f'Detection Count ({n_samples} samples)')
    for bar, val in zip(bars, det_vals):
        ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3, str(val),
                ha='center', fontsize=9)
    # 柱状图2: 平均耗时
    ax2 = axes[1]
    time_vals = [metrics[t]["avg_time"] for t in tools]
    bars2 = ax2.bar(x, time_vals, color=['#2196F3','#FF9800','#4CAF50','#9C27B0'])
    ax2.set_xticks(x); ax2.set_xticklabels(tools, fontsize=10)
    ax2.set_ylabel('Avg Time (seconds)'); ax2.set_title('Average Analysis Time')
    for bar, val in zip(bars2, time_vals):
        ax2.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3, f'{val:.1f}s',
                ha='center', fontsize=9)
    plt.tight_layout()
    plt.savefig(output_png, dpi=150)
    print(f"Chart saved to {output_png}")
    return True

if __name__ == "__main__":
    json_file = sys.argv[1] if len(sys.argv) > 1 else "comparison_results.json"
    out_png = sys.argv[2] if len(sys.argv) > 2 else "comparison_chart.png"
    plot_comparison(json_file, out_png)
