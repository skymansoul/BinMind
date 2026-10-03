# 对比实验可视化——生成检出率/误报率对比柱状图
# 依赖: matplotlib (pip install matplotlib)
# 输入: comparison_results.json
# 输出: comparison_chart.png

import json
import sys
from pathlib import Path

def load_data():
    path = Path(__file__).parent / "comparison_results.json"
    if not path.exists():
        # 生成示例数据用于演示
        return {
            "summary": {
                "OurMethod": {"detection_rate": 0.87, "avg_time_ms": 45, "false_positives": 2, "n_samples": 15, "detected": 13},
                "Angr": {"detection_rate": 0.93, "avg_time_ms": 3200, "false_positives": 34, "n_samples": 15, "detected": 14},
                "QEMU": {"detection_rate": 0.60, "avg_time_ms": 180, "false_positives": 0, "n_samples": 15, "detected": 9},
                "Ghidra": {"detection_rate": 0.80, "avg_time_ms": 850, "false_positives": 28, "n_samples": 15, "detected": 12},
            }
        }
    with open(path) as f:
        return json.load(f)


def plot_chart(data, output_path="comparison_chart.png"):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib未安装。安装: pip install matplotlib")
        # 生成ASCII图表作为fallback
        print("\nASCII替代图表:")
        print("Tool         Detection  FP_Count  Time(ms)")
        print("-" * 50)
        for tool, m in data.get("summary", {}).items():
            fp = m.get('false_positives', m.get('fp_count', 0))
            print(f"{tool:<12} {m['detection_rate']:>8.1%}  {fp:>8}  {m['avg_time_ms']:>8.0f}")
        return

    summary = data.get("summary", {})
    tools = list(summary.keys())
    colors = ['#2ecc71','#3498db','#e74c3c','#f39c12','#9b59b6','#1abc9c'][:len(tools)]
    det_rates = [summary[t].get("detection_rate", 0) * 100 for t in tools]
    fp_counts = [summary[t].get("false_positives", summary[t].get("fp_count", 0)) for t in tools]
    times = [summary[t].get("avg_time_ms", 0) for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    x = np.arange(len(tools))
    bars = ax1.bar(x, det_rates, color=colors)
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_title('Detection Rate by Tool')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, rotation=15)
    ax1.set_ylim(0, 100)
    for bar, rate in zip(bars, det_rates):
        ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                f'{rate:.1f}%', ha='center', fontsize=9)

    # 右图: 误报数vs耗时散点图
    ax2.scatter(fp_counts, times, s=200, c=colors)
    for i, tool in enumerate(tools):
        ax2.annotate(tool, (fp_counts[i], times[i]),
                    textcoords="offset points", xytext=(0, 10), ha='center')
    ax2.set_xlabel('False Positive Count')
    ax2.set_ylabel('Avg Time (ms)')
    ax2.set_title('FP Count vs Scan Time')
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    print(f"图表已保存: {output_path}")


if __name__ == '__main__':
    data = load_data()
    plot_chart(data, str(Path(__file__).parent / "comparison_chart.png"))
