# coding: utf-8
#
"""
生成对比实验柱状图-检出率对比 + 耗时对比。
依赖: matplotlib (pip install matplotlib)
"""

import json
import sys
import os


def plot_comparison(json_path: str, output_dir: str):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib未安装, 跳过绘图 (pip install matplotlib)")
        return

    with open(json_path) as f:
        data = json.load(f)

    tools = list(data.keys())
    detection_rates = []
    avg_times = []
    for tool in tools:
        results = data[tool]
        total = len(results)
        detected = sum(1 for r in results if r['detected'])
        dr = detected / max(total, 1) * 100
        avg_t = (sum(r['elapsed_sec'] for r in results) / max(total, 1))
        detection_rates.append(dr)
        avg_times.append(avg_t)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # 检出率柱状图
    colors = ['#2ecc71' if dr > 60 else '#e74c3c' for dr in detection_rates]
    bars1 = ax1.bar(tools, detection_rates, color=colors, edgecolor='black')
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_title('Detection Rate by Tool')
    ax1.set_ylim(0, 100)
    for bar, dr in zip(bars1, detection_rates):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f'{dr:.0f}%', ha='center', fontsize=9)

    # 平均耗时柱状图
    bars2 = ax2.bar(tools, avg_times, color='#3498db', edgecolor='black')
    ax2.set_ylabel('Avg Time (seconds)')
    ax2.set_title('Average Analysis Time')
    for bar, t in zip(bars2, avg_times):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                 f'{t:.1f}s', ha='center', fontsize=8)

    plt.tight_layout()
    out_path = os.path.join(output_dir, 'comparison_chart.png')
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    print(f"图表: {out_path}")


if __name__ == '__main__':
    json_path = sys.argv[1] if len(sys.argv) > 1 else 'comparison_results.json'
    out_dir = sys.argv[2] if len(sys.argv) > 2 else '.'
    plot_comparison(json_path, out_dir)
