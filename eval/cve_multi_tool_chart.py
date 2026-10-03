"""
"""
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


def generate_cve_chart(all_metrics, all_results, timestamp, out_dir):
    """生成对比图表."""
    tools = ['BinMind-Full', 'Regex-Base', 'Heuristic', 'Angr-CFG']

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    # (a) 召回率/F1 条形图
    ax = axes[0]
    x = np.arange(len(tools))
    width = 0.35
    recalls = [all_metrics[t]['recall'] for t in tools]
    f1s = [all_metrics[t]['f1'] for t in tools]
    bars1 = ax.bar(x - width/2, recalls, width, label='Recall',
                   color='#2196F3', alpha=0.85)
    bars2 = ax.bar(x + width/2, f1s, width, label='F1',
                   color='#4CAF50', alpha=0.85)
    ax.set_ylabel('Score')
    ax.set_title('(a) CVE Detection: Recall & F1')
    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=15, ha='right', fontsize=8)
    ax.legend()
    ax.set_ylim(0, 1.15)
    for bar, val in zip(bars1, recalls):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f'{val:.0%}', ha='center', fontsize=8)
    for bar, val in zip(bars2, f1s):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f'{val:.0%}', ha='center', fontsize=8)

    # (b) TP/FN 堆叠
    ax = axes[1]
    tps = [all_metrics[t]['TP'] for t in tools]
    fns = [all_metrics[t]['FN'] for t in tools]
    ax.bar(x, tps, 0.6, label='TP (Detected)', color='#4CAF50')
    ax.bar(x, fns, 0.6, bottom=tps, label='FN (Missed)', color='#F44336')
    ax.set_ylabel('Samples')
    ax.set_title('(b) Detection Count (16 CVE samples)')
    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=15, ha='right', fontsize=8)
    ax.legend()
    for i, (tp, fn) in enumerate(zip(tps, fns)):
        ax.text(i, tp/2, str(tp), ha='center', fontweight='bold', color='white')
        if fn > 0:
            ax.text(i, tp + fn/2, str(fn), ha='center', fontweight='bold')

    # (c) 耗时对比
    ax = axes[2]
    avg_times = [
        sum(r.get('duration_ms', 0) for r in all_results[t]) / max(len(all_results[t]), 1)
        for t in tools
    ]
    colors = ['#2196F3', '#FF9800', '#9C27B0', '#607D8B']
    ax.bar(x, avg_times, 0.6, color=colors)
    ax.set_ylabel('Avg Time (ms)')
    ax.set_title('(c) Average Analysis Time')
    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=15, ha='right', fontsize=8)
    for i, val in enumerate(avg_times):
        ax.text(i, val + 0.5, f'{val:.1f}ms', ha='center', fontsize=8)

    plt.tight_layout()
    chart_path = os.path.join(out_dir, f'cve_multi_tool_chart_{timestamp}.png')
    plt.savefig(chart_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  图表: {chart_path}')
