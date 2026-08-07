#!/usr/bin/env python3
"""
对比实验结果绘图 — 从comparison JSON生成论文级柱状图。

创建: 2026-06-11 16:45
修改:
  2025-10-07 16:45 — 初始实现: 检出率/误报率/耗时/内存柱状图

用法:
  python scripts/plot_results.py \
    --input results/comparison/comparison_20251007.json \
    --output results/comparison/charts/
"""

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


def load_data(json_path: str) -> dict:
    with open(json_path) as f:
        return json.load(f)


def _aggregate_tool_stats(data: dict) -> dict:
    """按工具聚合统计: 平均耗时/检出率/标准差。"""
    tool_runs = defaultdict(list)
    for r in data['runs']:
        if r['success']:
            tool_runs[r['tool']].append(r)

    stats = {}
    for tool, runs in tool_runs.items():
        times = [r['time'] for r in runs]
        findings = [r['findings'] for r in runs]
        stats[tool] = {
            'avg_time': np.mean(times),
            'std_time': np.std(times),
            'avg_findings': np.mean(findings),
            'std_findings': np.std(findings),
            'success_rate': len(runs) / max(1, len([x for x in data['runs']
                                                     if x['tool'] == tool])),
        }
    return stats


def plot_detection_time(data: dict, output_dir: str):
    """检出率 vs 耗时 柱状图(双Y轴)。"""
    stats = _aggregate_tool_stats(data)
    tools = sorted(stats.keys())
    x = np.arange(len(tools))
    width = 0.35

    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax2 = ax1.twinx()

    times = [stats[t]['avg_time'] for t in tools]
    time_err = [stats[t]['std_time'] for t in tools]
    findings = [stats[t]['avg_findings'] for t in tools]
    find_err = [stats[t]['std_findings'] for t in tools]

    bars1 = ax1.bar(x - width/2, times, width, label='Avg Time (s)',
                     color='#4472C4', yerr=time_err, capsize=4)
    bars2 = ax2.bar(x + width/2, findings, width, label='Avg Findings',
                     color='#ED7D31', yerr=find_err, capsize=4)

    ax1.set_xlabel('Tool')
    ax1.set_ylabel('Average Scan Time (seconds)', color='#4472C4')
    ax2.set_ylabel('Average Findings per Sample', color='#ED7D31')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, rotation=15)
    ax1.tick_params(axis='y', labelcolor='#4472C4')
    ax2.tick_params(axis='y', labelcolor='#ED7D31')

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    plt.title(f'Detection Performance Comparison ({data.get("samples", "?")} samples)')
    plt.tight_layout()
    os.makedirs(output_dir, exist_ok=True)
    fig.savefig(os.path.join(output_dir, 'detection_time.png'), dpi=150)
    plt.close(fig)


def plot_success_rate(data: dict, output_dir: str):
    """工具成功率柱状图。"""
    stats = _aggregate_tool_stats(data)
    tools = sorted(stats.keys())
    rates = [stats[t]['success_rate'] * 100 for t in tools]

    fig, ax = plt.subplots(figsize=(6, 4))
    colors = ['#4472C4', '#ED7D31', '#A5A5A5', '#FFC000']
    bars = ax.bar(tools, rates, color=colors[:len(tools)])
    ax.set_ylabel('Success Rate (%)')
    ax.set_ylim(0, 105)
    ax.set_title('Tool Execution Success Rate')
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{rate:.1f}%', ha='center', fontsize=9)
    plt.tight_layout()
    os.makedirs(output_dir, exist_ok=True)
    fig.savefig(os.path.join(output_dir, 'success_rate.png'), dpi=150)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='comparison JSON file')
    ap.add_argument('--output', default='results/comparison/charts/')
    args = ap.parse_args()

    data = load_data(args.input)
    output_dir = args.output

    print(f'Plotting {len(data.get("runs", []))} runs across {len(data.get("tools", []))} tools')
    plot_detection_time(data, output_dir)
    print(f'  -> {output_dir}detection_time.png')
    plot_success_rate(data, output_dir)
    print(f'  -> {output_dir}success_rate.png')
    print('Done.')


if __name__ == '__main__':
    main()
