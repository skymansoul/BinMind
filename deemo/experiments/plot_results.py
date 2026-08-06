# 对比实验可视化: 检出率 + 耗时柱状图, matplotlib 不可用时降级为 CSV

import json
import os
import sys
from collections import defaultdict


def load_results(json_path: str) -> list[dict]:
    with open(json_path) as f:
        return json.load(f)


def aggregate(results: list[dict]) -> dict:
    tools = defaultdict(lambda: {'total': 0, 'with_findings': 0, 'times': []})
    for r in results:
        tool = r.get('tool', 'unknown')
        tools[tool]['total'] += 1
        elapsed = r.get('elapsed_sec', 0)
        if elapsed > 0:
            tools[tool]['times'].append(elapsed)
        out = r.get('output', '')
        if out and ('findings' in str(out).lower()):
            tools[tool]['with_findings'] += 1

    summary = {}
    for tool, s in tools.items():
        avg_t = sum(s['times']) / max(1, len(s['times']))
        det_rate = s['with_findings'] / max(1, s['total'])
        summary[tool] = {
            'samples': s['total'],
            'detection_rate': round(det_rate, 3),
            'avg_time_sec': round(avg_t, 1),
        }
    return summary


def plot_benchmark(summary: dict, output_path: str):
    """从JSON聚合结果生成检出率/耗时双柱状图"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print('matplotlib not installed, falling back to CSV')
        _write_csv(summary, output_path.replace('.png', '.csv'))
        return

    tools = sorted(summary.keys())
    det_rates = [summary[t]['detection_rate'] * 100 for t in tools]
    avg_times = [summary[t]['avg_time_sec'] for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))
    x = np.arange(len(tools))
    width = 0.5
    colors = ['#2196F3', '#4CAF50', '#FF9800', '#F44336'][:len(tools)]

    bars1 = ax1.bar(x, det_rates, width, color=colors)
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_title('Detection Rate by Tool')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, rotation=15)
    ax1.set_ylim(0, 100)
    for bar, val in zip(bars1, det_rates):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                 f'{val:.1f}%', ha='center', fontsize=9)

    bars2 = ax2.bar(x, avg_times, width, color=colors)
    ax2.set_ylabel('Avg Time (seconds)')
    ax2.set_title('Average Analysis Time by Tool')
    ax2.set_xticks(x)
    ax2.set_xticklabels(tools, rotation=15)
    for bar, val in zip(bars2, avg_times):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 f'{val:.1f}s', ha='center', fontsize=9)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f'Plot saved: {output_path}')


def plot_comparison(data_file: str = None, output_stem: str = 'comparison_chart'):
    """多工具检出率/误报率/耗时对比图。
    可读 JSON 文件，缺省使用内置示例。
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print('matplotlib not installed, skipping comparison chart')
        return

    if data_file and os.path.isfile(data_file):
        with open(data_file) as f:
            raw = json.load(f)
        tools_data = raw.get('tools', raw)
        tools = list(tools_data.keys())
        det_rates = [tools_data[t].get('detection_rate', 0) * 100 for t in tools]
        fp_rates = [tools_data[t].get('fp_rate', 0) * 100 for t in tools]
        times = [tools_data[t].get('avg_time', 0) for t in tools]
    else:
        # 内置示例，实际使用时替换为数据文件
        tools = ['BinMind', 'Angr', 'QEMU', 'Ghidra']
        det_rates = [70, 55, 30, 45]
        fp_rates = [25, 40, 60, 35]
        times = [12.5, 45.0, 8.2, 30.0]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    x = np.arange(len(tools))
    w = 0.35

    ax1.bar(x - w / 2, det_rates, w, label='Detection Rate', color='#2ecc71')
    ax1.bar(x + w / 2, fp_rates, w, label='False Positive Rate', color='#e74c3c')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools)
    ax1.set_ylabel('Rate (%)')
    ax1.legend()
    ax1.set_title('Detection vs FP Rate')

    ax2.bar(tools, times, color='#3498db')
    ax2.set_ylabel('Seconds')
    ax2.set_title('Avg Scan Time')

    plt.tight_layout()
    pdf_path = f'{output_stem}.pdf'
    png_path = f'{output_stem}.png'
    plt.savefig(pdf_path, dpi=150)
    plt.savefig(png_path, dpi=150)
    print(f'Saved {pdf_path} and {png_path}')


def _write_csv(summary: dict, csv_path: str):
    with open(csv_path, 'w') as f:
        f.write('tool,samples,detection_rate,avg_time_sec\n')
        for tool, s in summary.items():
            f.write(f'{tool},{s["samples"]},{s["detection_rate"]},{s["avg_time_sec"]}\n')
    print(f'CSV saved: {csv_path}')


def main():
    json_path = os.path.join(os.path.dirname(__file__), 'benchmark_results.json')
    if not os.path.isfile(json_path):
        print(f'Results not found: {json_path}')
        return
    results = load_results(json_path)
    summary = aggregate(results)
    out_path = os.path.join(os.path.dirname(__file__), 'benchmark_plot.png')
    plot_benchmark(summary, out_path)


if __name__ == '__main__':
    main()
