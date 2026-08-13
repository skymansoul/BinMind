"""对比可视化 — matplotlib 图表 + LaTeX 表格生成.

创建: 2024-10-11
用途: 从 benchmark JSON 结果生成:
  1. 多工具 F1/Recall/Precision 柱状图
  2. 时间效率对比图
  3. 混淆矩阵热力图
  4. LaTeX 对比表格

使用方式:
  python plot_comparison.py results/benchmark_20260807_120000.json
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

_PROJ = Path(__file__).resolve().parent
_RESULTS = _PROJ / 'results'
_RESULTS.mkdir(parents=True, exist_ok=True)

_HAS_MPL = False
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    _HAS_MPL = True
except ImportError:
    pass


# 颜色方案
try:
    from .plot_data import MIMO_DEFAULTS, COLORS
    from .plot_multi import plot_multi_type
except ImportError:
    from plot_data import MIMO_DEFAULTS, COLORS
    from plot_multi import plot_multi_type


def load_report(json_path: str = None, vuln_type: str = 'heap_overflow') -> dict:
    """加载基准报告 JSON, 或返回对应类型的默认数据."""
    if json_path and os.path.exists(json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    jsons = sorted(_RESULTS.glob('benchmark_*.json'))
    if jsons:
        with open(jsons[-1], 'r', encoding='utf-8') as f:
            return json.load(f)

    defaults = MIMO_DEFAULTS.get(vuln_type, MIMO_DEFAULTS['heap_overflow'])
    return {'tools': defaults}


def generate_latex(report: dict, output_dir: str = None) -> str:
    """生成 LaTeX 对比表格."""
    tools = report.get('tools', [])
    if not tools:
        return None
    out_dir = Path(output_dir or _RESULTS)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = str(out_dir / f'result_table_{ts}.tex')

    lines = [
        r'\begin{table}[htbp]',
        r'  \centering',
        r'  \caption{Multi-Tool Heap Overflow Detection Comparison}',
        r'  \label{tab:multitool}',
        r'  \begin{tabular}{lcccc}',
        r'    \toprule',
        r'    \textbf{Method} & \textbf{Recall} & \textbf{Precision} & \textbf{F1} & \textbf{Time (ms)} \\',
        r'    \midrule',
    ]
    for t in tools:
        lines.append(
            r'    \textbf{' + t['tool'] + '} & ' +
            f'{t["recall"]:.1f}\\% & {t["precision"]:.1f}\\% & '
            f'{t["f1"]:.1f} & {t["avg_time_ms"]:.0f} \\\\')
    lines.extend([
        r'    \bottomrule',
        r'  \end{tabular}',
        r'\end{table}',
    ])

    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'LaTeX: {path}')
    return path


def plot_metrics(report: dict, output_path: str = None):
    """绘制 F1/Recall/Precision 柱状图."""
    if not _HAS_MPL:
        print('[!] matplotlib 未安装, 跳过图表生成')
        return

    tools = [t['tool'] for t in report['tools']]
    recall = [t['recall'] for t in report['tools']]
    precision = [t['precision'] for t in report['tools']]
    f1 = [t['f1'] for t in report['tools']]

    x = range(len(tools))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar([i - width for i in x], recall, width,
                   label='Recall (%)', color='#2196F3', alpha=0.9)
    bars2 = ax.bar(x, precision, width,
                   label='Precision (%)', color='#4CAF50', alpha=0.9)
    bars3 = ax.bar([i + width for i in x], f1, width,
                   label='F1 Score', color='#FF5722', alpha=0.9)

    # 标注数值
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f'{h:.1f}', xy=(bar.get_x() + bar.get_width()/2, h),
                       xytext=(0, 3), textcoords='offset points',
                       ha='center', va='bottom', fontsize=8)

    ax.set_ylabel('Score (%)', fontsize=12)
    ax.set_title('Multi-Tool Heap Overflow Detection Comparison\n'
                 'AVHO-G vs Angr / QEMU / Ghidra (18-sample benchmark)',
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(tools, fontsize=10)
    ax.legend(loc='lower right', fontsize=10)
    ax.set_ylim(0, 110)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    if output_path is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = str(_RESULTS / f'comparison_metrics_{ts}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'图表: {output_path}')
    return output_path


def plot_time(report: dict, output_path: str = None):
    """绘制时间效率对比图 (对数坐标)."""
    if not _HAS_MPL:
        return

    tools = [t['tool'] for t in report['tools']]
    times = [t['avg_time_ms'] for t in report['tools']]

    fig, ax = plt.subplots(figsize=(10, 5))
    colors = [COLORS.get(t, '#607D8B') for t in tools]
    bars = ax.bar(tools, times, color=colors, alpha=0.85, edgecolor='white')

    for bar, t in zip(bars, times):
        label = f'{t:.1f}ms' if t < 1000 else f'{t/1000:.1f}s'
        ax.annotate(label, xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                   xytext=(0, 5), textcoords='offset points',
                   ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax.set_ylabel('Average Time per Sample (ms)', fontsize=12)
    ax.set_title('Analysis Speed Comparison\n(Log Scale)',
                 fontsize=14, fontweight='bold')
    ax.set_yscale('log')
    ax.grid(axis='y', alpha=0.3)

    # 加速比标注
    baseline = times[0] if times else 1
    for i, (tool, t) in enumerate(zip(tools, times)):
        if i == 0:
            continue
        speedup = t / baseline
        ax.annotate(f'{speedup:.0f}× slower',
                   xy=(i, t), xytext=(i + 0.3, t * 1.5),
                   fontsize=8, color='#F44336',
                   arrowprops=dict(arrowstyle='->', color='#F44336', lw=0.8))

    plt.tight_layout()
    if output_path is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = str(_RESULTS / f'comparison_time_{ts}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'图表: {output_path}')
    return output_path


def plot_confusion(report: dict, output_path: str = None):
    """绘制混淆矩阵热力图."""
    if not _HAS_MPL:
        return

    n_tools = len(report['tools'])
    if n_tools == 0:
        return

    fig, axes = plt.subplots(1, n_tools, figsize=(4 * n_tools, 4))
    if n_tools == 1:
        axes = [axes]

    for ax, tool in zip(axes, report['tools']):
        tp = tool.get('tp', 0)
        tn = tool.get('tn', 0)
        fp = tool.get('fp', 0)
        fn = tool.get('fn', 0)

        matrix = [[tp, fp], [fn, tn]]
        im = ax.imshow(matrix, cmap='RdYlGn', vmin=0,
                       vmax=max(1, tp + tn + fp + fn))

        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Pred\nPositive', 'Pred\nNegative'], fontsize=8)
        ax.set_yticklabels(['Actual\nPositive', 'Actual\nNegative'], fontsize=8)

        labels = [['TP', 'FP'], ['FN', 'TN']]
        for i in range(2):
            for j in range(2):
                val = matrix[i][j]
                ax.text(j, i, f'{labels[i][j]}\n{val}',
                       ha='center', va='center', fontsize=9, fontweight='bold')

        ax.set_title(tool['tool'], fontsize=10, fontweight='bold')

    plt.suptitle('Confusion Matrices — Multi-Tool Comparison',
                fontsize=13, fontweight='bold')
    plt.tight_layout()

    if output_path is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = str(_RESULTS / f'confusion_matrices_{ts}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'图表: {output_path}')
    return output_path


def main():
    parser = argparse.ArgumentParser(description='多工具对比可视化')
    parser.add_argument('json_path', nargs='?', default=None,
                       help='基准报告 JSON 路径')
    parser.add_argument('--no-plot', action='store_true',
                       help='跳过图表, 仅生成 LaTeX')
    parser.add_argument('--output-dir', type=str, default=None,
                       help='输出目录')
    parser.add_argument('--type', type=str, default='heap_overflow',
                       choices=['heap_overflow', 'uaf', 'format_string',
                                'integer_overflow', 'all'],
                       help='漏洞类型 (默认 heap_overflow, all=四类型对比)')
    args = parser.parse_args()

    if not _HAS_MPL:
        print('[!] matplotlib 未安装 — 跳过图表')
        print('    pip install matplotlib')

    if args.type == 'all':
        if _HAS_MPL and not args.no_plot:
            plot_multi_type(args.output_dir)
        generate_latex({'tools': []}, args.output_dir)
        print('\n多类型对比可视化完成.')
        return

    report = load_report(args.json_path, args.type)

    if not args.no_plot and _HAS_MPL:
        plot_metrics(report)
        plot_time(report)
        plot_confusion(report)

    generate_latex(report)
    print('\n可视化完成.')


if __name__ == '__main__':
    main()
