# coding: utf-8
# 创建: 2026-04-25  |  SSBCP vs Angr 可视化图表生成
#
"""
从 ssbcp_vs_angr.json 生成对比图表。

输出:
  ssbcp_vs_angr_chart.png — Precision/Recall/F1/Time 四面板
  ssbcp_vs_angr_confusion.png — TP/FP/TN/FN 堆叠柱状图
  result_table.tex — LaTeX论文表格
"""
import json
import os
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


def load_results() -> dict:
    """加载对比基准结果"""
    json_path = EVAL_DIR / 'ssbcp_vs_angr.json'
    if not json_path.exists():
        print(f'Results not found: {json_path}')
        print('Run ssbcp_benchmark.py first.')
        sys.exit(1)
    with open(json_path, encoding='utf-8') as f:
        return json.load(f)


def plot_comparison(data: dict, output: str = None):
    """四面板: Precision/Recall/F1 + 时间对比"""
    if not HAS_MPL:
        print('matplotlib not available')
        return
    if output is None:
        output = str(EVAL_DIR / 'ssbcp_vs_angr_chart.png')

    metrics = data.get('metrics', {})
    tool_names = list(metrics.keys())
    short_names = [t.replace('BinMind-', 'BM-') for t in tool_names]

    x = np.arange(len(tool_names))
    width = 0.18

    prec = [metrics[t].get('precision', 0) for t in tool_names]
    rec = [metrics[t].get('recall', 0) for t in tool_names]
    f1 = [metrics[t].get('f1', 0) for t in tool_names]
    fpr = [metrics[t].get('fp_rate', 0) for t in tool_names]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # 子图1: P/R/F1/FPR 分组柱状图
    bars_p = ax1.bar(x - 1.5*width, prec, width,
                     color='#2196F3', alpha=0.85, label='Precision')
    bars_r = ax1.bar(x - 0.5*width, rec, width,
                     color='#4CAF50', alpha=0.85, label='Recall')
    bars_f = ax1.bar(x + 0.5*width, f1, width,
                     color='#FF9800', alpha=0.85, label='F1')
    bars_fp = ax1.bar(x + 1.5*width, fpr, width,
                      color='#F44336', alpha=0.85, label='FP Rate')
    ax1.set_xticks(x)
    ax1.set_xticklabels(short_names, fontsize=11)
    ax1.set_ylabel('Rate', fontsize=12)
    ax1.set_title('Detection Performance Comparison', fontsize=13)
    ax1.set_ylim(0, 1.15)
    ax1.legend(fontsize=9, loc='lower right')
    for bars, vals in [(bars_p, prec), (bars_r, rec),
                        (bars_f, f1), (bars_fp, fpr)]:
        for bar, val in zip(bars, vals):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                      f'{val:.1%}', ha='center', fontsize=7)

    # 子图2: 耗时对比(对数刻度)
    times = [metrics[t].get('avg_time_ms', 0) for t in tool_names]
    colors = ['#2196F3', '#FF5722']
    bars_t = ax2.bar(x, times, width*3, color=colors[:len(tool_names)],
                      alpha=0.85)
    ax2.set_xticks(x)
    ax2.set_xticklabels(short_names, fontsize=11)
    ax2.set_ylabel('Avg Time (ms)', fontsize=12)
    ax2.set_title('Analysis Latency (log scale)', fontsize=13)
    ax2.set_yscale('log')
    ax2.set_ylim(1, max(times) * 5)
    for bar, val in zip(bars_t, times):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.3,
                  f'{val:.0f}ms', ha='center', fontsize=9, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'Comparison chart saved: {output}')


def plot_confusion(data: dict, output: str = None):
    """TP/FP/TN/FN 堆叠柱状图"""
    if not HAS_MPL:
        return
    if output is None:
        output = str(EVAL_DIR / 'ssbcp_vs_angr_confusion.png')

    metrics = data.get('metrics', {})
    tool_names = list(metrics.keys())
    short_names = [t.replace('BinMind-', 'BM-') for t in tool_names]
    x = np.arange(len(tool_names))
    width = 0.5

    tp = [metrics[t].get('TP', 0) for t in tool_names]
    fp = [metrics[t].get('FP', 0) for t in tool_names]
    tn = [metrics[t].get('TN', 0) for t in tool_names]
    fn = [metrics[t].get('FN', 0) for t in tool_names]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x, tn, width, color='#BBDEFB', label='TN (correctly safe)')
    ax.bar(x, fn, width, bottom=tn, color='#FFCDD2', label='FN (missed)')
    ax.bar(x, fp, width, bottom=[a+b for a, b in zip(tn, fn)],
           color='#FF5252', label='FP (false alarm)')
    ax.bar(x, tp, width,
           bottom=[a+b+c for a, b, c in zip(tn, fn, fp)],
           color='#4CAF50', label='TP (correctly detected)')
    ax.set_xticks(x)
    ax.set_xticklabels(short_names, fontsize=11)
    ax.set_ylabel('Sample Count', fontsize=12)
    ax.set_title('Confusion Matrix: SSBCP vs Angr (18 samples)', fontsize=13)
    ax.legend(fontsize=9, loc='upper right')

    for i in range(len(tool_names)):
        if fp[i] > 0:
            ax.text(i, tn[i] + fn[i] + fp[i]/2, f'{fp[i]} FP',
                    ha='center', fontsize=10, fontweight='bold', color='white')

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'Confusion chart saved: {output}')


def generate_latex(data: dict, output: str = None):
    """生成LaTeX论文表格"""
    if output is None:
        output = str(EVAL_DIR / 'result_table.tex')

    metrics = data.get('metrics', {})
    n = data.get('n_samples', 18)

    lines = [
        r'% Auto-generated: SSBCP vs Angr comparison',
        r'% Generated: 2026-08-08',
        r'\begin{table}[htbp]',
        r'\centering',
        r'\caption{Heap Overflow Detection: BinMind-SSBCP vs Angr '
        r'on ' + str(n) + r' Samples}',
        r'\label{tab:ssbcp-vs-angr}',
        r'\begin{tabular}{lrrrrrr}',
        r'\toprule',
        r'\textbf{Tool} & \textbf{TP} & \textbf{FP} & \textbf{TN} '
        r'& \textbf{FN} & \textbf{F1} & \textbf{Time(ms)} \\',
        r'\midrule',
    ]

    for tool_name, m in metrics.items():
        lines.append(
            f'{tool_name} & {m["TP"]} & {m["FP"]} & {m["TN"]} & '
            f'{m["FN"]} & {m["f1"]:.3f} & {m["avg_time_ms"]:.0f} \\\\')

    lines.extend([
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
        '',
        r'% Precision/Recall detail',
        r'\begin{table}[htbp]',
        r'\centering',
        r'\caption{Precision and Recall Comparison}',
        r'\label{tab:prec-recall}',
        r'\begin{tabular}{lrrrr}',
        r'\toprule',
        r'\textbf{Tool} & \textbf{Precision} & \textbf{Recall} '
        r'& \textbf{FP Rate} & \textbf{Speedup} \\',
        r'\midrule',
    ])

    # speedup: 最慢工具为1x, 其他相对加速
    max_time = max(m['avg_time_ms'] for m in metrics.values())
    for tool_name, m in metrics.items():
        speedup = max_time / max(m['avg_time_ms'], 0.001)
        lines.append(
            f'{tool_name} & {m["precision"]:.1%} & {m["recall"]:.1%} & '
            f'{m["fp_rate"]:.1%} & {speedup:.1f}x \\\\')

    lines.extend([
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
    ])

    with open(output, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'LaTeX table saved: {output}')


def main():
    data = load_results()
    print(f'Loaded {data.get("n_samples", 0)} samples')
    for tool, m in data.get('metrics', {}).items():
        print(f'  {tool}: P={m["precision"]:.1%} R={m["recall"]:.1%} '
              f'F1={m["f1"]:.3f} FP={m["FP"]} time={m["avg_time_ms"]:.0f}ms')

    plot_comparison(data)
    plot_confusion(data)
    generate_latex(data)
    print('\nAll visualizations generated.')


if __name__ == '__main__':
    main()
