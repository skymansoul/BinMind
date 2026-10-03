#!/usr/bin/env python3
"""
生成发表级可视化图表和LaTeX表格 — 堆溢出检测多工具对比.

读取 unified_tool_comparison.json, 生成:
  1. P/R/F1/FPR 四指标柱状图 (publication_grade_metrics.png)
  2. Precision-Recall散点图 (publication_pr_scatter.png)
  3. FP reduction瀑布图 (fp_reduction_waterfall.png)
  4. LaTeX表格 (result_table.tex)
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

_BASE = Path(__file__).parent.parent
RESULTS_DIR = _BASE / "eval" / "results"
INPUT_JSON = RESULTS_DIR / "unified_tool_comparison.json"

TOOL_ORDER = [
    "BinMind-baseline", "BinMind-HOSV", "BinMind-GAPSBV-CJ",
    "Angr", "Ghidra", "QEMU",
]
TOOL_LABELS = {
    "BinMind-baseline": "BinMind\n(baseline)",
    "BinMind-HOSV": "BinMind\nHOSV",
    "BinMind-GAPSBV-CJ": "BinMind\nGAPSBV-CJ",
    "Angr": "Angr\n(symbex)",
    "Ghidra": "Ghidra\n(static)",
    "QEMU": "QEMU\n(dynamic)",
}
TOOL_COLORS = {
    "BinMind-baseline": "#95a5a6",
    "BinMind-HOSV": "#3498db",
    "BinMind-GAPSBV-CJ": "#2ecc71",
    "Angr": "#e74c3c",
    "Ghidra": "#9b59b6",
    "QEMU": "#f39c12",
}


def load_data() -> dict:
    with open(INPUT_JSON, encoding='utf-8') as f:
        return json.load(f)


def plot_metrics_bars(summary: dict, out_dir: str):
    """四指标分组柱状图."""
    tools = [t for t in TOOL_ORDER if t in summary]
    metrics = ['precision', 'recall', 'f1', 'fp_rate']
    labels = ['Precision', 'Recall', 'F1', 'FP Rate']
    x = np.arange(len(metrics))
    width = 0.12
    fig, ax = plt.subplots(figsize=(14, 7))
    for i, tool in enumerate(tools):
        vals = [summary[tool][m] for m in metrics]
        bars = ax.bar(x + i * width, vals, width,
                      label=tool.replace('BinMind-', ''),
                      color=TOOL_COLORS[tool], edgecolor='white', linewidth=0.8)
        for bar, v in zip(bars, vals):
            if v > 0.01:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        f'{v:.2f}', ha='center', va='bottom', fontsize=7,
                        fontweight='bold')
    ax.set_xticks(x + width * (len(tools) - 1) / 2)
    ax.set_xticklabels(labels, fontsize=12, fontweight='bold')
    ax.set_ylabel('Score', fontsize=13, fontweight='bold')
    ax.set_title('Heap Overflow Detection: Multi-Tool Comparison (17 CVE samples)',
                 fontsize=14, fontweight='bold')
    ax.set_ylim(0, 1.15)
    ax.axhline(y=0.2, color='green', linestyle='--', alpha=0.4, linewidth=1)
    ax.legend(loc='upper right', fontsize=9, ncol=2)
    ax.grid(axis='y', alpha=0.3)
    path = os.path.join(out_dir, 'publication_grade_metrics.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


def plot_pr_scatter(summary: dict, out_dir: str):
    """Precision-Recall 散点图."""
    fig, ax = plt.subplots(figsize=(9, 8))
    for tool in TOOL_ORDER:
        if tool not in summary:
            continue
        m = summary[tool]
        ax.scatter(m['recall'], m['precision'],
                   c=TOOL_COLORS[tool], s=300, edgecolors='white',
                   linewidth=2, zorder=5)
        label = TOOL_LABELS[tool].replace('\n', ' ')
        ax.annotate(label, (m['recall'], m['precision']),
                    textcoords='offset points', xytext=(12, 8),
                    fontsize=9, fontweight='bold',
                    arrowprops=dict(arrowstyle='-', alpha=0.3))
    ax.set_xlabel('Recall', fontsize=13, fontweight='bold')
    ax.set_ylabel('Precision', fontsize=13, fontweight='bold')
    ax.set_title('Precision vs Recall: Heap Overflow Detection',
                 fontsize=14, fontweight='bold')
    ax.set_xlim(-0.05, 1.1)
    ax.set_ylim(-0.05, 1.1)
    ax.grid(True, alpha=0.3)
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.2, linewidth=1)
    path = os.path.join(out_dir, 'publication_pr_scatter.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


def plot_fp_reduction(summary: dict, out_dir: str):
    """FP reduction 瀑布图: baseline → 堆写模式验证 → 仿射边界验证-约束求解."""
    stages = ['BinMind\nbaseline', 'BinMind\nHOSV', 'BinMind\nGAPSBV-CJ']
    keys = ['BinMind-baseline', 'BinMind-HOSV', 'BinMind-GAPSBV-CJ']
    fp_rates = [summary[k]['fp_rate'] for k in keys if k in summary]
    precisions = [summary[k]['precision'] for k in keys if k in summary]
    f1s = [summary[k]['f1'] for k in keys if k in summary]

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    colors = ['#95a5a6', '#3498db', '#2ecc71']
    x = np.arange(len(stages))

    for ax_idx, (name, vals) in enumerate(
            [('FP Rate (lower=better)', fp_rates),
             ('Precision (higher=better)', precisions),
             ('F1 Score (higher=better)', f1s)]):
        ax = axes[ax_idx]
        bars = ax.bar(x, vals, color=colors, edgecolor='white', linewidth=1.5, width=0.55)
        for i, v in enumerate(vals):
            ax.text(i, v + 0.02, f'{v:.4f}', ha='center',
                    fontweight='bold', fontsize=11)
        ax.set_xticks(x)
        ax.set_xticklabels(stages, fontsize=10)
        ax.set_ylabel(name, fontweight='bold', fontsize=11)
        ax.set_ylim(0, 1.1)
        ax.grid(axis='y', alpha=0.3)

        if ax_idx == 0 and len(vals) >= 2:
            reduction = (1 - vals[2] / max(vals[0], 0.001)) * 100
            ax.annotate(f'-{reduction:.0f}%', xy=(2, vals[2]),
                        xytext=(2, vals[0] * 0.5),
                        ha='center', fontsize=14, fontweight='bold',
                        color='green',
                        arrowprops=dict(arrowstyle='->', color='green', lw=2))

    fig.suptitle('Ablation: FP Reduction Across Detection Layers',
                 fontsize=14, fontweight='bold')
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    path = os.path.join(out_dir, 'fp_reduction_waterfall.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


def generate_latex(summary: dict, out_dir: str):
    """生成LaTeX表格."""
    tools = [t for t in TOOL_ORDER if t in summary]
    lines = []
    lines.append(r'\begin{table}[htbp]')
    lines.append(r'  \centering')
    lines.append(r'  \caption{Heap Overflow Detection: Multi-Tool Comparison (17 CVE Samples)}')
    lines.append(r'  \label{tab:heap_overflow_comparison}')
    lines.append(r'  \begin{tabular}{lrrrrrrr}')
    lines.append(r'    \toprule')
    lines.append(r'    Tool & P & R & F1 & FPR & TP & FP & Time(ms) \\')
    lines.append(r'    \midrule')
    for tool in tools:
        m = summary[tool]
        name = tool.replace('_', r'\_')
        lines.append(
            f'    {name} & {m["precision"]:.4f} & {m["recall"]:.4f} & '
            f'{m["f1"]:.4f} & {m["fp_rate"]:.4f} & {m["tp"]} & {m["fp"]} & '
            f'{m["avg_time_ms"]:.1f} \\\\')
    lines.append(r'    \bottomrule')
    lines.append(r'  \end{tabular}')
    lines.append(r'\end{table}')

    path = os.path.join(out_dir, 'result_table.tex')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'  Saved: {path}')

    # 消融表
    ablation_tools = ['BinMind-baseline', 'BinMind-HOSV', 'BinMind-GAPSBV-CJ']
    lines2 = []
    lines2.append(r'\begin{table}[htbp]')
    lines2.append(r'  \centering')
    lines2.append(r'  \caption{Ablation Study: Layered FP Reduction}')
    lines2.append(r'  \label{tab:ablation_fp_reduction}')
    lines2.append(r'  \begin{tabular}{lrrrr}')
    lines2.append(r'    \toprule')
    lines2.append(r'    Configuration & Precision & Recall & F1 & FPR \\')
    lines2.append(r'    \midrule')
    labels_ab = {
        'BinMind-baseline': r'Baseline (pattern only)',
        'BinMind-HOSV': r'+ HOSV (constraint graph)',
        'BinMind-GAPSBV-CJ': r'+ GAPSBV-CJ (constraint join)',
    }
    for tool in ablation_tools:
        if tool not in summary:
            continue
        m = summary[tool]
        lines2.append(
            f'    {labels_ab[tool]} & {m["precision"]:.4f} & {m["recall"]:.4f} & '
            f'{m["f1"]:.4f} & {m["fp_rate"]:.4f} \\\\')
    lines2.append(r'    \bottomrule')
    lines2.append(r'  \end{tabular}')
    lines2.append(r'\end{table}')

    path2 = os.path.join(out_dir, 'ablation_table.tex')
    with open(path2, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines2))
    print(f'  Saved: {path2}')


def main():
    data = load_data()
    summary = data['summary']
    out_dir = str(RESULTS_DIR)
    print('Generating publication-grade figures and tables...')
    plot_metrics_bars(summary, out_dir)
    plot_pr_scatter(summary, out_dir)
    plot_fp_reduction(summary, out_dir)
    generate_latex(summary, out_dir)
    print('Done.')


if __name__ == '__main__':
    main()
