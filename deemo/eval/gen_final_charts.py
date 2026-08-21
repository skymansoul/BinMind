# 最终对比图表生成器 — 从统一CSV生成论文级图表.
# 依赖: matplotlib

import csv, os
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

EVAL = Path(__file__).resolve().parent
OUT = EVAL / 'final_deliverables'
CSV_PATH = OUT / 'unified_comparison.csv'

plt.rcParams.update({
    'font.size': 11, 'font.family': 'serif',
    'figure.dpi': 300, 'savefig.bbox': 'tight',
    'axes.grid': True, 'grid.alpha': 0.3,
})


def load_csv():
    rows = []
    with open(CSV_PATH, encoding='utf-8') as f:
        r = csv.DictReader(f)
        for row in r:
            row['precision'] = float(row['precision'])
            row['recall'] = float(row['recall'])
            row['f1'] = float(row['f1'])
            row['fp_rate'] = float(row['fp_rate'])
            row['avg_time_ms'] = float(row['avg_time_ms'])
            row['samples'] = int(row['samples'])
            rows.append(row)
    return rows


def chart_cross_type(rows):
    """123样本跨类型基准 — F1/速度气泡图."""
    data = [r for r in rows if r['benchmark'] == 'cross_type_123']
    tools = [r['tool'] for r in data]
    f1 = [r['f1'] for r in data]
    ms = [r['avg_time_ms'] for r in data]
    fpr = [r['fp_rate'] for r in data]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    colors = ['#2196F3', '#FF9800', '#4CAF50', '#F44336']
    for i, (t, f, m, fp) in enumerate(zip(tools, f1, ms, fpr)):
        size = max(100, (1 - fp) * 400)
        ax.scatter(m, f, s=size, c=colors[i % len(colors)], alpha=0.8,
                   edgecolors='black', linewidths=0.5, zorder=3)
        offset_x = 0.5 if m < max(ms) * 0.3 else -2
        ax.annotate(t.replace('-', '\n'), (m, f), fontsize=8,
                    ha='left' if offset_x > 0 else 'right',
                    textcoords='offset points', xytext=(offset_x * 5, 5))

    ax.set_xlabel('Avg Time per Sample (ms)')
    ax.set_ylabel('F1 Score')
    ax.set_title('Cross-Type Benchmark (123 samples, 5 vulnerability classes)')
    ax.set_xscale('log')
    ax.set_xlim(0.3, 100)
    ax.set_ylim(0.65, 1.05)
    ax.axhline(y=1.0, color='gray', linestyle='--', alpha=0.5)
    fig.savefig(OUT / 'fig_cross_type_bubble.png')
    plt.close(fig)
    print('  fig_cross_type_bubble.png')


def chart_cve_comparison(rows):
    """17 CVE GAPSBV-CJ基准 — 分组柱状图."""
    data = [r for r in rows if r['benchmark'] == 'gapsbv_cj_17']
    tools = [r['tool'] for r in data]
    prec = [r['precision'] for r in data]
    rec = [r['recall'] for r in data]
    f1 = [r['f1'] for r in data]

    x = np.arange(len(tools))
    w = 0.25
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - w, prec, w, label='Precision', color='#2196F3')
    ax.bar(x, rec, w, label='Recall', color='#4CAF50')
    ax.bar(x + w, f1, w, label='F1', color='#FF9800')

    ax.set_ylabel('Score')
    ax.set_title('GAPSBV-CJ 17 CVE Benchmark')
    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=15, fontsize=9)
    ax.legend(loc='lower left')
    ax.set_ylim(0, 1.15)
    for i in range(len(tools)):
        ax.text(i - w, prec[i] + 0.02, f'{prec[i]:.0%}', ha='center', fontsize=7)
        ax.text(i, rec[i] + 0.02, f'{rec[i]:.0%}', ha='center', fontsize=7)
        ax.text(i + w, f1[i] + 0.02, f'{f1[i]:.2f}', ha='center', fontsize=7)

    fig.savefig(OUT / 'fig_cj_cve_bar.png')
    plt.close(fig)
    print('  fig_cj_cve_bar.png')


def chart_speed_comparison(rows):
    """速度对比 — 对数尺度水平柱状图."""
    data = [r for r in rows if r['benchmark'] == 'gapsbv_cj_17']
    tools = [r['tool'] for r in data]
    ms = [r['avg_time_ms'] for r in data]

    fig, ax = plt.subplots(figsize=(7, 3))
    colors = ['#4CAF50', '#2196F3', '#FF9800', '#F44336']
    y = np.arange(len(tools))
    ax.barh(y, ms, color=colors, alpha=0.85, edgecolor='black', linewidth=0.5)
    ax.set_yticks(y)
    ax.set_yticklabels(tools, fontsize=9)
    ax.set_xlabel('Time per Sample (ms, log scale)')
    ax.set_xscale('log')
    ax.set_title('Detection Speed: BinMind vs Angr (17 CVE)')
    for i, v in enumerate(ms):
        ax.text(v * 1.15, i, f'{v:.1f}ms', va='center', fontsize=8)

    fig.savefig(OUT / 'fig_speed_comparison.png')
    plt.close(fig)
    print('  fig_speed_comparison.png')


if __name__ == '__main__':
    rows = load_csv()
    print('Generating charts...')
    chart_cross_type(rows)
    chart_cve_comparison(rows)
    chart_speed_comparison(rows)
    print(f'Charts saved to: {OUT}')
