# 对比实验绘图 — 检出率/误报率柱状图(含加壳/未加壳分组)
"""从eval/benchmark_results.csv读取数据, 生成对比图表。

输出:
  eval/comparison_bar.png      — 召回率 vs 误报率 分组柱状图
  eval/benchmark_comparison.png — 精度-召回散点对比

用法: python eval/plot_comparison.py
"""

import os, csv, json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(EVAL_DIR, 'benchmark_results.csv')
SUMMARY_PATH = os.path.join(EVAL_DIR, 'benchmark_summary.json')
OUT_BAR = os.path.join(EVAL_DIR, 'comparison_bar.png')
OUT_SCATTER = os.path.join(EVAL_DIR, 'benchmark_comparison.png')


def load_summary() -> dict:
    """从summary json加载指标。"""
    if os.path.isfile(SUMMARY_PATH):
        with open(SUMMARY_PATH, encoding='utf-8') as f:
            return json.load(f)
    return {}


def main():
    summary = load_summary()
    tools = summary.get('tools', {})
    if not tools:
        print(f"No summary at {SUMMARY_PATH}; run run_benchmark.py first")
        return 1

    # 提取各工具plain变体指标
    names = sorted(tools.keys())
    recall = [tools[t]['plain']['recall_pct'] for t in names]
    fp_rate = [tools[t]['plain']['fp_rate_pct'] for t in names]
    precision = [tools[t]['plain']['precision_pct'] for t in names]

    # 图1: 召回率 vs 误报率 分组柱状图
    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(names))
    width = 0.35
    b1 = ax.bar(x - width/2, recall, width, label='Recall (%)',
                color='#2e86de')
    b2 = ax.bar(x + width/2, fp_rate, width, label='FP Rate (%)',
                color='#e74c3c')
    ax.set_ylabel('Percentage (%)')
    ax.set_title('Heap Overflow Detection: Recall vs FP Rate (plain)')
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20)
    ax.legend()
    for bars in (b1, b2):
        for b in bars:
            ax.annotate(f'{b.get_height():.0f}', xy=(b.get_x() + b.get_width()/2,
                        b.get_height()), xytext=(0, 3),
                        textcoords='offset points', ha='center', fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT_BAR, dpi=150)
    plt.close(fig)

    # 图2: 精度-召回 散点(含加壳分组)
    fig, ax = plt.subplots(figsize=(8, 6))
    variants = ('plain', 'packed')
    markers = {'plain': 'o', 'packed': '^'}
    colors = {'plain': '#2e86de', 'packed': '#e67e22'}
    for variant in variants:
        xs, ys = [], []
        for t in names:
            v = tools[t].get(variant)
            if not v:
                continue
            xs.append(v['recall_pct'])
            ys.append(v['precision_pct'])
            ax.annotate(t, (v['recall_pct'], v['precision_pct']),
                        fontsize=8, ha='left', va='bottom')
        ax.scatter(xs, ys, marker=markers[variant], s=90,
                   color=colors[variant], label=f'{variant}')
    ax.set_xlabel('Recall (%)')
    ax.set_ylabel('Precision (%)')
    ax.set_title('Precision-Recall by Tool (plain vs packed)')
    ax.set_xlim(-5, 110)
    ax.set_ylim(-5, 110)
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT_SCATTER, dpi=150)
    plt.close(fig)

    print(f"Saved: {OUT_BAR}")
    print(f"Saved: {OUT_SCATTER}")
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
