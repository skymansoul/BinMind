# 消融对比绘图 — 基线 vs WIDV 的召回/误报/精度对比
"""从tests/scan_results/ablation_heap.json绘制消融对比图。
输出: eval/ablation_comparison.png

用法: python eval/plot_ablation.py
"""

import os, json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ABL_PATH = os.path.join(EVAL_DIR, '..', 'tests', 'scan_results',
                        'ablation_heap.json')
OUT = os.path.join(EVAL_DIR, 'ablation_comparison.png')


def main():
    if not os.path.isfile(ABL_PATH):
        print(f"Missing {ABL_PATH}; run tests/run_ablation.py first")
        return 1
    with open(ABL_PATH, encoding='utf-8') as f:
        data = json.load(f)

    baseline = data['baseline']
    enhanced = data['enhanced']

    # 指标: 召回率, 内部过滤数(基线过度过滤/增强保留), 精度
    # fp_rate在两种变体下均为0%(安全样本零误报), 故以filtered_alerts
    # 展示"未知写大小→cannot_overflow"缺陷的消除效果
    metrics = ['recall_pct', 'filtered_alerts', 'precision_pct']
    labels = ['Recall (%)', 'Filtered Alerts', 'Precision (%)']
    b_vals = [baseline[m] for m in metrics]
    e_vals = [enhanced[m] for m in metrics]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(metrics))
    width = 0.3
    b1 = ax.bar(x - width/2, b_vals, width, label='Baseline (alloc-side only)',
                color='#95a5a6')
    b2 = ax.bar(x + width/2, e_vals, width, label='WIDV (bidirectional)',
                color='#2ecc71')
    ax.set_ylabel('Percentage (%)')
    ax.set_title('WIDV Ablation: Baseline vs Bidirectional Interval Verification')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    for bars in (b1, b2):
        for b in bars:
            ax.annotate(f'{b.get_height():.0f}', xy=(b.get_x() + b.get_width()/2,
                        b.get_height()), xytext=(0, 3),
                        textcoords='offset points', ha='center', fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT, dpi=150)
    plt.close(fig)
    print(f"Saved: {OUT}")
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
