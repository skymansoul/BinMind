"""UAF-OG 对比图生成 — 检出率/误报率柱状图.

  - 指标: 检出率 = TP/(TP+FN), 误报率 = FP/(FP+TN).
  - 输出 eval/og_results/comparison_og.png + SVG.
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path(__file__).resolve().parent / 'og_results'
TOOLS = ('BASE', 'UAF-OG', 'Angr')
COLORS = {'BASE': '#e76f51', 'UAF-OG': '#2a9d8f', 'Angr': '#e9c46a'}


def main():
    data = json.loads((OUT / 'benchmark_og.json').read_text(encoding='utf-8'))
    s = data['summary']
    x = np.arange(len(TOOLS))
    width = 0.35
    recall = [s[t]['recall'] for t in TOOLS]
    fpr = [s[t]['fp'] / max(1, s[t]['fp'] + s[t]['tn']) for t in TOOLS]

    fig, ax = plt.subplots(figsize=(9, 5))
    b1 = ax.bar(x - width / 2, recall, width, label='Recall',
                color=[COLORS[t] for t in TOOLS], alpha=0.9)
    b2 = ax.bar(x + width / 2, fpr, width, label='FPR',
                color=[COLORS[t] for t in TOOLS], alpha=0.45, hatch='//')
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01,
                    f'{h * 100:.0f}%', ha='center', va='bottom', fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(TOOLS)
    ax.set_ylim(0, 1.15)
    ax.set_title('UAF detection: recall vs FPR (20 samples, 15 TP + 5 TN)')
    ax.grid(axis='y', alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT / 'comparison_og.png', dpi=150)
    fig.savefig(OUT / 'comparison_og.svg')
    print('saved:', OUT / 'comparison_og.png')


if __name__ == '__main__':
    main()
