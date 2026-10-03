"""分配契约流保持 对比图生成 — 检出率/误报率柱状图 (normal/stripped 分组).

  - 指标: 检出率 = TP/(TP+FN), 误报率 = FP/(FP+TN).
  - 两个子图: normal 组 (带符号) 与 stripped 组 (去符号).
  - 输出 eval/alloc_contract_results/comparison_alloc_contract.png 与 SVG.
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path(__file__).resolve().parent / 'alloc_contract_results'
TOOLS = ('alloc_contract', 'Angr', 'QEMU', 'Ghidra')
COLORS = {'alloc_contract': '#2a9d8f', 'Angr': '#e9c46a', 'QEMU': '#457b9d',
          'Ghidra': '#e76f51'}


def load_summary(path: Path) -> dict:
    data = json.loads(path.read_text(encoding='utf-8'))
    return data['summary']


def metrics(m: dict) -> tuple:
    recall = m['recall']
    fpr = m['fp'] / max(1, m['fp'] + m['tn'])
    return recall, fpr


def plot_group(ax, summaries: dict, title: str):
    x = np.arange(len(TOOLS))
    width = 0.35
    recall = [metrics(summaries[t])[0] for t in TOOLS]
    fpr = [metrics(summaries[t])[1] for t in TOOLS]
    b1 = ax.bar(x - width / 2, recall, width, label='检出率 (Recall)',
                color=[COLORS[t] for t in TOOLS], alpha=0.9)
    b2 = ax.bar(x + width / 2, fpr, width, label='误报率 (FPR)',
                color=[COLORS[t] for t in TOOLS], alpha=0.45,
                hatch='//')
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01,
                    f'{h * 100:.0f}%', ha='center', va='bottom',
                    fontsize=8)
    ax.set_title(title, fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(TOOLS, fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', alpha=0.3)


def main():
    normal = load_summary(OUT / 'benchmark_alloc_contract.json')
    stripped = load_summary(OUT / 'benchmark_stripped.json')
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    plot_group(axes[0], normal, 'With symbols (normal, -O0)')
    plot_group(axes[1], stripped, 'Stripped (no symbols, -O1)')
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', ncol=2, fontsize=9)
    fig.suptitle('Heap overflow detection: recall vs FPR (20 samples, '
                 '15 TP + 5 TN)', fontsize=12)
    fig.tight_layout(rect=(0, 0.06, 1, 0.95))
    fig.savefig(OUT / 'comparison_alloc_contract.png', dpi=150)
    fig.savefig(OUT / 'comparison_alloc_contract.svg')
    print('saved:', OUT / 'comparison_alloc_contract.png')

    print(f'{"Tool":10s} {"N-Rec":>8s} {"N-FPR":>8s} {"S-Rec":>8s} {"S-FPR":>8s}')
    for t in TOOLS:
        nr, nf = metrics(normal[t])
        sr, sf = metrics(stripped[t])
        print(f'{t:10s} {nr*100:7.1f}% {nf*100:7.1f}% '
              f'{sr*100:7.1f}% {sf*100:7.1f}%')


if __name__ == '__main__':
    main()
