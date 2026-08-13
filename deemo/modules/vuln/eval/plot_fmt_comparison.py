"""Fmt-OG 对比图生成 — 检出率/误报率柱状图 (normal/stripped 双组)."""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path(__file__).resolve().parent / 'fmt_results'
TOOLS = ('BASE', 'Fmt-OG', 'Angr')
COLORS = {'BASE': '#e76f51', 'Fmt-OG': '#2a9d8f', 'Angr': '#e9c46a'}


def load_summary(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))['summary']


def metrics(m: dict):
    recall = m['recall']
    fpr = m['fp'] / max(1, m['fp'] + m['tn'])
    return recall, fpr


def plot_group(ax, s: dict, title: str):
    x = np.arange(len(TOOLS))
    width = 0.35
    recall = [metrics(s[t])[0] for t in TOOLS]
    fpr = [metrics(s[t])[1] for t in TOOLS]
    b1 = ax.bar(x - width / 2, recall, width, label='Recall',
                color=[COLORS[t] for t in TOOLS], alpha=0.9)
    b2 = ax.bar(x + width / 2, fpr, width, label='FPR',
                color=[COLORS[t] for t in TOOLS], alpha=0.45, hatch='//')
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01,
                    f'{h * 100:.0f}%', ha='center', va='bottom', fontsize=8)
    ax.set_title(title, fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(TOOLS, fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', alpha=0.3)


def main():
    normal = load_summary(OUT / 'benchmark_fmt.json')
    stripped = load_summary(OUT / 'benchmark_fmt_stripped.json')
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    plot_group(axes[0], normal, 'With symbols (normal, -O0)')
    plot_group(axes[1], stripped, 'Stripped (no symbols, -O1)')
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', ncol=2, fontsize=9)
    fig.suptitle('Format string detection: recall vs FPR '
                 '(20 samples, 15 TP + 5 TN)', fontsize=12)
    fig.tight_layout(rect=(0, 0.06, 1, 0.95))
    fig.savefig(OUT / 'comparison_fmt.png', dpi=150)
    fig.savefig(OUT / 'comparison_fmt.svg')
    print('saved:', OUT / 'comparison_fmt.png')


if __name__ == '__main__':
    main()
