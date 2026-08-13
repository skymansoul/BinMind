"""对比实验可视化 — 检出率/误报率柱状图 (含 plain/packed 分组)。

图1: 各工具检出率(Recall)与误报率(FPR)成对柱状图。
图2: 工具间 Precision/Recall/F1/FPR 四指标分组柱状图。
用法: python eval/plot_comparison.py [--class heap|uaf]
输出: eval/comparison_<class>_{plain,packed,metrics}.png。
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

EVAL = Path(__file__).resolve().parent
CLASS_TOOLS = {
    'heap': (['CACBV', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT'],
             ['CACBV\n(ours)', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT']),
    'uaf': (['LCV', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT'],
            ['LCV\n(ours)', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT']),
    'fmt': (['FSV', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT'],
            ['FSV\n(ours)', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT']),
}


def _get(metrics: dict, tool: str, group: str):
    m = metrics.get(f'{tool}@{group}')
    if m:
        return m
    return metrics.get(f'{tool}@plain') or metrics.get(tool) or {}


def plot_detection(metrics: dict, sample_class: str) -> None:
    for group, suffix in (('plain', 'plain'), ('packed', 'packed')):
        rec = [_get(metrics, t, group).get('recall', 0.0) * 100 for t in TOOLS]
        fpr = [_get(metrics, t, group).get('fpr', 0.0) * 100 for t in TOOLS]
        x = np.arange(len(TOOLS))
        w = 0.36
        fig, ax = plt.subplots(figsize=(8, 4.6))
        b1 = ax.bar(x - w / 2, rec, w, label='Detection rate (Recall)',
                    color='#2e7d32')
        b2 = ax.bar(x + w / 2, fpr, w, label='False positive rate (FPR)',
                    color='#c62828')
        for b in list(b1) + list(b2):
            ax.annotate(f'{b.get_height():.0f}', (b.get_x() + b.get_width() / 2,
                                                  b.get_height()),
                        ha='center', va='bottom', fontsize=8)
        ax.set_xticks(x)
        ax.set_xticklabels(TOOL_LABELS)
        ax.set_ylabel('Rate (%)')
        ax.set_ylim(0, 105)
        ax.set_title(f'{sample_class.upper()} memory safety: recall vs FPR '
                     f'({group} binaries)')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        fig.tight_layout()
        out = EVAL / f'comparison_{sample_class}_{group}.png'
        fig.savefig(out, dpi=130)
        plt.close(fig)
        print('[plot]', out)


def plot_metrics(metrics: dict, sample_class: str) -> None:
    group = 'plain'
    prec = [_get(metrics, t, group).get('precision', 0.0) * 100 for t in TOOLS]
    rec = [_get(metrics, t, group).get('recall', 0.0) * 100 for t in TOOLS]
    f1 = [_get(metrics, t, group).get('f1', 0.0) * 100 for t in TOOLS]
    fpr = [_get(metrics, t, group).get('fpr', 0.0) * 100 for t in TOOLS]
    x = np.arange(len(TOOLS))
    w = 0.19
    fig, ax = plt.subplots(figsize=(9, 4.8))
    series = [('Precision', prec, '#1565c0'), ('Recall', rec, '#2e7d32'),
              ('F1', f1, '#f9a825'), ('FPR', fpr, '#c62828')]
    for i, (label, vals, color) in enumerate(series):
        off = (i - 1.5) * w
        ax.bar(x + off, vals, w, label=label, color=color)
    ax.set_xticks(x)
    ax.set_xticklabels(TOOL_LABELS)
    ax.set_ylabel('Score (%)')
    ax.set_ylim(0, 105)
    ax.set_title(f'{sample_class.upper()} memory safety: precision / recall / F1 / FPR')
    ax.legend(ncol=4, loc='upper center', fontsize=8)
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    out = EVAL / f'comparison_{sample_class}_metrics.png'
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print('[plot]', out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    args = ap.parse_args()
    global TOOLS, TOOL_LABELS
    TOOLS, TOOL_LABELS = CLASS_TOOLS[args.sample_class]
    data = json.loads((EVAL / f'benchmark_summary_{args.sample_class}.json')
                      .read_text(encoding='utf-8'))
    metrics = data['tools']
    if not metrics:
        print('[plot] no metrics; run run_benchmark.py first')
        return
    plot_detection(metrics, args.sample_class)
    plot_metrics(metrics, args.sample_class)


if __name__ == '__main__':
    main()
