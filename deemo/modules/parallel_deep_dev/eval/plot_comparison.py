"""对比实验可视化 — 检出率/误报率柱状图 (含 plain/packed 分组)。

图1: 各工具检出率(Recall)与误报率(FPR)成对柱状图。
图2: 工具间 Precision/Recall/F1/FPR 四指标分组柱状图。
输出 eval/comparison_detection.png 与 eval/comparison_metrics.png。
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

EVAL = Path(__file__).resolve().parent
TOOLS = ['CACBV', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT']
TOOL_LABELS = ['CACBV\n(ours)', 'Baseline', 'Angr', 'Ghidra', 'QEMU-GT']


def _get(metrics: dict, tool: str, group: str):
    m = metrics.get(f'{tool}@{group}')
    if m:
        return m
    return metrics.get(f'{tool}@plain') or metrics.get(tool) or {}


def plot_detection(metrics: dict) -> None:
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
        ax.set_title(f'Heap overflow detection: recall vs FPR '
                     f'({group} binaries)')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        fig.tight_layout()
        out = EVAL / f'comparison_{group}.png'
        fig.savefig(out, dpi=130)
        plt.close(fig)
        print('[plot]', out)


def plot_metrics(metrics: dict) -> None:
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
    ax.set_title('Heap overflow detection: precision / recall / F1 / FPR')
    ax.legend(ncol=4, loc='upper center', fontsize=8)
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    out = EVAL / 'comparison_metrics.png'
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print('[plot]', out)


def main() -> None:
    data = json.loads((EVAL / 'benchmark_summary.json').read_text(
        encoding='utf-8'))
    metrics = data['tools']
    if not metrics:
        print('[plot] no metrics; run run_benchmark.py first')
        return
    plot_detection(metrics)
    plot_metrics(metrics)


if __name__ == '__main__':
    main()
