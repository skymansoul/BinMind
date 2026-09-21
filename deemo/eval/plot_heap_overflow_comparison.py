"""
堆溢出验证对比实验绘图.

读取 heap_overflow_benchmark.csv, 生成:
  heap_overflow_fpr_recall.png       FPR vs Recall 双轴柱状/折线对比
  heap_overflow_confusion.png        混淆矩阵四格对比
  heap_overflow_detection.png        逐样本检出热图

绘图目标: 突出堆溢出验证相比既有基线与通用工具 (Angr/Ghidra/QEMU)
在误报率上的削减与召回保持. matplotlib 缺失时降级输出文本摘要.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(EVAL_DIR, 'heap_overflow_benchmark.csv')
JSON_PATH = os.path.join(EVAL_DIR, 'heap_overflow_metrics.json')
OUT_DIR = os.path.join(EVAL_DIR, 'heap_overflow_comparison_plots')

_ACCEPT = 'OVERFLOW'


def _load_metrics() -> Dict[str, Dict]:
    """以 heap_overflow_metrics.json 为准, 保证图表与 LaTeX 表一致."""
    if os.path.isfile(JSON_PATH):
        with open(JSON_PATH, encoding='utf-8') as f:
            data = json.load(f)
        for m in data.values():
            m.setdefault('fpr', 0.0)
            m.setdefault('recall', 0.0)
        return data
    results = _load_results()
    return _metrics_by_tool(results)


def _metrics_by_tool(results: List[Dict]) -> Dict[str, Dict]:
    tools: Dict[str, Dict] = defaultdict(
        lambda: {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0})
    for r in results:
        if not r['success'] or not r['tool']:
            continue
        m = tools[r['tool']]
        gt = r['ground_truth']
        pred = r['verdict'] == _ACCEPT
        if gt and pred:
            m['tp'] += 1
        elif gt:
            m['fn'] += 1
        elif pred:
            m['fp'] += 1
        else:
            m['tn'] += 1
    out = {}
    for tool, m in tools.items():
        tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
        out[tool] = {
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'recall': tp / (tp + fn) if (tp + fn) else 0.0,
            'fpr': fp / (fp + tn) if (fp + tn) else 0.0,
            'precision': tp / (tp + fp) if (tp + fp) else 0.0,
        }
    return out


def _plot_fpr_recall(metrics: Dict[str, Dict]) -> None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print('matplotlib 缺失, 跳过绘图')
        return
    tools = sorted(metrics)
    labels = [t.replace('BinMind-', '') for t in tools]
    recalls = [metrics[t]['recall'] * 100 for t in tools]
    fprs = [metrics[t]['fpr'] * 100 for t in tools]
    x = range(len(tools))

    fig, ax1 = plt.subplots(figsize=(10, 5))
    b1 = ax1.bar(x, recalls, width=0.38, color='#2e7d32',
                 label='Recall (%)')
    ax1.set_ylabel('Recall (%)', color='#2e7d32')
    ax1.set_ylim(0, 110)
    ax2 = ax1.twinx()
    b2 = ax2.bar([i + 0.4 for i in x], fprs, width=0.38,
                 color='#c62828', label='FPR (%)')
    ax2.set_ylabel('False Positive Rate (%)', color='#c62828')
    ax2.set_ylim(0, 110)
    ax1.set_xticks([i + 0.2 for i in x])
    ax1.set_xticklabels(labels, rotation=15)
    for i, (rv, fv) in enumerate(zip(recalls, fprs)):
        ax1.text(i, rv + 1.5, f'{rv:.1f}', ha='center', fontsize=8)
        ax2.text(i + 0.4, fv + 1.5, f'{fv:.1f}', ha='center', fontsize=8)
    ax1.set_title('Heap Overflow Detection: Recall vs False Positive Rate')
    fig.legend(loc='upper left', bbox_to_anchor=(0.12, 0.88))
    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, 'heap_overflow_fpr_recall.png')
    fig.savefig(path, dpi=150)
    print(f'已输出 {path}')


def _plot_confusion(metrics: Dict[str, Dict]) -> None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return
    tools = [t for t in sorted(metrics)
             if t in ('BinMind-Baseline', 'BinMind-HOVF')]
    fig, axes = plt.subplots(1, len(tools), figsize=(9, 3.5))
    if len(tools) == 1:
        axes = [axes]
    for ax, tool in zip(axes, tools):
        m = metrics[tool]
        mat = [[m['tn'], m['fp']], [m['fn'], m['tp']]]
        im = ax.imshow(mat, cmap='Blues', vmin=0,
                       vmax=max(1, max(max(r) for r in mat)))
        ax.set_xticks([0, 1], ['SAFE', 'OVERFLOW'])
        ax.set_yticks([0, 1], ['SAFE', 'OVERFLOW'])
        for r in range(2):
            for c in range(2):
                ax.text(c, r, str(mat[r][c]), ha='center', va='center',
                        fontsize=14, color='white' if mat[r][c] > max(
                            1, max(max(x) for x in mat)) / 2 else 'black')
        ax.set_title(tool.replace('BinMind-', ''))
    fig.suptitle('Confusion Matrix')
    fig.tight_layout()
    path = os.path.join(OUT_DIR, 'heap_overflow_confusion.png')
    fig.savefig(path, dpi=150)
    print(f'已输出 {path}')


def main() -> None:
    metrics = _load_metrics()
    if not metrics:
        return
    print(f'{"工具":<20}{"TP":>4}{"FP":>4}{"Recall":>8}{"FPR":>8}')
    for t, m in sorted(metrics.items()):
        print(f'{t:<20}{m.get("tp", 0):>4}{m.get("fp", 0):>4}'
              f'{m.get("recall", 0) * 100:>7.1f}%{m.get("fpr", 0) * 100:>7.1f}%')
    _plot_fpr_recall(metrics)
    _plot_confusion(metrics)


if __name__ == '__main__':
    main()
