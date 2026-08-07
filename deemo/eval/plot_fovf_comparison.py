"""
FOVF 对比实验绘图 (格式化字符串).

读取 fovf_metrics.json, 生成 FPR-Recall 对比与混淆矩阵.
"""

from __future__ import annotations

import json
import os
from typing import Dict

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(EVAL_DIR, 'fovf_metrics.json')
OUT_DIR = os.path.join(EVAL_DIR, 'fovf_comparison_plots')


def _load() -> Dict[str, Dict]:
    if not os.path.isfile(JSON_PATH):
        print('缺 fovf_metrics.json')
        return {}
    with open(JSON_PATH, encoding='utf-8') as f:
        data = json.load(f)
    for m in data.values():
        m.setdefault('fpr', 0.0)
        m.setdefault('recall', 0.0)
    return data


def _plot_fpr_recall(metrics: Dict[str, Dict]) -> None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print('matplotlib 缺失, 跳过')
        return
    tools = sorted(metrics)
    labels = [t.replace('FMT-', '') for t in tools]
    recalls = [metrics[t]['recall'] * 100 for t in tools]
    fprs = [metrics[t]['fpr'] * 100 for t in tools]
    x = range(len(tools))
    fig, ax1 = plt.subplots(figsize=(10, 5))
    ax1.bar(x, recalls, width=0.38, color='#2e7d32', label='Recall (%)')
    ax1.set_ylabel('Recall (%)', color='#2e7d32')
    ax1.set_ylim(0, 110)
    ax2 = ax1.twinx()
    ax2.bar([i + 0.4 for i in x], fprs, width=0.38, color='#c62828',
            label='FPR (%)')
    ax2.set_ylabel('False Positive Rate (%)', color='#c62828')
    ax2.set_ylim(0, 110)
    ax1.set_xticks([i + 0.2 for i in x])
    ax1.set_xticklabels(labels, rotation=15)
    for i, (rv, fv) in enumerate(zip(recalls, fprs)):
        ax1.text(i, rv + 1.5, f'{rv:.1f}', ha='center', fontsize=8)
        ax2.text(i + 0.4, fv + 1.5, f'{fv:.1f}', ha='center', fontsize=8)
    ax1.set_title('Format-String Detection: Recall vs False Positive Rate')
    fig.legend(loc='upper left', bbox_to_anchor=(0.12, 0.88))
    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, 'fovf_fpr_recall.png')
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
             if t in ('FMT-Existing', 'FOVF')]
    fig, axes = plt.subplots(1, len(tools), figsize=(9, 3.5))
    if len(tools) == 1:
        axes = [axes]
    for ax, tool in zip(axes, tools):
        m = metrics[tool]
        mat = [[m['tn'], m['fp']], [m['fn'], m['tp']]]
        vmax = max(1, max(max(r) for r in mat))
        ax.imshow(mat, cmap='Blues', vmin=0, vmax=vmax)
        ax.set_xticks([0, 1], ['SAFE', 'OVERFLOW'])
        ax.set_yticks([0, 1], ['SAFE', 'OVERFLOW'])
        for r in range(2):
            for c in range(2):
                ax.text(c, r, str(mat[r][c]), ha='center', va='center',
                        fontsize=14,
                        color='white' if mat[r][c] > vmax / 2 else 'black')
        ax.set_title(tool.replace('FMT-', ''))
    fig.suptitle('Format-String Confusion Matrix')
    fig.tight_layout()
    path = os.path.join(OUT_DIR, 'fovf_confusion.png')
    fig.savefig(path, dpi=150)
    print(f'已输出 {path}')


def main() -> None:
    metrics = _load()
    if not metrics:
        return
    print(f'{"工具":<16}{"TP":>4}{"FP":>4}{"Recall":>8}{"FPR":>8}')
    for t, m in sorted(metrics.items()):
        print(f'{t:<16}{m.get("tp", 0):>4}{m.get("fp", 0):>4}'
              f'{m.get("recall", 0) * 100:>7.1f}%{m.get("fpr", 0) * 100:>7.1f}%')
    _plot_fpr_recall(metrics)
    _plot_confusion(metrics)


if __name__ == '__main__':
    main()
