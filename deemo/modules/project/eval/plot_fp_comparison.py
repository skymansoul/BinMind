# FP-Reduction 对比实验可视化: 检出率/误报率分组柱状图
# 数据源: eval_output/fp_benchmark_results.csv (工具 × 样本 × 分组)
# 分组: plain (未加壳/-O0) 与 packed (加壳代理/-O2 release)
# 输出: eval_output/fp_comparison.png (+ SVG), ASCII 汇总兜底
import csv
import json
import sys
import pathlib
from typing import Dict, List

_PROJ_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    _MPL = True
except ImportError:
    _MPL = False

_CSV = _PROJ_ROOT / "eval_output" / "fp_benchmark_results.csv"
_PNG = _PROJ_ROOT / "eval_output" / "fp_comparison.png"
_SVG = _PROJ_ROOT / "eval_output" / "fp_comparison.svg"

_GROUP_LABELS = {"plain": "plain (-O0, unstripped)", "packed": "release (-O2, packed proxy)"}


def load_results(path: pathlib.Path) -> List[Dict]:
    with open(path, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def metrics_for(results: List[Dict], tool: str,
                group: str) -> Dict[str, float]:
    rows = [r for r in results if r['tool'] == tool and r['group'] == group]
    tp = fp = tn = fn = 0
    for r in rows:
        if r['success'] != 'True':
            continue
        vuln = r['is_vulnerable'] == 'True'
        det = r['detected'] == 'True'
        if vuln and det:
            tp += 1
        elif vuln:
            fn += 1
        elif det:
            fp += 1
        else:
            tn += 1
    return {
        "recall": tp / max(tp + fn, 1),
        "fpr": fp / max(fp + tn, 1),
        "precision": tp / max(tp + fp, 1),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
    }


def ascii_table(by_tool_group: Dict[str, Dict[str, Dict]]):
    print("=" * 64)
    print("  分组指标 (Recall / FPR)")
    print("=" * 64)
    tools = ["our_method", "our_base", "naive", "regex", "angr"]
    print(f"{'工具':<12} {'未加壳R':>8} {'未加壳FPR':>10} "
          f"{'加壳R':>8} {'加壳FPR':>10}")
    for t in tools:
        row = []
        for g in ("plain", "packed"):
            m = by_tool_group.get(t, {}).get(g, {})
            row.append(m.get('recall', 0))
            row.append(m.get('fpr', 0))
        print(f"{t:<12} {row[0]:7.1%} {row[1]:9.1%} "
              f"{row[2]:7.1%} {row[3]:9.1%}")


def plot(results: List[Dict]):
    tools = ["our_method", "our_base", "naive", "regex", "angr"]
    groups = ["plain", "packed"]
    by_tool_group: Dict[str, Dict[str, Dict]] = {}
    for t in tools:
        by_tool_group[t] = {}
        for g in groups:
            by_tool_group[t][g] = metrics_for(results, t, g)

    ascii_table(by_tool_group)

    if not _MPL:
        print("matplotlib 不可用, 仅输出 ASCII 汇总")
        return

    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

    for gi, g in enumerate(groups):
        recalls = [by_tool_group[t][g]['recall'] for t in tools]
        fprs = [by_tool_group[t][g]['fpr'] for t in tools]
        precs = [by_tool_group[t][g]['precision'] for t in tools]

        ax = axes[0][gi]
        x = np.arange(len(tools))
        w = 0.35
        bars1 = ax.bar(x - w / 2, recalls, w, label='Recall',
                       color='#2ecc71')
        bars2 = ax.bar(x + w / 2, precs, w, label='Precision',
                       color='#3498db')
        ax.set_xticks(x)
        ax.set_xticklabels(tools, rotation=15)
        ax.set_ylim(0, 1.15)
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        ax.set_title(f'{_GROUP_LABELS[g]} — Recall / Precision')
        for b in list(bars1) + list(bars2):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02,
                    f'{b.get_height():.0%}', ha='center', fontsize=8)

        ax = axes[1][gi]
        colors = ['#2ecc71' if f < 0.1 else '#f39c12' if f < 0.5
                  else '#e74c3c' for f in fprs]
        bars = ax.bar(tools, fprs, color=colors, edgecolor='white')
        ax.set_title(f'{_GROUP_LABELS[g]} — False Positive Rate (lower is better)')
        ax.grid(axis='y', alpha=0.3)
        for i, b in enumerate(bars):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.01,
                    f'{fprs[i]:.0%}', ha='center', fontsize=9)

    plt.suptitle('Heap Overflow Static Detection — FP-Reduction '
                 'Multi-Tool Comparison (fp_samples)', fontsize=13)
    plt.tight_layout(rect=(0, 0, 1, 0.96))
    plt.savefig(_PNG, dpi=150, bbox_inches='tight')
    plt.savefig(_SVG, bbox_inches='tight')
    print(f"图表: {_PNG} / {_SVG}")


def main():
    if not _CSV.exists():
        print(f"缺少数据: {_CSV} (先运行 eval.fp_benchmark)")
        return 1
    plot(load_results(_CSV))
    return 0


if __name__ == '__main__':
    sys.exit(main())
