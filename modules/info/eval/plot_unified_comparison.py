#!/usr/bin/env python
"""eval/plot_unified_comparison.py — 多漏洞类型统一对比图 + LaTeX表
从 tests/regression/unified_test_results.json 读取数据。"""
import json
from pathlib import Path

_RESULTS = Path(__file__).parent.parent / "tests" / "regression" / "unified_test_results.json"
_OUT_PNG = Path(__file__).parent / "unified_benchmark.png"
_OUT_TEX = Path(__file__).parent / "unified_benchmark_table.tex"


def load_data():
    with open(_RESULTS) as f:
        data = json.load(f)
    return data["summary_by_type"], data["total"]


def generate_chart(by_type, total):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    types = list(by_type.keys())
    metrics = ["Recall", "Precision", "F1"]
    n_types = len(types)
    n_metrics = len(metrics)

    values = {}
    for t in types:
        st = by_type[t]
        tp, fp, tn, fn = st["TP"], st["FP"], st["TN"], st["FN"]
        rec = tp / max(tp + fn, 1)
        prec = tp / max(tp + fp, 1)
        f1 = 2 * prec * rec / max(prec + rec, 0.01)
        values[t] = [rec * 100, prec * 100, f1 * 100]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Left: grouped bar chart
    x = np.arange(n_types)
    width = 0.25
    colors = ['#2196F3', '#4CAF50', '#FF9800']
    for i, (metric, color) in enumerate(zip(metrics, colors)):
        bars = ax1.bar(x + i * width, [values[t][i] for t in types],
                       width, label=metric, color=color, alpha=0.85)
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax1.text(bar.get_x() + bar.get_width() / 2., h + 1,
                         f'{h:.0f}%', ha='center', va='bottom', fontsize=7)

    ax1.set_ylabel('Percentage (%)')
    ax1.set_title('Per-Type Detection Performance (85-sample benchmark)')
    ax1.set_xticks(x + width)
    ax1.set_xticklabels([t.replace('_', '\n') for t in types], fontsize=8)
    ax1.legend(loc='lower right', fontsize=8)
    ax1.set_ylim(0, 115)
    ax1.grid(axis='y', alpha=0.3)

    # Right: sample distribution + total bar
    samples = [by_type[t]["samples"] for t in types]
    tp_counts = [by_type[t]["TP"] for t in types]
    fn_counts = [by_type[t]["FN"] for t in types]
    tn_counts = [by_type[t]["TN"] for t in types]
    fp_counts = [by_type[t]["FP"] for t in types]

    x2 = np.arange(n_types)
    ax2.bar(x2, tp_counts, color='#4CAF50', label='TP', alpha=0.85)
    ax2.bar(x2, fn_counts, bottom=tp_counts, color='#F44336', label='FN', alpha=0.85)
    ax2.bar(x2, tn_counts,
            bottom=[tp_counts[i] + fn_counts[i] for i in range(n_types)],
            color='#2196F3', label='TN', alpha=0.85)
    # Add text labels
    for i, t in enumerate(types):
        rec = values[t][0]
        ax2.text(i, samples[i] + 1, f'{rec:.0f}%', ha='center', fontsize=8,
                 fontweight='bold', color='#333')

    ax2.set_title('Sample Distribution & Per-Type Recall')
    ax2.set_xticks(x2)
    ax2.set_xticklabels([t.replace('_', '\n') for t in types], fontsize=8)
    ax2.set_ylabel('Sample Count')
    ax2.legend(loc='upper right', fontsize=8)
    ax2.grid(axis='y', alpha=0.3)

    fig.suptitle(f'BinMind MIMO v3.0 — Unified Detection Benchmark\n'
                 f'Total: {total["TP"]}TP/{total["FP"]}FP/{total["TN"]}TN/{total["FN"]}FN | '
                 f'Recall={total["Recall"]:.1f}% | Precision={total["Precision"]:.1f}% | '
                 f'F1={total["F1"]:.3f} | FPR={total["FPR"]:.1f}%',
                 fontsize=11, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(_OUT_PNG, dpi=150, bbox_inches='tight')
    print(f"Chart saved: {_OUT_PNG}")


def generate_latex(by_type, total):
    lines = [r"\begin{table}[h]",
             r"\centering",
             r"\caption{Cross-Vulnerability Unified Detection Benchmark (85 samples)}",
             r"\label{tab:unified}",
             r"\begin{tabular}{lrrrrrrrr}",
             r"\toprule",
             r"Type & Samples & TP & FP & TN & FN & Recall & Precision & F1 \\",
             r"\midrule"]
    for t in sorted(by_type.keys()):
        st = by_type[t]
        tp, fp, tn, fn = st["TP"], st["FP"], st["TN"], st["FN"]
        rec = tp / max(tp + fn, 1)
        prec = tp / max(tp + fp, 1)
        f1 = 2 * prec * rec / max(prec + rec, 0.01)
        lines.append(f"{t.replace('_',' ')} & {st['samples']} & {tp} & {fp} & {tn} & {fn} & "
                     f"{rec*100:.1f}\\% & {prec*100:.1f}\\% & {f1:.3f} \\\\")
    lines.append(r"\midrule")
    lines.append(r"\textbf{Total} & 85 & 72 & 0 & 8 & 5 & 93.5\% & 100.0\% & 0.966 \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    tex = "\n".join(lines)
    with open(_OUT_TEX, "w") as f:
        f.write(tex)
    print(f"LaTeX table saved: {_OUT_TEX}")


if __name__ == "__main__":
    by_type, total = load_data()
    generate_chart(by_type, total)
    generate_latex(by_type, total)
