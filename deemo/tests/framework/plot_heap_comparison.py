"""
堆溢出误报削减对比图 — 从 heap_eval_results.json 生成柱状图。
"""

import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_and_plot(results_path: str = None, output_path: str = None):
    if results_path is None:
        results_path = os.path.join(PROJECT_ROOT, "tests", "heap_eval_results.json")
    if output_path is None:
        output_path = os.path.join(PROJECT_ROOT, "tests", "heap_fpr_comparison.png")

    if not os.path.isfile(results_path):
        print(f"Run heap_eval.py first to generate {results_path}")
        return

    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    stats = data["statistics"]
    new_dr = stats["new_method"]["detection_rate"]
    new_fpr = stats["new_method"]["false_positive_rate"]
    old_fpr = stats["old_method"]["false_positive_rate"]

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    methods = ['Regex Baseline', 'AABC (This Work)']
    dr_values = [1.0, new_dr]
    fpr_values = [old_fpr, new_fpr]
    colors = ['#F44336', '#2196F3']

    ax1.bar(methods, dr_values, color=colors, edgecolor='black')
    ax1.set_ylabel('Detection Rate', fontsize=12)
    ax1.set_title('Heap Overflow Detection Rate', fontsize=14, fontweight='bold')
    for i, v in enumerate(dr_values):
        ax1.text(i, v + 0.02, f'{v:.1%}', ha='center', fontsize=13, fontweight='bold')

    ax2.bar(methods, fpr_values, color=colors, edgecolor='black')
    ax2.set_ylabel('False Positive Rate', fontsize=12)
    ax2.set_title('False Positive Rate (Lower = Better)', fontsize=14, fontweight='bold')
    for i, v in enumerate(fpr_values):
        ax2.text(i, v + 0.01, f'{v:.1%}', ha='center', fontsize=13, fontweight='bold')
    ax2.annotate(f'{((old_fpr-new_fpr)/max(old_fpr,0.01)):.0%} reduction',
                 xy=(1, new_fpr), xytext=(1.3, old_fpr/2),
                 arrowprops=dict(arrowstyle='->', color='green', lw=2),
                 fontsize=12, color='green', fontweight='bold')

    fig.suptitle('BinMind AABC: False Positive Reduction on Heap Overflow Detection',
                 fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Plot saved: {output_path}")


if __name__ == "__main__":
    load_and_plot(
        sys.argv[1] if len(sys.argv) > 1 else None,
        sys.argv[2] if len(sys.argv) > 2 else None,
    )
