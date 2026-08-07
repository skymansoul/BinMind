# coding: utf-8
"""
对比结果绘图 — 检出率/误报率柱状图 + F1 对比.

输入: eval/hosv_benchmark_results.json
输出: eval/hosv_comparison.png (precision/recall/F1 分组柱状图)
      eval/hosv_fpr_comparison.png (误报率对比)
"""

import json
import os

BASE = os.path.dirname(os.path.abspath(__file__))

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    MPL_OK = True
except ImportError:
    MPL_OK = False


def _load():
    p = os.path.join(BASE, "hosv_benchmark_results.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def plot_main(data):
    cross = data["cross"]
    tools = [c["tool"] for c in cross]
    precision = [c["precision"] for c in cross]
    recall = [c["recall"] for c in cross]
    f1 = [c["f1"] for c in cross]

    x = np.arange(len(tools))
    width = 0.26
    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.bar(x - width, precision, width, label="Precision", color="#4C72B0")
    ax.bar(x, recall, width, label="Recall", color="#55A868")
    ax.bar(x + width, f1, width, label="F1", color="#C44E52")
    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=12, ha="right")
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score")
    ax.set_title("Heap Overflow Detection Comparison (18 samples)")
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)
    for i, (p, r, f) in enumerate(zip(precision, recall, f1)):
        ax.text(x[i] - width, p + 0.02, "%.2f" % p, ha="center", fontsize=9)
        ax.text(x[i], r + 0.02, "%.2f" % r, ha="center", fontsize=9)
        ax.text(x[i] + width, f + 0.02, "%.2f" % f, ha="center", fontsize=9)
    fig.tight_layout()
    out = os.path.join(BASE, "hosv_comparison.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print("saved:", out)


def plot_fpr(data):
    cross = data["cross"]
    tools = [c["tool"] for c in cross]
    fpr = []
    for c in cross:
        fp, tn = c["fp"], c["tn"]
        fpr.append(fp / (fp + tn) if fp + tn else 0.0)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    colors = ["#C44E52" if f > 0 else "#55A868" for f in fpr]
    ax.bar(tools, fpr, color=colors)
    ax.set_ylabel("False Positive Rate")
    ax.set_title("False Positive Rate (0 = no FP)")
    ax.set_ylim(0, 1.05)
    for i, f in enumerate(fpr):
        ax.text(i, f + 0.02, "%.2f" % f, ha="center")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    out = os.path.join(BASE, "hosv_fpr_comparison.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print("saved:", out)


def main():
    data = _load()
    if not MPL_OK:
        print("matplotlib not available; skipping plots")
        return
    plot_main(data)
    plot_fpr(data)


if __name__ == "__main__":
    main()
