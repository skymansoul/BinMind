# -*- coding: utf-8 -*-
# 对比图表生成
#
"""
读取 benchmark_results.csv / benchmark_results.json, 生成:
  recall_comparison.png   检出率柱状图 (工具 × 变体 O0/O2 分组)
  fpr_comparison.png      误报率柱状图
  verdict_heatmap.png     判定矩阵热图 (O0)

用法: python plot_comparison.py
"""

import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_EVAL = Path(__file__).resolve().parent
_CORPUS = _EVAL.parents[1] / "modules" / "vuln" / "test_samples" / "cve_heap"

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei",
                                   "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False


def main() -> int:
    csv_path = _EVAL / "benchmark_results.csv"
    if not csv_path.exists():
        print("benchmark_results.csv missing — run run_benchmark.py first")
        return 1
    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    tools = ["GASRI", "Angr", "Qemu", "Ghidra"]
    variants = ["O0", "O2"]
    metric = {}
    for r in rows:
        m = metric.setdefault((r["tool"], r["variant"]),
                              {"TP": 0, "TN": 0, "FP": 0, "FN": 0})
        m[r["verdict"]] += 1

    x = np.arange(len(tools))
    width = 0.38
    recall, fpr = [], []
    for t in tools:
        rv, fv = [], []
        for v in variants:
            m = metric.get((t, v), {"TP": 0, "TN": 0, "FP": 0, "FN": 0})
            rv.append(m["TP"] / max(1, m["TP"] + m["FN"]))
            fv.append(m["FP"] / max(1, m["FP"] + m["TN"]))
        recall.append(rv)
        fpr.append(fv)

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, v in enumerate(variants):
        ax.bar(x + (i - 0.5) * width, [recall[j][i] for j in range(4)],
               width, label=f"variant {v}")
    ax.set_ylabel("Detection rate (Recall)")
    ax.set_title("Heap-overflow detection rate by tool & variant")
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    ax.set_ylim(0, 1.05)
    for i in range(2):
        for j in range(4):
            ax.text(x[j] + (i - 0.5) * width, recall[j][i] + 0.02,
                    f"{recall[j][i]:.2f}", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(_EVAL / "recall_comparison.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, v in enumerate(variants):
        ax.bar(x + (i - 0.5) * width, [fpr[j][i] for j in range(4)],
               width, label=f"variant {v}", color=["#c44e52", "#55a868"][i])
    ax.set_ylabel("False positive rate (FPR)")
    ax.set_title("Heap-overflow false positive rate by tool & variant")
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    ax.set_ylim(0, 1.05)
    for i in range(2):
        for j in range(4):
            ax.text(x[j] + (i - 0.5) * width, fpr[j][i] + 0.02,
                    f"{fpr[j][i]:.2f}", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(_EVAL / "fpr_comparison.png", dpi=150)
    plt.close(fig)

    r2 = [r for r in rows if r["variant"] == "O0"]
    samples = sorted({r["sample"] for r in r2})
    grid = np.zeros((len(tools), len(samples)))
    for r in r2:
        if r["tool"] in tools and r["sample"] in samples:
            grid[tools.index(r["tool"]), samples.index(r["sample"])] = \
                {"TP": 1.0, "TN": 0.0, "FP": -1.0, "FN": 0.5}.get(
                    r["verdict"], 0)
    fig, ax = plt.subplots(figsize=(0.55 * len(samples) + 2, 4))
    ax.imshow(grid, cmap=plt.cm.RdYlGn, vmin=-1, vmax=1, aspect="auto")
    ax.set_xticks(range(len(samples)))
    ax.set_xticklabels(samples, rotation=90, fontsize=7)
    ax.set_yticks(range(len(tools)))
    ax.set_yticklabels(tools)
    ax.set_title("Per-sample verdict heatmap (O0)\n"
                 "green=TP blue=TN yellow=FN red=FP")
    fig.tight_layout()
    fig.savefig(_EVAL / "verdict_heatmap.png", dpi=150)
    plt.close(fig)

    print(f"saved: {_EVAL / 'recall_comparison.png'}, "
          f"{_EVAL / 'fpr_comparison.png'}, {_EVAL / 'verdict_heatmap.png'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
