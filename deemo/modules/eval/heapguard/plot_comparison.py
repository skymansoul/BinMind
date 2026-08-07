# -*- coding: utf-8 -*-
# 创建: 2026-04-28  |  对比图表生成
#
"""
对比图表生成器。

输入: benchmark_results.json (汇总指标) + benchmark_results.csv (逐样本)。
输出:
  recall_comparison.png     检出率柱状图 (按工具 × 变体 O0/O2 分组)
  fpr_comparison.png        误报率柱状图 (按工具 × 变体 O0/O2 分组)
  verdict_heatmap.png       判定矩阵热图 (工具 × 样本)

中文字体: Windows 下使用 Microsoft YaHei 回退。
"""

import csv
import json
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    plt = None
    np = None

_EVAL = Path(__file__).resolve().parent
_CORPUS = Path(__file__).resolve().parents[0] / "deemo" / "modules" / \
    "vuln" / "test_samples" / "cve_heap"


def _config_font():
    if plt is None:
        return
    plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei",
                                       "DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False


def _load():
    summary_path = _CORPUS / "benchmark_results.json"
    csv_path = _EVAL / "benchmark_results.csv"
    summary = {}
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    rows = []
    if csv_path.exists():
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    return summary, rows


def plot_recall_fpr(summary: dict, rows: list) -> None:
    if plt is None:
        print("matplotlib not available — skip plots")
        return
    tools = list(summary.get("tools", {}).keys())
    variants = summary.get("variants", ["O0", "O2"])
    # 逐样本按工具×变体聚合
    metric = {}
    for r in rows:
        key = (r["tool"], r["variant"])
        m = metric.setdefault(key, {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
        if r["verdict"] == "TP":
            m["tp"] += 1
        elif r["verdict"] == "TN":
            m["tn"] += 1
        elif r["verdict"] == "FP":
            m["fp"] += 1
        else:
            m["fn"] += 1

    x = np.arange(len(tools))
    width = 0.38

    def bar_values(mfield, denom_field, denom_alt):
        vals = []
        for t in tools:
            v = []
            for var in variants:
                m = metric.get((t, var), {})
                tp = m.get(mfield, 0)
                denom = m.get(denom_field, 0) + tp
                if denom_alt == "fp":
                    denom = m.get("fp", 0) + m.get("tn", 0)
                v.append(tp / max(1, denom))
            vals.append(v)
        return vals

    # 检出率 (recall)
    recall = bar_values("tp", "fn", "tp")
    fig, ax = plt.subplots(figsize=(9, 5))
    for i, var in enumerate(variants):
        vals = [recall[j][i] for j in range(len(tools))]
        ax.bar(x + (i - 0.5) * width, vals, width,
               label=f"variant {var}")
    ax.set_ylabel("Detection rate (Recall)")
    ax.set_title("Heap-overflow detection rate by tool & variant")
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    ax.set_ylim(0, 1.05)
    for i, var in enumerate(variants):
        for j in range(len(tools)):
            v = recall[j][i]
            ax.text(x[j] + (i - 0.5) * width, v + 0.02, f"{v:.2f}",
                    ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(_EVAL / "recall_comparison.png", dpi=150)
    print(f"saved: {_EVAL / 'recall_comparison.png'}")
    plt.close(fig)

    # 误报率 (FPR)
    fpr_vals = []
    for t in tools:
        v = []
        for var in variants:
            m = metric.get((t, var), {})
            fpr = m.get("fp", 0) / max(1, m.get("fp", 0) + m.get("tn", 0))
            v.append(fpr)
        fpr_vals.append(v)
    fig, ax = plt.subplots(figsize=(9, 5))
    for i, var in enumerate(variants):
        vals = [fpr_vals[j][i] for j in range(len(tools))]
        ax.bar(x + (i - 0.5) * width, vals, width,
               label=f"variant {var}", color=["#c44e52", "#55a868"][i])
    ax.set_ylabel("False positive rate (FPR)")
    ax.set_title("Heap-overflow false positive rate by tool & variant")
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    ax.set_ylim(0, 1.05)
    for i, var in enumerate(variants):
        for j in range(len(tools)):
            v = fpr_vals[j][i]
            ax.text(x[j] + (i - 0.5) * width, v + 0.02, f"{v:.2f}",
                    ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(_EVAL / "fpr_comparison.png", dpi=150)
    print(f"saved: {_EVAL / 'fpr_comparison.png'}")
    plt.close(fig)


def plot_heatmap(rows: list) -> None:
    if plt is None:
        return
    tools = sorted({r["tool"] for r in rows}, reverse=True)
    samples = sorted({r["sample"] for r in rows})
    variants = sorted({r["variant"] for r in rows})
    # 只取 O0 变体展示逐样本判定
    r2 = [r for r in rows if r["variant"] == "O0"]
    grid = np.zeros((len(tools), len(samples)))
    for r in r2:
        ti = tools.index(r["tool"])
        si = samples.index(r["sample"])
        grid[ti, si] = {"TP": 1.0, "TN": 0.0, "FP": -1.0, "FN": 0.5}.get(
            r["verdict"], 0)
    fig, ax = plt.subplots(figsize=(0.55 * len(samples) + 2, 4))
    cmap = plt.cm.RdYlGn
    im = ax.imshow(grid, cmap=cmap, vmin=-1, vmax=1, aspect="auto")
    ax.set_xticks(range(len(samples)))
    ax.set_xticklabels(samples, rotation=90, fontsize=7)
    ax.set_yticks(range(len(tools)))
    ax.set_yticklabels(tools)
    ax.set_title("Per-sample verdict heatmap (O0)\n"
                 "green=TP blue=TN yellow=FN red=FP")
    fig.colorbar(im, ax=ax, fraction=0.03)
    fig.tight_layout()
    fig.savefig(_EVAL / "verdict_heatmap.png", dpi=150)
    print(f"saved: {_EVAL / 'verdict_heatmap.png'}")
    plt.close(fig)


def main() -> int:
    _config_font()
    summary, rows = _load()
    if not rows:
        print("benchmark_results.csv empty — run run_benchmark.py first")
        return 1
    plot_recall_fpr(summary, rows)
    plot_heatmap(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
