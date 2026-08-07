# 对比实验可视化 — 真实 CSV 数据绘图
#
# 读取 eval/results/multi_tool_comparison.csv (run_benchmark.py 输出),
# 生成:
#   1. comparison_recall.png — 检出率(召回)柱状图
#   2. comparison_fpr.png    — 误报率柱状图 (核心创新锚点)
#   3. comparison_bar.png    — 召回+误报双指标组合图
#
# 决策: 只用实测数据, 不用文献估计 (避免注水).
# QEMU/Ghidra 不可用时其数据为 0 且标注 unavailable.
# 创建: 2026-06-20

import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RESULTS = Path(__file__).resolve().parent / "results"


def load_csv():
    p = RESULTS / "multi_tool_comparison.csv"
    if not p.exists():
        print(f"CSV not found: {p}")
        return []
    with open(p, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def aggregate(rows):
    """按工具聚合 TP/FP/TN/FN."""
    agg = {}
    for r in rows:
        tool = r["tool"]
        if tool not in agg:
            agg[tool] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "err": 0}
        a = agg[tool]
        is_vuln = r["is_vuln"] == "True"
        detected = r["detected"] == "True"
        if is_vuln:
            if detected:
                a["tp"] += 1
            else:
                a["fn"] += 1
        else:
            if detected:
                a["fp"] += 1
            else:
                a["tn"] += 1
        if r.get("error"):
            a["err"] += 1
    return agg


def plot(rows):
    agg = aggregate(rows)
    if not agg:
        return
    tools = sorted(agg.keys())
    recalls, fprs, labels = [], [], []
    for t in tools:
        a = agg[t]
        rec = a["tp"] / max(a["tp"] + a["fn"], 1)
        fpr = a["fp"] / max(a["fp"] + a["tn"], 1)
        recalls.append(rec)
        fprs.append(fpr)
        labels.append(f"{t} (unavail)" if a["err"] else t)

    x = np.arange(len(tools))
    width = 0.35

    # 图1: 召回率
    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(x, recalls, width, color="#2e7d32", edgecolor="black")
    for i, (b, v) in enumerate(zip(bars, recalls)):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02,
                f"{v:.1%}", ha="center", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Recall")
    ax.set_title("Heap-Overflow Detection Recall (45 vulnerable samples)")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    (RESULTS / "comparison_recall.png").write_bytes(
        _fig_bytes(fig))
    plt.close(fig)

    # 图2: 误报率 (核心创新锚点)
    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(x, fprs, width, color="#c62828", edgecolor="black")
    for i, (b, v) in enumerate(zip(bars, fprs)):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02,
                f"{v:.1%}", ha="center", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("False Positive Rate")
    ax.set_title("Heap-Overflow Detection False Positive Rate (45 safe samples)")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    (RESULTS / "comparison_fpr.png").write_bytes(_fig_bytes(fig))
    plt.close(fig)

    # 图3: 双指标组合
    fig, ax = plt.subplots(figsize=(8, 5))
    ax2 = ax.twinx()
    b1 = ax.bar(x - width / 2, recalls, width, color="#2e7d32",
                label="Recall")
    b2 = ax2.bar(x + width / 2, fprs, width, color="#c62828",
                 label="FPR")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax2.set_ylim(0, 1.15)
    ax.set_ylabel("Recall")
    ax2.set_ylabel("False Positive Rate")
    ax.set_title("BinMind vs generic tools: Recall vs FPR")
    for b, v in zip(b1, recalls):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.0%}",
                ha="center", fontsize=9)
    for b, v in zip(b2, fprs):
        ax2.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.0%}",
                 ha="center", fontsize=9)
    ax.legend(loc="upper left")
    ax2.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    (RESULTS / "comparison_bar.png").write_bytes(_fig_bytes(fig))
    plt.close(fig)

    print(f"saved: comparison_recall.png, comparison_fpr.png, "
          f"comparison_bar.png")
    for t in tools:
        a = agg[t]
        print(f"  {t}: TP={a['tp']} FP={a['fp']} TN={a['tn']} FN={a['fn']}")


def _fig_bytes(fig):
    import io
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110)
    buf.seek(0)
    return buf.getvalue()


if __name__ == "__main__":
    rows = load_csv()
    plot(rows)
