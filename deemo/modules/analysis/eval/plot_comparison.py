# 对比实验可视化 - 真实 CSV 数据绘图
#
# 读取 eval/results/multi_tool_comparison.csv (run_benchmark.py 输出),
# 生成:
#   1. comparison_recall.png - 检出率(召回)柱状图
#   2. comparison_fpr.png    - 误报率柱状图 (核心创新锚点)
#   3. comparison_bar.png    - 召回+误报双指标组合图
#
# 决策: 只用实测数据, 不用文献估计 (避免注水).
# QEMU/Ghidra 不可用时其数据为 0 且标注 unavailable.

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

    # 图4: 按样本分组 (awsc_same_source / fp_prone) 的误报对比
    # 两组均为未加壳 MinGW 样本; 加壳样本维度留待扩展.
    fig, ax = plt.subplots(figsize=(8, 5))
    groups = sorted(set(r.get("group", "") for r in rows if r.get("group")))
    if groups:
        gx = np.arange(len(groups))
        fpr_bin, fpr_angr = [], []
        for g in groups:
            def _fpr(tool):
                gr = [r for r in rows
                      if r["tool"] == tool and r.get("group") == g
                      and r["is_vuln"] == "False"]
                fp = sum(1 for r in gr if r["detected"] == "True")
                return fp / max(len(gr), 1)
            fpr_bin.append(_fpr("BinMind"))
            fpr_angr.append(_fpr("Angr"))
        ax.bar(gx - width / 2, fpr_bin, width, color="#2e7d32",
               label="BinMind")
        ax.bar(gx + width / 2, fpr_angr, width, color="#c62828",
               label="Angr")
        for i, v in enumerate(fpr_bin):
            ax.text(gx[i] - width / 2, v + 0.02, f"{v:.0%}",
                    ha="center", fontsize=9)
        for i, v in enumerate(fpr_angr):
            ax.text(gx[i] + width / 2, v + 0.02, f"{v:.0%}",
                    ha="center", fontsize=9)
        ax.set_xticks(gx)
        ax.set_xticklabels(groups)
        ax.set_ylim(0, 1.15)
        ax.set_ylabel("False Positive Rate")
        ax.set_title("FPR by sample group (unpacked MinGW binaries)")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()
        (RESULTS / "comparison_group_fpr.png").write_bytes(_fig_bytes(fig))
        plt.close(fig)

    print(f"saved: comparison_recall.png, comparison_fpr.png, "
          f"comparison_bar.png, comparison_group_fpr.png")
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
