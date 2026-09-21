"""
守卫感知区间验证消融实验可视化 — 从sgav_benchmark_results.json加载6配置指标,
生成F1/FPR双轴折线图 + TP/FP/TN/FN堆叠柱状图.
"""
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

EVAL_DIR = Path(__file__).resolve().parent
RESULT_PATH = EVAL_DIR / "results" / "sgav_benchmark_results.json"
OUT_DIR = EVAL_DIR / "results"

CONFIGS = ["A0_pattern", "A1_alias", "A2_guard",
           "A3_range", "A4_bounded", "full"]
LABELS = ["A0\nPattern", "A1\n+Alias", "A2\n+Guard",
           "A3\n+Range", "A4\n+Bounded", "Full\nGuard-Range"]
COLORS = ["#e74c3c", "#e67e22", "#f1c40f",
          "#2ecc71", "#3498db", "#9b59b6"]


def load_results():
    with open(RESULT_PATH, encoding="utf-8") as f:
        return json.load(f)


def plot_f1_fpr(data):
    fig, ax1 = plt.subplots(figsize=(8, 5))
    f1s = [data[c]["f1"] for c in CONFIGS]
    fprs = [data[c]["fpr"] for c in CONFIGS]
    x = np.arange(len(CONFIGS))
    ax1.plot(x, f1s, "o-", color="#2ecc71", linewidth=2.5,
             markersize=10, label="F1", zorder=3)
    ax1.fill_between(x, f1s, alpha=0.1, color="#2ecc71")
    ax1.set_ylabel("F1 Score", fontsize=13, color="#27ae60")
    ax1.set_ylim(0, 1.15)
    ax1.set_xticks(x)
    ax1.set_xticklabels(LABELS, fontsize=10)
    ax2 = ax1.twinx()
    ax2.plot(x, fprs, "s--", color="#e74c3c", linewidth=2.5,
             markersize=10, label="FPR", zorder=3)
    ax2.set_ylabel("False Positive Rate", fontsize=13, color="#c0392b")
    ax2.set_ylim(-0.05, 0.3)
    for i, (f1, fpr) in enumerate(zip(f1s, fprs)):
        ax1.annotate(f"{f1:.3f}", (i, f1), textcoords="offset points",
                     xytext=(0, 12), ha="center", fontsize=9, color="#27ae60")
        ax2.annotate(f"{fpr:.3f}", (i, fpr), textcoords="offset points",
                     xytext=(0, -15), ha="center", fontsize=9, color="#c0392b")
    ax1.set_title("Guard-Range Ablation: F1 & FPR Across Configurations",
                  fontsize=14, fontweight="bold")
    ax1.axhline(y=1.0, color="#27ae60", linestyle=":", alpha=0.3)
    ax2.axhline(y=0.0, color="#c0392b", linestyle=":", alpha=0.3)
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="center right",
               fontsize=11)
    plt.tight_layout()
    out = OUT_DIR / "sgav_ablation_f1_fpr.png"
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


def plot_confusion(data):
    fig, ax = plt.subplots(figsize=(9, 5))
    tps = [data[c]["tp"] for c in CONFIGS]
    fps = [data[c]["fp"] for c in CONFIGS]
    tns = [data[c]["tn"] for c in CONFIGS]
    fns = [data[c]["fn"] for c in CONFIGS]
    x = np.arange(len(CONFIGS))
    w = 0.6
    ax.bar(x, tps, w, label="TP", color="#2ecc71")
    ax.bar(x, tns, w, bottom=tps, label="TN", color="#3498db")
    ax.bar(x, fps, w, bottom=[t + n for t, n in zip(tps, tns)],
           label="FP", color="#e74c3c")
    ax.bar(x, fns, w,
           bottom=[t + n + f for t, n, f in zip(tps, tns, fps)],
           label="FN", color="#e67e22")
    for i in range(len(CONFIGS)):
        total = tps[i] + tns[i] + fps[i] + fns[i]
        ax.text(i, total + 0.5, f"n={total}", ha="center", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(LABELS, fontsize=10)
    ax.set_ylabel("Count", fontsize=13)
    ax.set_title("Guard-Range Ablation: Confusion Matrix Breakdown",
                 fontsize=14, fontweight="bold")
    ax.legend(loc="upper right", fontsize=11)
    ax.set_ylim(0, 35)
    plt.tight_layout()
    out = OUT_DIR / "sgav_ablation_confusion.png"
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


def plot_recall_fpr_tradeoff(data):
    fig, ax = plt.subplots(figsize=(7, 5))
    recalls = [data[c]["recall"] for c in CONFIGS]
    fprs = [data[c]["fpr"] for c in CONFIGS]
    ax.plot(fprs, recalls, "o-", color="#9b59b6", linewidth=2.5,
            markersize=12, zorder=3)
    for i, c in enumerate(CONFIGS):
        ax.annotate(c.replace("_", "\n"), (fprs[i], recalls[i]),
                    textcoords="offset points", xytext=(10, 5),
                    fontsize=8, color="#333")
    ax.set_xlabel("False Positive Rate", fontsize=13)
    ax.set_ylabel("Recall", fontsize=13)
    ax.set_xlim(-0.03, 0.25)
    ax.set_ylim(-0.05, 1.1)
    ax.axhline(y=1.0, color="#27ae60", linestyle=":", alpha=0.3)
    ax.axvline(x=0.0, color="#e74c3c", linestyle=":", alpha=0.3)
    ax.set_title("Guard-Range: Recall-FPR Tradeoff (A0→Full)",
                 fontsize=14, fontweight="bold")
    ax.grid(True, alpha=0.2)
    plt.tight_layout()
    out = OUT_DIR / "sgav_recall_fpr_tradeoff.png"
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


def main():
    data = load_results()
    plot_f1_fpr(data)
    plot_confusion(data)
    plot_recall_fpr_tradeoff(data)
    print("All plots generated.")


if __name__ == "__main__":
    main()
