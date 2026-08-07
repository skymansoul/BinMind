#!/usr/bin/env python3
"""
发表级对比图表 v2 — 修复图例、零值标注、色盲友好调色板.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import os

EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "eval", "results")
EVAL_DIR = os.path.normpath(EVAL_DIR)
OUT_DIR = EVAL_DIR

# 色盲友好调色板 (Paul Tol)
C_BLUE = "#4477AA"
C_ORANGE = "#EE6677"
C_GREEN = "#228833"
C_PURPLE = "#AA3377"
C_CYAN = "#66CCEE"
C_YELLOW = "#CCBB44"

plt.rcParams.update({
    "font.size": 12, "font.family": "serif",
    "axes.labelsize": 13, "axes.titlesize": 14,
    "xtick.labelsize": 11, "ytick.labelsize": 11,
    "legend.fontsize": 10, "figure.dpi": 150,
})

# ═══════════════════════════════════════════
# 图1: F1 & FPR对比 + 速度对比 (2x1)
# ═══════════════════════════════════════════
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

tools = ["BinMind\n(Full)", "Angr", "Ghidra", "QEMU"]
f1 = [1.000, 0.730, 0.730, 0.730]
fpr = [0.000, 1.000, 1.000, 1.000]
x = np.arange(len(tools))
w = 0.3

# 左图: F1 (深蓝) vs FPR (浅红)
bars_f1 = ax1.bar(x - w/2, f1, w, label="F1 Score (higher=better)", color=C_BLUE)
bars_fpr = ax1.bar(x + w/2, fpr, w, label="FPR (lower=better)", color=C_ORANGE, alpha=0.7)
ax1.set_ylabel("Score / Rate")
ax1.set_title("(a) Heap Overflow Detection (40 samples)")
ax1.set_xticks(x)
ax1.set_xticklabels(tools, fontsize=10)
ax1.set_ylim(0, 1.35)
ax1.legend(loc="upper left")
for bar, val in zip(bars_f1, f1):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
             f"{val:.3f}", ha="center", va="bottom", fontsize=8)
for bar, val in zip(bars_fpr, fpr):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
             f"{val:.3f}", ha="center", va="bottom", fontsize=8)

# 右图: 速度对比
times = [3, 846, 123, 3059]
colors_s = [C_BLUE, C_ORANGE, C_GREEN, C_PURPLE]
bars_t = ax2.bar(tools, times, color=colors_s)
ax2.set_ylabel("Time per sample (ms, log scale)")
ax2.set_title("(b) Analysis Speed Comparison")
ax2.set_yscale("log")
ax2.set_ylim(1, 10000)
for bar, val in zip(bars_t, times):
    ax2.text(bar.get_x() + bar.get_width()/2, val * 1.2,
             f"{val}ms", ha="center", va="bottom", fontsize=9)
ax2.grid(axis="y", alpha=0.2)

plt.tight_layout()
out1 = os.path.join(OUT_DIR, "publication_heap_comparison.png")
fig.savefig(out1, dpi=200, bbox_inches="tight")
plt.close(fig)
print(f"Saved: {out1}")

# ═══════════════════════════════════════════
# 图2: PC-BVF消融实验 (修正版)
# ═══════════════════════════════════════════
configs = ["Baseline\n(Regex)", "CJ\nonly", "CJ+BVF", "CJ+BVF\n+PC-BVF"]
abl_prec = [0.333, 0, 0, 1.0]
abl_rec = [1.0, 0, 0, 1.0]
abl_f1 = [0.5, 0, 0, 1.0]
abl_fpr = [1.0, 0, 0, 0.0]

fig2, ax3 = plt.subplots(figsize=(8, 5))
x2 = np.arange(len(configs))
w2 = 0.18

# 四组柱: Prec(蓝), Recall(绿), F1(橙), FPR(红)
b1 = ax3.bar(x2 - 1.5*w2, abl_prec, w2, label="Precision", color=C_BLUE)
b2 = ax3.bar(x2 - 0.5*w2, abl_rec, w2, label="Recall", color=C_GREEN)
b3 = ax3.bar(x2 + 0.5*w2, abl_f1, w2, label="F1", color=C_YELLOW)
b4 = ax3.bar(x2 + 1.5*w2, abl_fpr, w2, label="FPR", color=C_ORANGE, alpha=0.7)

ax3.set_ylabel("Score / Rate")
ax3.set_title("PC-BVF Ablation Study (12 targeted samples)")
ax3.set_xticks(x2)
ax3.set_xticklabels(configs, fontsize=10)
ax3.set_ylim(-0.05, 1.35)
ax3.legend(loc="upper left", ncol=2)
ax3.axhline(y=0, color="gray", linewidth=0.5)

# 标注所有非零值
for bars, vals in [(b1, abl_prec), (b2, abl_rec), (b3,abl_f1),(b4,abl_fpr)]:
    for bar, val in zip(bars, vals):
        if val > 0:
            ax3.text(bar.get_x() + bar.get_width()/2, val + 0.02,
                     f"{val:.2f}", ha="center", va="bottom", fontsize=7)
        else:
            ax3.text(bar.get_x() + bar.get_width()/2, 0.02,
                     "0", ha="center", va="bottom", fontsize=6, color="gray")

# 标注PC-BVF关键贡献
ax3.annotate("PC-BVF recovers\nRecall=1.0, FPR=0.0",
             xy=(3, 1.0), xytext=(1.8, 1.15),
             arrowprops=dict(arrowstyle="->", color="red", lw=1.5),
             fontsize=9, color="red", fontweight="bold")

# 添加备注
ax3.text(0.5, -0.15,
         "Note: CJ/CJ+BVF return all-SAFE (Recall=0%) — a degenerate state.\n"
         "PC-BVF is the only configuration achieving both perfect Recall and zero FPR.",
         transform=ax3.transAxes, fontsize=8, style="italic", color="gray",
         ha="center", va="top")

plt.tight_layout()
out2 = os.path.join(OUT_DIR, "publication_ablation.png")
fig2.savefig(out2, dpi=200, bbox_inches="tight")
plt.close(fig2)
print(f"Saved: {out2}")

# ═══════════════════════════════════════════
# 图3: 多漏洞类型统一验证
# ═══════════════════════════════════════════
vuln_types = ["Heap Overflow\n(GAPSBV-CJ+PC-BVF)", "Format String\n(FCPV)", "UAF\n(HOIG)"]
tp = [23, 24, 14]
fp = [0, 0, 0]
tn = [17, 7, 6]
fn = [0, 0, 0]

fig3, ax4 = plt.subplots(figsize=(8, 5))
x3 = np.arange(len(vuln_types))
w3 = 0.18

ax4.bar(x3 - 1.5*w3, tp, w3, label="TP", color=C_GREEN)
ax4.bar(x3 - 0.5*w3, fp, w3, label="FP", color=C_ORANGE)
ax4.bar(x3 + 0.5*w3, tn, w3, label="TN", color=C_BLUE)
ax4.bar(x3 + 1.5*w3, fn, w3, label="FN", color=C_YELLOW)

ax4.set_ylabel("Sample Count")
ax4.set_title("Multi-Vulnerability Detection Results (91 samples total)")
ax4.set_xticks(x3)
ax4.set_xticklabels(vuln_types, fontsize=10)
ax4.legend()
ax4.set_ylim(0, 30)

for i, (t, f, n, m) in enumerate(zip(tp, fp, tn, fn)):
    total = t + f + n + m
    ax4.text(i, 26, f"F1=1.00\n(n={total})",
             ha="center", va="bottom", fontsize=9, fontweight="bold")

# 标注TP值
for i, val in enumerate(tp):
    ax4.text(i - 1.5*w3, val + 0.5, str(val), ha="center", fontsize=8)
for i, val in enumerate(tn):
    ax4.text(i + 0.5*w3, val + 0.5, str(val), ha="center", fontsize=8)

plt.tight_layout()
out3 = os.path.join(OUT_DIR, "publication_multi_vuln.png")
fig3.savefig(out3, dpi=200, bbox_inches="tight")
plt.close(fig3)
print(f"Saved: {out3}")

print("\nAll publication charts generated (v2, fixed).")
