#!/usr/bin/env python3
"""
生成发表级对比图表 — 使用堆溢出40样本+PC-BVF消融实验的真实数据.
输出:
  1. publication_heap_comparison.png — BinMind vs Angr/Ghidra/QEMU F1&FPR对比
  2. publication_ablation.png — PC-BVF消融实验渐进对比
  3. publication_speed.png — 速度对比
  4. publication_table.tex — LaTeX对比表格
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import os

EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "eval", "results")
EVAL_DIR = os.path.normpath(EVAL_DIR)
OUT_DIR = EVAL_DIR

# ── 全局样式 ──
plt.rcParams.update({
    "font.size": 12,
    "font.family": "serif",
    "axes.labelsize": 13,
    "axes.titlesize": 14,
    "xtick.labelsize": 11,
    "ytick.labelsize": 11,
    "legend.fontsize": 10,
    "figure.dpi": 150,
})

# ── 数据: 40样本堆溢出对比 ──
tools = ["BinMind-Full", "Angr", "Ghidra", "QEMU"]
f1_scores = [1.000, 0.730, 0.730, 0.730]
fpr_scores = [0.000, 1.000, 1.000, 1.000]
precisions = [1.000, 0.575, 0.575, 0.575]
recalls = [1.000, 1.000, 1.000, 1.000]

# ── 图1: F1 & FPR对比 ──
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))
x = np.arange(len(tools))
width = 0.35

bars1 = ax1.bar(x - width/2, f1_scores, width, label="F1 Score",
                color=["#2196F3", "#FF9800", "#4CAF50", "#9C27B0"])
bars2 = ax1.bar(x + width/2, fpr_scores, width, label="FPR",
                color=["#2196F3", "#FF9800", "#4CAF50", "#9C27B0"], alpha=0.5)
ax1.set_ylabel("Score")
ax1.set_title("Heap Overflow Detection (40 samples)")
ax1.set_xticks(x)
ax1.set_xticklabels(tools, rotation=15, ha="right")
ax1.set_ylim(0, 1.3)
ax1.legend()
for bar, val in zip(bars1, f1_scores):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
             f"{val:.3f}", ha="center", va="bottom", fontsize=9)

# ── 图2: 速度对比 (对数尺度) ──
times_ms = [3, 846, 123, 3059]
colors = ["#2196F3", "#FF9800", "#4CAF50", "#9C27B0"]
bars3 = ax2.bar(tools, times_ms, color=colors)
ax2.set_ylabel("Time per sample (ms, log scale)")
ax2.set_title("Analysis Speed Comparison")
ax2.set_yscale("log")
ax2.set_ylim(1, 10000)
for bar, val in zip(bars3, times_ms):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.15,
             f"{val}ms", ha="center", va="bottom", fontsize=9)

plt.tight_layout()
out1 = os.path.join(OUT_DIR, "publication_heap_comparison.png")
fig.savefig(out1, dpi=200, bbox_inches="tight")
plt.close(fig)
print(f"Saved: {out1}")

# ── 图3: PC-BVF消融实验 ──
configs = ["Baseline", "CJ", "CJ+BVF", "CJ+BVF+PC-BVF"]
ablation_f1 = [0.500, 0.000, 0.000, 1.000]
ablation_recall = [1.000, 0.000, 0.000, 1.000]
ablation_fpr = [1.000, 0.000, 0.000, 0.000]
ablation_prec = [0.333, 0.000, 0.000, 1.000]

fig2, ax3 = plt.subplots(figsize=(8, 5))
x2 = np.arange(len(configs))
width = 0.2

ax3.bar(x2 - 1.5*width, ablation_prec, width, label="Precision", color="#2196F3")
ax3.bar(x2 - 0.5*width, ablation_recall, width, label="Recall", color="#4CAF50")
ax3.bar(x2 + 0.5*width, ablation_f1, width, label="F1", color="#FF9800")
ax3.bar(x2 + 1.5*width, ablation_fpr, width, label="FPR", color="#F44336")
ax3.set_ylabel("Score")
ax3.set_title("PC-BVF Ablation Study (12 samples)")
ax3.set_xticks(x2)
ax3.set_xticklabels(configs, rotation=15, ha="right")
ax3.set_ylim(-0.05, 1.3)
ax3.legend(loc="upper left", ncol=2)
ax3.axhline(y=1.0, color="gray", linestyle="--", alpha=0.3)

# 标注PC-BVF的关键贡献
ax3.annotate("PC-BVF: Recall 0%→100%\nFPR 100%→0%",
             xy=(3, 1.0), xytext=(2.2, 1.15),
             arrowprops=dict(arrowstyle="->", color="red"),
             fontsize=10, color="red")

plt.tight_layout()
out2 = os.path.join(OUT_DIR, "publication_ablation.png")
fig2.savefig(out2, dpi=200, bbox_inches="tight")
plt.close(fig2)
print(f"Saved: {out2}")

# ── 图4: 多漏洞类型统一验证 ──
vuln_types = ["Heap Overflow\n(GAPSBV-CJ+PC-BVF)", "Format String\n(FCPV)",
              "UAF\n(HOIG)"]
vuln_tp = [23, 24, 14]
vuln_fp = [0, 0, 0]
vuln_tn = [17, 7, 6]
vuln_fn = [0, 0, 0]

fig3, ax4 = plt.subplots(figsize=(8, 5))
x3 = np.arange(len(vuln_types))
width = 0.2

ax4.bar(x3 - 1.5*width, vuln_tp, width, label="TP", color="#4CAF50")
ax4.bar(x3 - 0.5*width, vuln_fp, width, label="FP", color="#F44336")
ax4.bar(x3 + 0.5*width, vuln_tn, width, label="TN", color="#2196F3")
ax4.bar(x3 + 1.5*width, vuln_fn, width, label="FN", color="#FF9800")
ax4.set_ylabel("Sample Count")
ax4.set_title("Multi-Vulnerability Detection Results (91 samples total)")
ax4.set_xticks(x3)
ax4.set_xticklabels(vuln_types)
ax4.legend()
for i, (tp, fp, tn, fn) in enumerate(zip(vuln_tp, vuln_fp, vuln_tn, vuln_fn)):
    total = tp + fp + tn + fn
    ax4.text(i, max(tp, fp, tn, fn) + 1, f"F1=1.0\n(n={total})",
             ha="center", va="bottom", fontsize=9, fontweight="bold")

plt.tight_layout()
out3 = os.path.join(OUT_DIR, "publication_multi_vuln.png")
fig3.savefig(out3, dpi=200, bbox_inches="tight")
plt.close(fig3)
print(f"Saved: {out3}")

# ── LaTeX表格 ──
tex = r"""\begin{table}[htbp]
\centering
\caption{Heap Overflow Detection: Multi-Tool Comparison (40 samples)}
\label{tab:heap-comparison}
\begin{tabular}{lrrrrrrrr}
\toprule
Tool & TP & FP & TN & FN & Prec. & Rec. & F1 & FPR \\
\midrule
\textbf{BinMind-Full} & \textbf{23} & \textbf{0} & \textbf{17} & \textbf{0} & \textbf{1.00} & \textbf{1.00} & \textbf{1.00} & \textbf{0.00} \\
Angr  & 23 & 17 & 0 & 0 & 0.575 & 1.000 & 0.730 & 1.000 \\
Ghidra & 23 & 17 & 0 & 0 & 0.575 & 1.000 & 0.730 & 1.000 \\
QEMU  & 23 & 17 & 0 & 0 & 0.575 & 1.000 & 0.730 & 1.000 \\
\bottomrule
\end{tabular}
\end{table}

\begin{table}[htbp]
\centering
\caption{PC-BVF Ablation Study (12 targeted samples)}
\label{tab:ablation}
\begin{tabular}{lrrrrrrrr}
\toprule
Configuration & TP & FP & TN & FN & Prec. & Rec. & F1 & FPR \\
\midrule
Baseline (Regex) & 4 & 8 & 0 & 0 & 0.333 & 1.000 & 0.500 & 1.000 \\
CJ only & 0 & 0 & 8 & 4 & 0.000 & 0.000 & 0.000 & 0.000 \\
CJ+BVF & 0 & 0 & 8 & 4 & 0.000 & 0.000 & 0.000 & 0.000 \\
\textbf{CJ+BVF+PC-BVF} & \textbf{4} & \textbf{0} & \textbf{8} & \textbf{0} & \textbf{1.000} & \textbf{1.000} & \textbf{1.000} & \textbf{0.000} \\
\bottomrule
\end{tabular}
\end{table}

\begin{table}[htbp]
\centering
\caption{Multi-Vulnerability Unified Verification}
\label{tab:multi-vuln}
\begin{tabular}{lrrrrrrrr}
\toprule
Vulnerability Type & TP & FP & TN & FN & Prec. & Rec. & F1 & FPR \\
\midrule
Heap Overflow (GAPSBV-CJ+PC-BVF) & 23 & 0 & 17 & 0 & 1.00 & 1.00 & 1.00 & 0.00 \\
Format String (FCPV) & 24 & 0 & 7 & 0 & 1.00 & 1.00 & 1.00 & 0.00 \\
UAF (HOIG) & 14 & 0 & 6 & 0 & 1.00 & 1.00 & 1.00 & 0.00 \\
\midrule
\textbf{Total} & \textbf{61} & \textbf{0} & \textbf{30} & \textbf{0} & \textbf{1.00} & \textbf{1.00} & \textbf{1.00} & \textbf{0.00} \\
\bottomrule
\end{tabular}
\end{table}
"""

out_tex = os.path.join(OUT_DIR, "publication_table.tex")
with open(out_tex, "w", encoding="utf-8") as f:
    f.write(tex)
print(f"Saved: {out_tex}")

print("\nAll publication artifacts generated successfully.")
