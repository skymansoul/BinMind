#!/usr/bin/env python
# coding: utf-8
# eval/plot_real_cve.py — 真实 CVE 语料对比图
# 读取 real_cve_validation.json, 绘制双面板:
#   左: 堆溢出召回率 (越高越好)   右: 跨类型误报绝对数 (越低越好)
# 用法: python eval/plot_real_cve.py

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_EVAL = Path(__file__).parent
_DATA = _EVAL / "real_cve_validation.json"
_PNG = _EVAL / "real_cve_comparison.png"


def main():
    data = json.loads(_DATA.read_text(encoding="utf-8"))
    summary = data["summary"]
    tools = ["NAIVE", "PSVR_HLM_v2", "FC_VRA_v3"]
    labels = ["NAIVE\n(naive pair match)", "PSVR-HLM v2\n(previous)", "FC-VRA v3\n(this work)"]
    rec = [summary[t]["recall_pct"] for t in tools]
    fp = [summary[t]["cross_type_fp_abs"] for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))
    x = np.arange(len(tools))
    colors = ["#C44E52", "#4C72B0", "#DD8452"]

    b1 = ax1.bar(x, rec, 0.55, color=colors)
    ax1.set_title("Heap-Overflow Recall on 104 Real CVE Samples (%)")
    ax1.set_ylim(0, 115)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9)
    for i, v in enumerate(rec):
        ax1.text(i, v + 2, f"{v:.1f}", ha="center", fontsize=10)
    b1[-1].set_edgecolor("black")
    b1[-1].set_linewidth(1.8)

    b2 = ax2.bar(x, fp, 0.55, color=colors)
    ax2.set_title("Cross-Type False Positives (87 non-heap CVE samples)")
    ax2.set_ylim(0, 40)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=9)
    for i, v in enumerate(fp):
        ax2.text(i, v + 1, str(v), ha="center", fontsize=10)
    b2[-1].set_edgecolor("black")
    b2[-1].set_linewidth(1.8)

    fig.suptitle("Real CVE Corpus Validation (no debug info, no IR)",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    fig.savefig(_PNG, dpi=150)
    print(f"saved: {_PNG}")


if __name__ == "__main__":
    main()
