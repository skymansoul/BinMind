#!/usr/bin/env python
# coding: utf-8
# eval/plot_multi_fp.py — 多类型 (heap/uaf/fmt) 检出率/误报率对比
# 读取 tests/multi_fp_regression/results/summary_multi.json, 绘制 3×2 网格:
#   每行一个漏洞类型, 左列检出率, 右列误报率。
# 改进检测器 (FC_VRA_v3/UAF_FC_v3/FMT_FC_v3) 高亮。
# 用法: python eval/plot_multi_fp.py

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_EVAL = Path(__file__).parent
_SUMMARY = (_EVAL.parent / "tests" / "multi_fp_regression" / "results"
            / "summary_multi.json")
_PNG = _EVAL / "multi_fp_comparison.png"
_PDF = _EVAL / "multi_fp_comparison.pdf"

TYPE_LABEL = {"heap": "Heap Overflow (CWE-122)",
              "uaf": "Use-After-Free (CWE-416)",
              "fmt": "Format String (CWE-134)"}
STAR = {"FC_VRA_v3", "UAF_FC_v3", "FMT_FC_v3"}


def main():
    data = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    types = ["heap", "uaf", "fmt"]
    fig, axes = plt.subplots(3, 2, figsize=(12, 10))

    for row, vtype in enumerate(types):
        rows = [r for r in data if r["type"] == vtype]
        rows.sort(key=lambda r: r["recall_pct"], reverse=True)
        tools = [r["tool"] for r in rows]
        rec = [r["recall_pct"] for r in rows]
        fpr = [r["fpr_pct"] for r in rows]
        x = np.arange(len(tools))

        ax1, ax2 = axes[row]
        b1 = ax1.bar(x, rec, 0.6, color="#4C72B0")
        ax1.set_title(f"{TYPE_LABEL[vtype]} — Detection Rate (%)", fontsize=11)
        ax1.set_ylim(0, 115)
        ax1.set_xticks(x)
        ax1.set_xticklabels(tools, rotation=20, ha="right", fontsize=9)
        for i, v in enumerate(rec):
            ax1.text(i, v + 2, f"{v:.0f}", ha="center", fontsize=9)

        b2 = ax2.bar(x, fpr, 0.6, color="#C44E52")
        ax2.set_title(f"{TYPE_LABEL[vtype]} — False Positive Rate (%)",
                      fontsize=11)
        ax2.set_ylim(0, 115)
        ax2.set_xticks(x)
        ax2.set_xticklabels(tools, rotation=20, ha="right", fontsize=9)
        for i, v in enumerate(fpr):
            ax2.text(i, v + 2, f"{v:.0f}", ha="center", fontsize=9)

        # 高亮改进检测器
        for i, t in enumerate(tools):
            if t in STAR:
                b1[i].set_edgecolor("#DD8452")
                b1[i].set_linewidth(2.5)
                b2[i].set_edgecolor("#DD8452")
                b2[i].set_linewidth(2.5)

    fig.suptitle("Flow-Correlated FP-Reduction across Three Vulnerability Types\n"
                 "(15 vulnerable + 15 safe samples each; orange = this work)",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(_PNG, dpi=150)
    fig.savefig(_PDF)
    print(f"saved: {_PNG} / {_PDF}")


if __name__ == "__main__":
    main()
