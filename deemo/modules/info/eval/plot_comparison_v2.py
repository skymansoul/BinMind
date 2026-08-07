#!/usr/bin/env python
# coding: utf-8
# eval/plot_comparison_v2.py — 检出率/误报率分组对比柱状图
# 读取 benchmark_v2.csv, 按工具×分组(未加壳/加壳) 绘制:
#   左图: 检出率 (Recall%) — 越高越好
#   右图: 误报率 (FPR%)   — 越低越好
# FC-VRA-v3 高亮 (黄色描边), 跳过的工具 (skip) 不参与绘制。
# 输出: eval/comparison_v2.png / .pdf
# 用法: python eval/plot_comparison_v2.py

import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_EVAL = Path(__file__).parent
_CSV = _EVAL / "benchmark_v2.csv"
_PNG = _EVAL / "comparison_v2.png"
_PDF = _EVAL / "comparison_v2.pdf"

_TP = Path(_EVAL).parent / "tests" / "heap_fp_benchmark"


def _load():
    truth = {}
    for d in _TP.iterdir():
        t = d / "truth.json"
        if t.exists():
            truth[d.name] = json.loads(t.read_text(encoding="utf-8"))[
                "expect_overflow"]
    rows = list(csv.DictReader(open(_CSV, encoding="utf-8")))
    # 工具×分组 → [tp, fp, fn, tn]
    agg = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0]))
    skipped = defaultdict(set)
    for r in rows:
        if r["sample_id"] not in truth:
            continue
        if r.get("skip") == "1":
            skipped[r["tool"]].add(r["group"])
            continue
        expect = truth[r["sample_id"]]
        det = int(r["detected"])
        s = agg[r["tool"]][r["group"]]
        if expect and det:
            s[0] += 1
        elif expect:
            s[2] += 1
        elif det:
            s[1] += 1
        else:
            s[3] += 1
    return agg, skipped


def _metrics(agg):
    """工具 → (unpacked_recall, unpacked_fpr, packed_recall, packed_fpr, present_groups)"""
    out = {}
    for tool, groups in agg.items():
        rec = {}
        fpr = {}
        for g, (tp, fp, fn, tn) in groups.items():
            rec[g] = tp / (tp + fn) * 100 if (tp + fn) else 0.0
            fpr[g] = fp / (fp + tn) * 100 if (fp + tn) else 0.0
        out[tool] = {
            "u_rec": rec.get("unpacked", 0), "u_fpr": fpr.get("unpacked", 0),
            "p_rec": rec.get("packed", 0), "p_fpr": fpr.get("packed", 0),
            "groups": set(groups.keys()),
        }
    return out


def _plot(m, skipped):
    tools = [t for t in sorted(m) if t not in skipped or "unpacked" in m[t]["groups"]]
    if not tools:
        print("no data to plot")
        return
    n = len(tools)
    x = np.arange(n)
    w = 0.36

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    u_rec = [m[t]["u_rec"] for t in tools]
    p_rec = [m[t]["p_rec"] for t in tools]
    b1 = ax1.bar(x - w / 2, u_rec, w, label="Unpacked", color="#4C72B0")
    b2 = ax1.bar(x + w / 2, p_rec, w, label="Packed", color="#55A868")
    for t, b in zip(tools, [b1, b2]):
        pass
    # 高亮 FC-VRA
    for i, t in enumerate(tools):
        if t == "FC_VRA_v3":
            for b in (ax1.patches[i], ax1.patches[n + i]):
                b.set_edgecolor("#DD8452")
                b.set_linewidth(2.5)
    ax1.set_ylabel("Detection Rate (Recall %)")
    ax1.set_title("Detection Rate by Tool and Group")
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, rotation=20, ha="right")
    ax1.set_ylim(0, 115)
    ax1.legend()
    for i, v in enumerate(u_rec):
        ax1.text(i - w / 2, v + 1, f"{v:.0f}", ha="center", fontsize=8)
        ax1.text(i + w / 2, p_rec[i] + 1, f"{p_rec[i]:.0f}", ha="center",
                 fontsize=8)

    u_fpr = [m[t]["u_fpr"] for t in tools]
    p_fpr = [m[t]["p_fpr"] for t in tools]
    ax2.bar(x - w / 2, u_fpr, w, label="Unpacked", color="#4C72B0")
    ax2.bar(x + w / 2, p_fpr, w, label="Packed", color="#55A868")
    for i, t in enumerate(tools):
        if t == "FC_VRA_v3":
            for b in (ax2.patches[i], ax2.patches[n + i]):
                b.set_edgecolor("#DD8452")
                b.set_linewidth(2.5)
    ax2.set_ylabel("False Positive Rate (%)")
    ax2.set_title("False Positive Rate by Tool and Group")
    ax2.set_xticks(x)
    ax2.set_xticklabels(tools, rotation=20, ha="right")
    ax2.set_ylim(0, 115)
    ax2.legend()
    for i, v in enumerate(u_fpr):
        ax2.text(i - w / 2, v + 1, f"{v:.0f}", ha="center", fontsize=8)
        ax2.text(i + w / 2, p_fpr[i] + 1, f"{p_fpr[i]:.0f}", ha="center",
                 fontsize=8)

    fig.suptitle("Heap-Overflow Static Detection: Recall vs. False-Positive Rate\n"
                 "(30-sample benchmark; 15 vulnerable / 15 safe)", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(_PNG, dpi=150)
    fig.savefig(_PDF)
    print(f"saved: {_PNG} / {_PDF}")


def main():
    agg, skipped = _load()
    m = _metrics(agg)
    _plot(m, skipped)


if __name__ == "__main__":
    main()
