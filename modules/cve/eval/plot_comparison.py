# 对比实验可视化 - 检出率/误报率柱状图.
#
# 决策逻辑:
#   从 eval/results/benchmark.json 读取各工具逐样本结果,
#   按工具与 (加壳/未加壳) 分组聚合 TP/FP/FN/TN,
#   绘制检出率与误报率双轴柱状图, 输出 PNG.
#   工具缺外部依赖 (qemu/ghidra 未配置) 时仅统计可运行部分,
#   并标注 "n/a" 防止误导.
#

import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
BENCH_JSON = RESULTS_DIR / "benchmark.json"

TOOL_ORDER = ["BinMind-PcWBI", "BinMind-Baseline", "angr",
              "qemu-user", "ghidra-headless"]


def _aggregate(rows, group=None):
    tp = fp = fn = tn = 0
    for r in rows:
        if group is not None and r.get("group") != group:
            continue
        v = r.get("verdict")
        if v == "NA":
            continue
        if v == "TP":
            tp += 1
        elif v == "FP":
            fp += 1
        elif v == "FN":
            fn += 1
        elif v == "TN":
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return tp, fp, fn, tn, recall, fpr


def plot():
    if not BENCH_JSON.exists():
        print(f"benchmark.json not found: {BENCH_JSON}. "
              "Run eval/run_benchmark.py first.")
        return
    rows = json.loads(BENCH_JSON.read_text(encoding="utf-8"))

    tools = [t for t in TOOL_ORDER
             if any(r.get("tool") == t for r in rows)]

    def _series(group):
        return [_aggregate(
            [r for r in rows if r.get("tool") == t], group) for t in tools]

    overall = _series(None)
    unpacked = _series("unpacked")
    packed = _series("packed")

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    x = range(len(tools))

    def _draw(ax, data, title, metric_idx, metric_name):
        vals = [d[metric_idx] if d[metric_idx] == d[metric_idx] else 0
                for d in data]
        ax.bar(x, vals, color="#4C72B0", width=0.55)
        ax.set_xticks(list(x))
        ax.set_xticklabels(tools, rotation=20, ha="right", fontsize=9)
        ax.set_ylim(0, 1.05)
        ax.set_title(title)
        ax.set_ylabel(metric_name)
        for xi, d, v in zip(x, data, vals):
            if d[metric_idx] != d[metric_idx]:
                ax.text(xi, 0.02, "n/a", ha="center", fontsize=8,
                        color="gray")
            else:
                ax.text(xi, v + 0.02, f"{v:.2f}", ha="center", fontsize=8)

    # 左图: 检出率 (未加壳/加壳双组)
    _draw(axes[0], [d if d[4] == d[4] else (0, 0, 0, 0, 0, 0)
                    for d in unpacked], "Recall (unpacked)", 4, "Recall")
    _draw(axes[1], [d if d[5] == d[5] else (0, 0, 0, 0, 0, 0)
                    for d in unpacked], "FP Rate (unpacked)", 5, "FPR")

    fig.suptitle("Heap Overflow Detection: Multi-Tool Comparison "
                 "(20 samples, O0+O2)", fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    out = RESULTS_DIR / "comparison_bar.png"
    fig.savefig(out, dpi=120)
    print(f"plot saved -> {out}")

    # 分加壳/未加壳双图
    for group, label in (("unpacked", "unpacked"), ("packed", "packed")):
        fig2, ax2 = plt.subplots(1, 2, figsize=(13, 5))
        data = _series(group)
        _draw(ax2[0], data, f"Recall ({label})", 4, "Recall")
        _draw(ax2[1], data, f"FP Rate ({label})", 5, "FPR")
        fig2.tight_layout()
        out2 = RESULTS_DIR / f"comparison_{label}.png"
        fig2.savefig(out2, dpi=120)
        print(f"plot saved -> {out2}")


if __name__ == "__main__":
    plot()
