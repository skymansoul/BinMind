"""
多工具对比可视化 — 检出率/误报率柱状图 + LaTeX 表.

合并说明 (BinMind/eval ↔ deemo/modules/eval 两个版本功能合并):
  - BinMind/eval 版: load/aggregate/grouped_fp/plot — 读 cve_benchmark.csv,
    输出 comparison_bar/grouped/fp/perf.png + result_table.tex
    (Recall/Precision/FPR/F1/平均耗时/峰值内存). 其 gen_latex(agg, path)
    因与 deemo 版同名, 在本合并文件中保留为 gen_latex_agg, 能力不变.
  - deemo/modules/eval 版: load_rows/load_summary/plot_comparison/
    plot_packed_group/gen_latex — 读 results/benchmark_hfp.csv +
    benchmark_summary.json, 输出 fig_tool_comparison.png /
    fig_packed_group.png / result_table.tex (加壳分组, 工具缺失置灰).
  - main() 两套管线均保留: 存在 cve_benchmark.csv 时跑 eval 管线,
    存在 results/benchmark_hfp.csv 时跑 deemo 管线.

决策逻辑:
  读取 benchmark CSV, 生成:
    1. 检出率/误报率分组柱状图 (按工具)
    2. 加壳/未加壳分组图 (若样本含 packed 标记列)
    3. result_table.tex — 论文用 LaTeX 对比表
  外部工具不可用时对应柱为 0 并标注 unavailable.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
RESULTS = BASE / 'results'

TOOL_LABELS = {
    'BinMind-HFP': 'BinMind-HFP (ours)',
    'angr': 'Angr (symbolic)',
    'qemu': 'QEMU (dynamic)',
    'ghidra': 'Ghidra (pattern)',
}


# ---------------------------------------------------------------------------
# BinMind/eval 版: cve_benchmark.csv 管线
# ---------------------------------------------------------------------------

def load(path: Path) -> list:
    """[BinMind/eval 版] 读取 cve_benchmark.csv."""
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def aggregate(rows: list) -> dict:
    """[BinMind/eval 版] 按工具聚合 TP/FP/FN/TN 与指标."""
    agg = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0,
                               "time": 0.0, "mem": 0.0, "n": 0})
    for r in rows:
        a = agg[r["tool"]]
        a["TP"] += int(r["tp"])
        a["FP"] += int(r["fp"])
        a["FN"] += int(r["fn"])
        a["TN"] += int(r["tn"])
        a["time"] += float(r["time_ms"])
        a["mem"] += float(r["peak_mem_mb"])
        a["n"] += 1
    out = {}
    for tool, a in agg.items():
        tp, fp, fn, tn = a["TP"], a["FP"], a["FN"], a["TN"]
        out[tool] = {
            "Recall": tp / max(tp + fn, 1) * 100,
            "Precision": tp / max(tp + fp, 1) * 100,
            "FPR": fp / max(fp + tn, 1) * 100,
            "F1": 2 * tp / max(2 * tp + fp + fn, 1),
            "FP": fp, "TP": tp, "FN": fn, "TN": tn,
            "avg_time_ms": a["time"] / max(a["n"], 1),
            "avg_mem_mb": a["mem"] / max(a["n"], 1),
        }
    return out


def grouped_fp(rows: list) -> dict:
    """[BinMind/eval 版] 按样本类型(安全/漏洞)统计每工具误报/漏报."""
    g = defaultdict(lambda: {"safe_fp": 0, "safe_n": 0,
                             "vuln_fn": 0, "vuln_n": 0})
    for r in rows:
        d = g[r["tool"]]
        if r["truth"] == "safe":
            d["safe_n"] += 1
            d["safe_fp"] += int(r["fp"])
        else:
            d["vuln_n"] += 1
            d["vuln_fn"] += int(r["fn"])
    return g


def gen_latex_agg(agg: dict, out_path: Path):
    """[BinMind/eval 版] 由聚合指标生成 LaTeX 表 (原 eval 版 gen_latex)."""
    tools = list(agg.keys())
    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Heap Overflow Static Detection: 20-sample CVE Benchmark}")
    lines.append(r"\label{tab:cve_comparison}")
    lines.append(r"\begin{tabular}{lccccccc}")
    lines.append(r"\toprule")
    lines.append("Tool & TP & FP & FN & Recall(\\%) & Precision(\\%) "
                 "& FPR(\\%) & F1 \\\\")
    lines.append(r"\midrule")
    for t in tools:
        d = agg[t]
        lines.append(
            f"{t} & {d['TP']} & {d['FP']} & {d['FN']} & "
            f"{d['Recall']:.1f} & {d['Precision']:.1f} & "
            f"{d['FPR']:.1f} & {d['F1']:.4f} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[latex] {out_path}")


def plot(rows: list, out_dir: Path):
    """[BinMind/eval 版] 四张对比图 + LaTeX 表 (comparison_*.png)."""
    agg = aggregate(rows)
    g = grouped_fp(rows)
    tools = list(agg.keys())
    x = range(len(tools))
    w = 0.25

    # 图1: Recall/Precision/F1
    metrics = ["Recall", "Precision", "F1"]
    fig, ax = plt.subplots(figsize=(10, 6))
    for i, m in enumerate(metrics):
        vals = [agg[t][m] for t in tools]
        ax.bar([xi + (i - 1) * w for xi in x], vals, w, label=m)
    ax.set_xticks([xi for xi in x])
    ax.set_xticklabels(tools, rotation=15)
    ax.set_ylabel("Percent (%)")
    ax.set_ylim(0, 105)
    ax.legend()
    ax.set_title("Heap Overflow Detection: Recall / Precision / F1")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "comparison_bar.png", dpi=150)
    plt.close(fig)

    # 图2: 安全样本误报率 vs 漏洞样本漏报率 (分组柱状图)
    fig, ax = plt.subplots(figsize=(10, 6))
    safe_fp = [g[t]["safe_fp"] / max(g[t]["safe_n"], 1) * 100 for t in tools]
    vuln_fn = [g[t]["vuln_fn"] / max(g[t]["vuln_n"], 1) * 100 for t in tools]
    ax.bar([xi - w / 2 for xi in x], safe_fp, w, label="Safe-sample FPR (%)",
           color="#d62728")
    ax.bar([xi + w / 2 for xi in x], vuln_fn, w,
           label="Vuln-sample FNR (%)", color="#ff7f0e")
    ax.set_xticks([xi for xi in x])
    ax.set_xticklabels(tools, rotation=15)
    ax.set_ylabel("Percent (%)")
    ax.set_ylim(0, 105)
    ax.legend()
    ax.set_title("FP on safe samples vs FN on vulnerable samples")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "comparison_grouped.png", dpi=150)
    plt.close(fig)

    # 图3: TP/FP 计数
    fig, ax = plt.subplots(figsize=(8, 5))
    fvals = [agg[t]["FP"] for t in tools]
    tvals = [agg[t]["TP"] for t in tools]
    ax.bar([xi - 0.125 for xi in x], fvals, 0.25, label="False Positives",
           color="#d62728")
    ax.bar([xi + 0.125 for xi in x], tvals, 0.25, label="True Positives",
           color="#2ca02c")
    ax.set_xticks([xi for xi in x])
    ax.set_xticklabels(tools, rotation=15)
    ax.set_ylabel("Sample count")
    ax.legend()
    ax.set_title("Heap Overflow Detection: TP / FP counts")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "comparison_fp.png", dpi=150)
    plt.close(fig)

    # 图4: 耗时与内存
    fig, ax = plt.subplots(figsize=(8, 5))
    tv = [agg[t]["avg_time_ms"] for t in tools]
    mv = [agg[t]["avg_mem_mb"] for t in tools]
    ax.bar([xi - 0.2 for xi in x], tv, 0.4, label="Avg time (ms)")
    ax2 = ax.twinx()
    ax2.plot(x, mv, "o-", color="#9467bd", label="Peak mem (MB)")
    ax.set_xticks([xi for xi in x])
    ax.set_xticklabels(tools, rotation=15)
    ax.set_ylabel("Time (ms)")
    ax2.set_ylabel("Memory (MB)")
    ax.legend(loc="upper left")
    ax2.legend(loc="upper right")
    ax.set_title("Avg time and peak memory")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "comparison_perf.png", dpi=150)
    plt.close(fig)

    gen_latex_agg(agg, out_dir / "result_table.tex")
    print(f"[plot] saved to {out_dir}")


# ---------------------------------------------------------------------------
# deemo/modules/eval 版: results/benchmark_hfp.csv 管线
# ---------------------------------------------------------------------------

def load_rows(csv_path: Path) -> List[Dict]:
    """[deemo/modules/eval 版] 读取 benchmark_hfp.csv."""
    with open(csv_path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def load_summary() -> Dict:
    """[deemo/modules/eval 版] 读取 results/benchmark_summary.json."""
    p = RESULTS / 'benchmark_summary.json'
    if p.exists():
        return json.loads(p.read_text(encoding='utf-8'))
    return {}


def plot_comparison(rows: List[Dict], out_png: Path) -> None:
    """[deemo/modules/eval 版] 检出率/误报率分组柱状图."""
    tools = ['BinMind-HFP', 'angr', 'qemu', 'ghidra']
    labels = [TOOL_LABELS.get(t, t) for t in tools]
    recall, fpr = [], []
    avail_flags = []
    for t in tools:
        trows = [r for r in rows if r['tool'] == t
                 and r['verdict'] != 'UNAVAILABLE']
        avail_flags.append(len(trows) > 0)
        if not trows:
            recall.append(0.0)
            fpr.append(0.0)
            continue
        vuln = [r for r in trows if r['ground_truth'] == 'VULN']
        safe = [r for r in trows if r['ground_truth'] == 'SAFE']
        tp = sum(1 for r in vuln if r['verdict'] == 'TP')
        fp = sum(1 for r in safe if r['verdict'] == 'FP')
        recall.append(tp / len(vuln) if vuln else 0.0)
        fpr.append(fp / len(safe) if safe else 0.0)

    x = np.arange(len(tools))
    w = 0.35
    fig, ax = plt.subplots(figsize=(10, 5))
    b1 = ax.bar(x - w / 2, recall, w, label='Recall', color='#2e86ab')
    b2 = ax.bar(x + w / 2, fpr, w, label='False Positive Rate',
                color='#e07a5f')
    for i, (b, a) in enumerate(zip(b1, avail_flags)):
        if not a:
            b.set_color('#cccccc')
    for i, (b, a) in enumerate(zip(b2, avail_flags)):
        if not a:
            b.set_color('#dddddd')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel('rate')
    ax.set_title('Heap overflow detection: recall vs false positive rate')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def plot_packed_group(rows: List[Dict], out_png: Path) -> None:
    """[deemo/modules/eval 版] 加壳/未加壳分组对比 (样本含 packed 列时)."""
    packed = [r for r in rows if r.get('packed') == '1']
    if not packed:
        # 无加壳样本: 按工具画检出计数
        tools = ['BinMind-HFP', 'angr', 'qemu', 'ghidra']
        counts = [sum(1 for r in rows if r['tool'] == t
                      and r['verdict'] in ('TP', 'FP')) for t in tools]
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(tools, counts, color='#3d5a80')
        ax.set_ylabel('findings')
        ax.set_title('Findings per tool (all samples)')
        fig.tight_layout()
        fig.savefig(out_png, dpi=150)
        plt.close(fig)
        return
    unpacked = [r for r in rows if r.get('packed') != '1']
    tools = ['BinMind-HFP', 'angr', 'qemu', 'ghidra']
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, group, title in ((axes[0], unpacked, 'unpacked'),
                             (axes[1], packed, 'packed')):
        tp = [sum(1 for r in group if r['tool'] == t
                  and r['verdict'] == 'TP') for t in tools]
        fp = [sum(1 for r in group if r['tool'] == t
                  and r['verdict'] == 'FP') for t in tools]
        x = np.arange(len(tools))
        ax.bar(x - 0.2, tp, 0.4, label='TP', color='#2e86ab')
        ax.bar(x + 0.2, fp, 0.4, label='FP', color='#e07a5f')
        ax.set_xticks(x)
        ax.set_xticklabels(tools, rotation=30, fontsize=8)
        ax.set_title(title)
        ax.legend(fontsize=8)
    fig.suptitle('Packed vs unpacked detection')
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def gen_latex(rows: List[Dict], summary: Dict, out_tex: Path) -> None:
    """[deemo/modules/eval 版] 由 benchmark_summary.json 生成 LaTeX 对比表."""
    tools = ['BinMind-HFP', 'angr', 'qemu', 'ghidra']
    lines = [
        '% Auto-generated by plot_comparison.py',
        r'\begin{table}[t]',
        r'\centering',
        r'\caption{Heap overflow detection comparison across tools.}',
        r'\label{tab:tool_comparison}',
        r'\begin{tabular}{lcccccc}',
        r'\toprule',
        r'Tool & TP & FP & FN & TN & Recall & FPR \\',
        r'\midrule',
    ]
    for t in tools:
        s = summary.get(t, {})
        if s.get('status') == 'unavailable' or not s:
            lines.append(f'{t} & -- & -- & -- & -- & -- & -- \\\\')
            continue
        lines.append(
            f'{TOOL_LABELS.get(t, t)} & {s["tp"]} & {s["fp"]} & '
            f'{s["fn"]} & {s["tn"]} & {s["recall"]:.3f} & '
            f'{s["fpr"]:.3f} \\\\')
    lines += [
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
        '',
    ]
    out_tex.parent.mkdir(parents=True, exist_ok=True)
    out_tex.write_text('\n'.join(lines), encoding='utf-8')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', default=str(ROOT / 'cve_benchmark.csv'))
    ap.add_argument('--out', default=str(ROOT))
    args = ap.parse_args()
    ran = 0

    cve_csv = Path(args.csv)
    if cve_csv.exists():
        rows = load(cve_csv)
        if rows:
            plot(rows, Path(args.out))
            ran += 1
        else:
            print('empty csv, run run_cve_benchmark.py first')

    hfp_csv = RESULTS / 'benchmark_hfp.csv'
    if hfp_csv.exists():
        rows = load_rows(hfp_csv)
        summary = load_summary()
        plot_comparison(rows, RESULTS / 'fig_tool_comparison.png')
        plot_packed_group(rows, RESULTS / 'fig_packed_group.png')
        gen_latex(rows, summary, RESULTS / 'result_table.tex')
        print('figures: fig_tool_comparison.png, fig_packed_group.png')
        print('latex: result_table.tex')
        ran += 1
    else:
        print(f'missing {hfp_csv}; run run_benchmark.py first')

    return 0 if ran else 1


if __name__ == '__main__':
    sys.exit(main())
