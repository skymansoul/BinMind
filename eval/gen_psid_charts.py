#!/usr/bin/env python3
"""生成PSID消融实验可视化图表和LaTeX表格."""
import json, os, sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
RESULTS_DIR = _BASE / "eval" / "results"

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


def load_results():
    micro_path = RESULTS_DIR / "ablation_micro.json"
    ablation_path = RESULTS_DIR / "ablation_interval.json"

    micro = json.loads(micro_path.read_text()) if micro_path.exists() else []
    ablation = json.loads(ablation_path.read_text()) if ablation_path.exists() else {}
    return micro, ablation


def plot_micro_benchmark(micro):
    """微基准: 约束求解 vs 约束求解+Interval 对比柱状图."""
    if not micro:
        return

    tests = [m["test"] for m in micro]
    cj_constr = [m["cj_constraints"] for m in micro]
    iv_constr = [m["iv_constraints"] for m in micro]

    x = np.arange(len(tests))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    bars1 = ax.bar(x - width/2, cj_constr, width, label='CJ', color='#4C72B0', edgecolor='white')
    bars2 = ax.bar(x + width/2, iv_constr, width, label='CJ+Interval', color='#55A868', edgecolor='white')

    for bar in bars1:
        h = bar.get_height()
        ax.annotate(f'{int(h)}', xy=(bar.get_x() + bar.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9)
    for bar in bars2:
        h = bar.get_height()
        ax.annotate(f'{int(h)}', xy=(bar.get_x() + bar.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9)

    verdict_map = {"proven_safe": "SAFE", "inconclusive": "INC", "proven_overflow": "OVF"}
    for i, m in enumerate(micro):
        cj_v = verdict_map.get(m["cj_verdict"], m["cj_verdict"][:4])
        iv_v = verdict_map.get(m["iv_verdict"], m["iv_verdict"][:4])
        color_cj = "#55A868" if cj_v == "SAFE" else ("#C44E52" if cj_v == "OVF" else "#DD8452")
        color_iv = "#55A868" if iv_v == "SAFE" else ("#C44E52" if iv_v == "OVF" else "#DD8452")
        ax.text(x[i] - width/2, -1.5, cj_v, ha='center', fontsize=7, color=color_cj, fontweight='bold')
        ax.text(x[i] + width/2, -1.5, iv_v, ha='center', fontsize=7, color=color_iv, fontweight='bold')

    ax.set_ylabel('Constraint Count', fontsize=12)
    ax.set_title('PSID Micro-Benchmark: CJ vs CJ+Interval Constraint Precision', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels([t.replace("-", "\n") for t in tests], fontsize=8)
    ax.legend(fontsize=11)
    ax.set_ylim(-3, max(max(cj_constr), max(iv_constr)) + 3)

    plt.tight_layout()
    out = RESULTS_DIR / "psid_micro_benchmark.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Chart: {out}")


def plot_verdict_comparison(micro):
    """判定结果对比: 桑基图/流向图."""
    if not micro:
        return

    improved = sum(1 for m in micro if m["improved"])
    unchanged = len(micro) - improved

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    labels = ['Improved\n(INC→SAFE)', 'Unchanged']
    sizes = [improved, unchanged]
    colors = ['#55A868', '#DD8452']
    ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%',
            startangle=90, textprops={'fontsize': 11})
    ax1.set_title(f'PSID Impact: {improved}/{len(micro)} Tests Improved', fontsize=13)

    new_constrs = [m["new_constraints"] for m in micro]
    test_names = [m["test"].split("-")[0] for m in micro]
    colors2 = ['#55A868' if m["improved"] else '#DD8452' for m in micro]
    ax2.barh(test_names, new_constrs, color=colors2, edgecolor='white')
    for i, v in enumerate(new_constrs):
        ax2.text(v + 0.1, i, str(v), va='center', fontsize=10)
    ax2.set_xlabel('New Constraints Injected', fontsize=11)
    ax2.set_title('PSID Constraint Injection by Test', fontsize=13)
    ax2.invert_yaxis()

    plt.tight_layout()
    out = RESULTS_DIR / "psid_verdict_comparison.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Chart: {out}")


def generate_latex_table(micro, ablation):
    """生成LaTeX结果表格."""
    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{PSID Micro-Benchmark: Interval Domain Precision Enhancement}")
    lines.append(r"\label{tab:psid-micro}")
    lines.append(r"\begin{tabular}{llccccc}")
    lines.append(r"\toprule")
    lines.append(r"Test & Scenario & CJ Const & IV Const & $\Delta$ & CJ Verdict & IV Verdict \\")
    lines.append(r"\midrule")

    verdict_map = {
        "proven_safe": "SAFE",
        "inconclusive": "INCONCL.",
        "proven_overflow": "OVERFLOW",
    }

    for m in micro:
        delta = m["iv_constraints"] - m["cj_constraints"]
        scenario = m["test"].split("-", 1)[1] if "-" in m["test"] else m["test"]
        cj_v = verdict_map.get(m["cj_verdict"], m["cj_verdict"])
        iv_v = verdict_map.get(m["iv_verdict"], m["iv_verdict"])
        improved_mark = r" \checkmark" if m["improved"] else ""
        lines.append(
            f"{m['test'].split('-')[0]} & {scenario} & "
            f"{m['cj_constraints']} & {m['iv_constraints']} & "
            f"+{delta} & {cj_v} & \\textbf{{{iv_v}}}{improved_mark} \\\\"
        )

    lines.append(r"\midrule")
    total_new = sum(m["new_constraints"] for m in micro)
    improved_count = sum(1 for m in micro if m["improved"])
    lines.append(
        f"\\multicolumn{{7}}{{c}}{{Improved: {improved_count}/{len(micro)}, "
        f"New constraints: {total_new}}} \\\\"
    )
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    out = RESULTS_DIR / "psid_result_table.tex"
    out.write_text("\n".join(lines), encoding='utf-8')
    print(f"LaTeX: {out}")


def generate_ablation_latex(ablation):
    """生成消融实验LaTeX表格."""
    metrics = ablation.get("metrics", {})
    if not metrics:
        return

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Ablation Study: Baseline vs CJ vs CJ+Interval (40 CVE Samples)}")
    lines.append(r"\label{tab:ablation-interval}")
    lines.append(r"\begin{tabular}{lcccccccc}")
    lines.append(r"\toprule")
    lines.append(r"Config & TP & FP & TN & FN & Precision & Recall & F1 & FPR \\")
    lines.append(r"\midrule")

    for cfg in ["Baseline", "CJ", "CJ+Interval"]:
        m = metrics.get(cfg, {})
        if not m:
            continue
        lines.append(
            f"{cfg} & {m['tp']} & {m['fp']} & {m['tn']} & {m['fn']} & "
            f"{m['precision']:.4f} & {m['recall']:.4f} & "
            f"{m['f1']:.4f} & {m['fpr']:.4f} \\\\"
        )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    out = RESULTS_DIR / "ablation_interval_table.tex"
    out.write_text("\n".join(lines), encoding='utf-8')
    print(f"LaTeX: {out}")


if __name__ == '__main__':
    print("[Visualize] Loading results...")
    micro, ablation = load_results()

    if micro:
        print(f"  Micro-benchmarks: {len(micro)} tests")
        plot_micro_benchmark(micro)
        plot_verdict_comparison(micro)
        generate_latex_table(micro, ablation)
    else:
        print("  No micro-benchmark results found. Run ablation_interval.py first.")

    if ablation.get("metrics"):
        generate_ablation_latex(ablation)
    else:
        print("  No ablation metrics found.")

    print("[Visualize] Done.")
