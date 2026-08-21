#!/usr/bin/env python3
# 生成 LaTeX 对比表格 — 读 benchmark_summary.json → result_table.tex.

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def gen(summary: dict) -> str:
    order = ["BinMind-DDSSC", "BinMind-Baseline", "angr", "Ghidra",
             "QEMU/Unicorn"]
    lines = [
        "% 多工具堆溢出检测对比表 (自动生成)",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\small",
        "\\caption{堆溢出静态检测对比: 召回率(Recall), 精确率(Precision), "
        "误报率(FPR), F1, 平均耗时, 峰值内存. "
        "BinMind-DDSSC 为本方法(PCST+BWR+多阶段过滤); "
        "BinMind-Baseline 为关闭PCST/BWR的旧语义基线.}",
        "\\label{tab:heap-benchmark}",
        "\\begin{tabular}{lcccccc}",
        "\\hline",
        "工具 & TP & FP & Recall(\\%) & Precision(\\%) & FPR(\\%) & F1 \\\\",
        "\\hline",
    ]
    for t in order:
        if t not in summary:
            continue
        s = summary[t]
        lines.append(
            f"  {t.replace('_', '\\_')} & {s['TP']} & {s['FP']} & "
            f"{s['Recall']:.1f} & {s['Precision']:.1f} & {s['FPR']:.1f} & "
            f"{s['F1']:.4f} \\\\")
    lines += [
        "\\hline",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return "\n".join(lines)


def main():
    summary_path = ROOT / "benchmark_summary.json"
    if not summary_path.exists():
        print("benchmark_summary.json not found; run run_benchmark.py first")
        return
    with open(summary_path, encoding="utf-8") as f:
        summary = json.load(f)
    out = ROOT / "result_table.tex"
    out.write_text(gen(summary), encoding="utf-8")
    print(f"[latex] {out}")


if __name__ == "__main__":
    main()
