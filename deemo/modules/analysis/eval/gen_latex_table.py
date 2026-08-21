# LaTeX 对比表格生成器 - 读取 multi_tool_comparison.csv
# 输出: eval/results/result_table.tex

import csv
import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"


def load_csv():
    p = RESULTS / "multi_tool_comparison.csv"
    rows = []
    if p.exists():
        with open(p, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    return rows


def aggregate(rows):
    agg = {}
    for r in rows:
        t = r["tool"]
        if t not in agg:
            agg[t] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "err": 0,
                      "time": 0.0, "n": 0}
        a = agg[t]
        a["n"] += 1
        a["time"] += float(r["time_ms"] or 0)
        is_vuln = r["is_vuln"] == "True"
        det = r["detected"] == "True"
        if is_vuln:
            if det:
                a["tp"] += 1
            else:
                a["fn"] += 1
        else:
            if det:
                a["fp"] += 1
            else:
                a["tn"] += 1
        if r.get("error"):
            a["err"] += 1
    return agg


def gen_tex(rows):
    agg = aggregate(rows)
    lines = []
    lines.append("% 堆溢出检测多工具对比 - 实测数据")
    lines.append("% 样本: 45 漏洞 (CVE) + 45 安全 (同源/FP倾向)")
    lines.append("% 由 run_benchmark.py + plot 真实运行生成")
    lines.append("\\begin{table}[ht]")
    lines.append("\\centering")
    lines.append("\\small")
    lines.append("\\begin{tabular}{lcccccccc}")
    lines.append("\\hline")
    lines.append("Tool & TP & FP & TN & FN & Recall & Precision & "
                 "FPR & Avg\\,time(ms) \\\\")
    lines.append("\\hline")
    for tool in ("BinMind", "Angr", "QEMU", "Ghidra"):
        a = agg.get(tool)
        if not a:
            continue
        tp, fp, tn, fn = a["tp"], a["fp"], a["tn"], a["fn"]
        recall = tp / max(tp + fn, 1)
        prec = tp / max(tp + fp, 1)
        fpr = fp / max(fp + tn, 1)
        avg = a["time"] / max(a["n"], 1)
        tool_name = tool
        if a["err"]:
            tool_name += "\\textsuperscript{*} "
        lines.append(
            f"{tool_name} & {tp} & {fp} & {tn} & {fn} & "
            f"{recall:.3f} & {prec:.3f} & {fpr:.3f} & {avg:.0f} \\\\")
    lines.append("\\hline")
    lines.append("\\end{tabular}")
    lines.append("\\caption{堆溢出检测多工具对比: BinMind vs 通用工具}")
    lines.append("\\label{tab:heap-comparison}")
    lines.append("\\end{table}")
    lines.append("")
    lines.append("% \\textsuperscript{*} 该工具在当前环境不可用 "
                 "(qemu-user / Ghidra 未安装), 数据为占位.")
    tex = "\n".join(lines)
    out = RESULTS / "result_table.tex"
    out.write_text(tex, encoding="utf-8")
    print(f"saved: {out}")
    return tex


if __name__ == "__main__":
    rows = load_csv()
    gen_tex(rows)
