# UAF LaTeX 对比表格生成器 - 从 uaf_benchmark.json 聚合工具指标.
#
# 决策逻辑:
#   对每个工具计算 TP/FP/FN/TN, Recall, Precision, FPR, F1,
#   输出 LaTeX booktabs 表格. 未运行工具 (全部 NA) 标注 n/a.
#

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCH_JSON = ROOT / "results" / "uaf_benchmark.json"
OUT_TEX = ROOT / "uaf_result_table.tex"

TOOL_ORDER = ["BinMind-UAF-ULPR", "BinMind-UAF-Base", "angr-uaf"]


def _metrics(rows):
    rows = [r for r in rows if r.get("verdict") != "NA"]
    tp = sum(1 for r in rows if r.get("verdict") == "TP")
    fp = sum(1 for r in rows if r.get("verdict") == "FP")
    fn = sum(1 for r in rows if r.get("verdict") == "FN")
    tn = sum(1 for r in rows if r.get("verdict") == "TN")
    n = len(rows)
    if n == 0:
        return None
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    f1 = (2 * prec * recall / (prec + recall)) if (prec + recall) \
        else float("nan")
    avg_t = sum(r.get("time_ms", 0) for r in rows) / n
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": recall, "prec": prec, "fpr": fpr, "f1": f1,
            "avg_t": avg_t, "n": n}


def _fmt(v, digits=3):
    if v != v:
        return "n/a"
    return f"{v:.{digits}f}"


def generate() -> str:
    rows = json.loads(BENCH_JSON.read_text(encoding="utf-8"))
    lines = [
        "\\begin{table}[h]",
        "\\centering",
        "\\caption{Multi-Tool Use-After-Free Detection Benchmark "
        "(15 vulnerable + 5 safe samples, O0+O2)}",
        "\\label{tab:uaf_benchmark}",
        "\\begin{tabular}{lrrrrrrrrrr}",
        "\\toprule",
        "Tool & TP & FP & FN & TN & Recall & Prec. & FPR & F1 "
        "& Time(ms) \\\\",
        "\\midrule",
    ]
    for tool in TOOL_ORDER:
        trows = [r for r in rows if r.get("tool") == tool]
        m = _metrics(trows)
        if m is None:
            lines.append(f"{tool} & - & - & - & - & n/a & n/a & n/a & n/a "
                         f"& n/a \\\\")
            continue
        lines.append(
            f"{tool} & {m['tp']} & {m['fp']} & {m['fn']} & {m['tn']} "
            f"& {_fmt(m['recall'])} & {_fmt(m['prec'])} "
            f"& {_fmt(m['fpr'])} & {_fmt(m['f1'])} "
            f"& {_fmt(m['avg_t'], 1)} \\\\")
    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    tex = "\n".join(lines)
    OUT_TEX.write_text(tex, encoding="utf-8")
    print(f"uaf result table -> {OUT_TEX}")
    return tex


if __name__ == "__main__":
    generate()
