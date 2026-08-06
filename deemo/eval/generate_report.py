# 统一对比报告生成器 —— 读取benchmark CSV, 生成LaTeX表格+matplotlib图表。
# 创建: 自主执行轮次

import os, csv, json, sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))


def read_csv(csv_path: str = None) -> list:
    """读取benchmark CSV, 返回行列表。"""
    cp = csv_path or os.path.join(EVAL_DIR, "benchmark_results.csv")
    if not os.path.exists(cp):
        return []
    with open(cp, "r") as f:
        return list(csv.DictReader(f))


def aggregate(rows: list) -> dict:
    """按工具聚合指标。"""
    tools = {}
    for r in rows:
        t = r.get("tool", "unknown")
        if t not in tools:
            tools[t] = {"total": 0, "detected": 0, "times": [], "fps": 0}
        tools[t]["total"] += 1
        tools[t]["detected"] += int(r.get("detected", 0))
        try:
            tools[t]["times"].append(float(r.get("duration_sec", 0)))
        except ValueError:
            pass
    for t in tools:
        d = tools[t]
        d["rate"] = round(d["detected"] / max(d["total"], 1), 3)
        d["avg_time"] = round(sum(d["times"]) / max(len(d["times"]), 1), 2)
    return tools


def generate_latex(aggregated: dict, output_path: str = None) -> str:
    """从聚合数据生成LaTeX对比表格。"""
    op = output_path or os.path.join(EVAL_DIR, "result_table.tex")
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Multi-Tool Benchmark: Heap Overflow Detection}",
        r"\label{tab:benchmark}",
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        r"Tool & Samples & Detection Rate & FP Rate & Avg Time(s) & Peak Mem(MB) \\",
        r"\midrule",
    ]
    for tool, stats in sorted(aggregated.items()):
        lines.append(
            f"{tool} & {stats['total']} & {stats['rate']:.1%} & "
            f"{stats.get('fp_rate', 0):.1%} & {stats['avg_time']:.1f} & "
            f"{stats.get('peak_mem', 0):.0f} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    latex = "\n".join(lines)
    with open(op, "w") as f:
        f.write(latex)
    return latex


def generate_plot(aggregated: dict, output_path: str = None) -> str:
    """生成matplotlib对比柱状图。"""
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        return "matplotlib not installed"

    op = output_path or os.path.join(EVAL_DIR, "comparison.png")
    tools = list(aggregated.keys())
    rates = [aggregated[t]["rate"] * 100 for t in tools]
    times = [aggregated[t]["avg_time"] for t in tools]
    colors = ['#2ecc71' if 'BinMind' in t else '#3498db' for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    ax1.bar(tools, rates, color=colors)
    ax1.set_ylabel('Detection Rate (%)'); ax1.set_title('Detection Rate')
    ax1.set_ylim(0, 100)
    for i, v in enumerate(rates): ax1.text(i, v + 1, f'{v:.0f}%', ha='center')
    ax2.bar(tools, times, color=colors)
    ax2.set_ylabel('Avg Time (s)'); ax2.set_title('Average Scan Time')
    for i, v in enumerate(times): ax2.text(i, v + 0.3, f'{v:.1f}s', ha='center')
    plt.tight_layout()
    plt.savefig(op, dpi=150); plt.close()
    return op


if __name__ == "__main__":
    rows = read_csv()
    if rows:
        agg = aggregate(rows)
        print(json.dumps({t: {k: v for k, v in s.items() if k != 'times'}
                         for t, s in agg.items()}, indent=2))
        latex = generate_latex(agg)
        print(f"LaTeX: {len(latex)} chars")
        plot = generate_plot(agg)
        print(f"Plot: {plot}")
    else:
        print("No benchmark data yet. Run run_benchmark.py first to generate CSV.")
        # Generate template with placeholders
        dummy = {"BinMind": {"total": 25, "rate": 0.0, "avg_time": 0.0},
                 "Angr": {"total": 25, "rate": 0.0, "avg_time": 0.0},
                 "QEMU": {"total": 25, "rate": 0.0, "avg_time": 0.0},
                 "Ghidra": {"total": 25, "rate": 0.0, "avg_time": 0.0}}
        latex = generate_latex(dummy)
        print(f"Template LaTeX generated: {len(latex)} chars")
