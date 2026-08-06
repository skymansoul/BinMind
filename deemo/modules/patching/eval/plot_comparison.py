# 对比实验柱状图 — matplotlib绘制检出率/误报率/耗时
"""从 benchmark_results.csv 读取数据，生成论文级对比图 + LaTeX表格。
用法: python eval/plot_comparison.py
输出: eval/comparison_bar.png + eval/result_table.tex
"""
import os, sys, csv, json
from collections import defaultdict
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(EVAL_DIR, "benchmark_results.csv")

def load_csv():
    data = defaultdict(lambda: {"detected": 0, "total": 0, "times": [], "errors": 0})
    if not os.path.exists(CSV_PATH):
        print(f"{CSV_PATH} not found — run run_benchmark.py first")
        return data
    with open(CSV_PATH, newline="") as f:
        for row in csv.DictReader(f):
            t = row["tool"]; data[t]["total"] += 1
            data[t]["times"].append(float(row.get("time_secs", 0)))
            if row.get("error") and row["error"] != "" and row["error"] != "None":
                data[t]["errors"] += 1
            if row.get("detected", "").lower() == "true":
                data[t]["detected"] += 1
    return data

def plot(data, out_path):
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed"); return
    tools = sorted(data.keys())
    rates = [data[t]["detected"]/data[t]["total"]*100 if data[t]["total"]>0 else 0 for t in tools]
    times = [sum(data[t]["times"])/len(data[t]["times"]) if data[t]["times"] else 0 for t in tools]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))
    colors = ["#2c7bb6","#fdae61","#d7191c","#4daf4a"]
    ax1.bar(tools, rates, color=colors[:len(tools)])
    ax1.set_ylabel("Detection Rate (%)"); ax1.set_title("Heap Overflow Detection Rate")
    for i, v in enumerate(rates): ax1.text(i, v+0.5, f"{v:.0f}%", ha="center", fontsize=10)
    ax2.bar(tools, times, color=colors[:len(tools)])
    ax2.set_ylabel("Avg Time (s)"); ax2.set_title("Average Analysis Time per Sample")
    for i, v in enumerate(times): ax2.text(i, v+0.1, f"{v:.1f}s", ha="center", fontsize=9)
    plt.tight_layout(); plt.savefig(out_path, dpi=300); print(f"Chart: {out_path}")

def latex_table(data, out_path):
    rows = []
    for t in sorted(data.keys()):
        d = data[t]; n = d["total"]
        rate = d["detected"]/n*100 if n>0 else 0
        avg_t = sum(d["times"])/len(d["times"]) if d["times"] else 0
        rows.append(f"    {t} & {n} & {rate:.1f}\\% & {avg_t:.1f}s & {d['errors']} \\\\")
    tbl = "\\begin{table}[t]\n\\centering\n\\caption{Tool Comparison on Heap Overflow CVE Samples}\n"
    tbl += "\\begin{tabular}{lcccc}\n\\toprule\n"
    tbl += "Tool & Samples & Detection Rate & Avg Time & Errors \\\\\n\\midrule\n"
    tbl += "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n\\end{table}"
    with open(out_path, "w") as f: f.write(tbl)
    print(f"LaTeX: {out_path}")

if __name__ == "__main__":
    data = load_csv()
    if data:
        plot(data, os.path.join(EVAL_DIR, "comparison_bar.png"))
        latex_table(data, os.path.join(EVAL_DIR, "result_table.tex"))
