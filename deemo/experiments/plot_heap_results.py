"""堆溢出对比实验可视化 — matplotlib柱状图 + LaTeX表格"""
import json, os, sys
from collections import defaultdict


def load(path):
    with open(path) as f: return json.load(f)


def aggregate(data):
    stats = defaultdict(lambda: {'times': [], 'findings': [], 'fp': [], 'total': 0, 'success': 0})
    for r in data:
        s = stats[r['tool']]
        s['total'] += 1
        if r['success']:
            s['success'] += 1
            s['times'].append(r['time'])
            s['findings'].append(r['findings'])
            s['fp'].append(r['fp'])
    agg = {}
    for tool, s in stats.items():
        n = s['total']
        if n == 0: continue
        agg[tool] = {
            'samples': n, 'success_rate': round(s['success'] / n * 100, 1),
            'avg_time': round(sum(s['times']) / len(s['times']), 1) if s['times'] else 0,
            'total_findings': sum(s['findings']),
            'total_fp': sum(s['fp']),
            'avg_findings': round(sum(s['findings']) / len(s['findings']), 1) if s['findings'] else 0,
        }
    return agg


def plot(agg, out='heap_comparison_chart.png'):
    try:
        import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed"); return
    tools = list(agg.keys())
    colors = ['#2563eb', '#f97316', '#22c55e', '#ef4444']
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    axes[0].bar(tools, [agg[t]['avg_findings'] for t in tools], color=colors[:len(tools)])
    axes[0].set_title('Avg Findings'); axes[0].set_ylabel('Count')
    axes[1].bar(tools, [agg[t]['total_fp'] for t in tools], color=colors[:len(tools)])
    axes[1].set_title('False Positives Filtered')
    axes[2].bar(tools, [agg[t]['avg_time'] for t in tools], color=colors[:len(tools)])
    axes[2].set_title('Avg Time (s)'); axes[2].set_ylabel('Seconds')
    plt.tight_layout(); plt.savefig(out, dpi=150)
    print(f"Chart: {out}")


def latex_table(agg):
    header = (
        "\\begin{table}[htbp]\n\\centering\n"
        "\\caption{Heap Overflow Detection: Tool Comparison}\n"
        "\\label{tab:heap_comparison}\n"
        "\\begin{tabular}{lccccc}\n\\toprule\n"
        "Tool & Samples & Success\\% & Avg Findings & FP Filtered & Time(s) \\\\\\n\\midrule\n"
    )
    rows = ""
    for t in ['Ours', 'Angr', 'Ghidra']:
        a = agg.get(t, {})
        if not a: continue
        rows += (f"{t} & {a.get('samples',0)} & {a.get('success_rate',0)}\\% & "
                 f"{a.get('avg_findings',0)} & {a.get('total_fp',0)} & "
                 f"{a.get('avg_time',0)} \\\\\n")
    footer = "\\bottomrule\n\\end{tabular}\n\\end{table}\n"
    return header + rows + footer


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'comparison_output/heap_comparison.json'
    if os.path.exists(path):
        data = load(path)
        agg = aggregate(data)
        plot(agg)
        tex = latex_table(agg)
        with open('heap_comparison_table.tex', 'w') as f: f.write(tex)
        print("LaTeX: heap_comparison_table.tex")
        for t, s in agg.items():
            print(f"  {t}: {s['samples']} samples, {s['avg_findings']}f avg, {s['total_fp']}fp, {s['avg_time']}s")
    else:
        print(f"No data at {path}")
