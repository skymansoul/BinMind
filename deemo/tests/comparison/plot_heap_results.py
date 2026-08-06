#!/usr/bin/env python3
"""堆溢出对比实验可视化 — matplotlib柱状图 + LaTeX表格."""
import json, sys
from collections import defaultdict

def load(path):
    with open(path) as f: return json.load(f)

def plot_chart(data, out='heap_comparison_chart.png'):
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print('matplotlib not installed')
        return

    tools = ['BinMind', 'Angr', 'QEMU', 'Ghidra']
    colors = ['#2196F3', '#FF9800', '#4CAF50', '#9C27B0']
    by_tool = defaultdict(lambda: {'findings': [], 'elapsed': []})
    for r in data:
        t = r['tool']
        if r['success'] and r['findings'] >= 0:
            by_tool[t]['findings'].append(r['findings'])
            by_tool[t]['elapsed'].append(r['elapsed'])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('Heap Overflow Detection — Tool Comparison', fontsize=14)

    avg_f = [sum(by_tool[t]['findings'])/max(len(by_tool[t]['findings']),1) for t in tools]
    b1 = ax1.bar(tools, avg_f, color=colors)
    ax1.set_title('Avg Detections per Sample'); ax1.set_ylabel('Findings')
    for b, v in zip(b1, avg_f): ax1.text(b.get_x()+b.get_width()/2, b.get_height()+0.2, f'{v:.1f}', ha='center')

    avg_t = [sum(by_tool[t]['elapsed'])/max(len(by_tool[t]['elapsed']),1) for t in tools]
    b2 = ax2.bar(tools, avg_t, color=colors)
    ax2.set_title('Avg Analysis Time (s)'); ax2.set_ylabel('Seconds')
    for b, v in zip(b2, avg_t): ax2.text(b.get_x()+b.get_width()/2, b.get_height()+0.02, f'{v:.2f}s', ha='center')

    plt.tight_layout(); plt.savefig(out, dpi=150); print(f'Chart: {out}')

def latex_table(data, out='heap_comparison_table.tex'):
    by_tool = defaultdict(lambda: {'findings': [], 'elapsed': [], 'success': 0})
    for r in data:
        t = r['tool']; by_tool[t]['findings'].append(r['findings'])
        by_tool[t]['elapsed'].append(r['elapsed'])
        if r['success']: by_tool[t]['success'] += 1
    n = len(set(r['sample'] for r in data))

    lines = [r'\begin{table}[h]', r'\centering',
             r'\caption{Heap Overflow Detection: Tool Comparison}',
             r'\label{tab:heap-compare}',
             r'\begin{tabular}{lcccc}',
             r'\hline',
             r'Tool & Samples & Detection Rate & False Positive Rate & Avg Time (s) \\',
             r'\hline']
    for t in ['BinMind', 'Angr', 'QEMU', 'Ghidra']:
        s = by_tool[t]; fl = s['findings']
        avg_f = sum(fl)/max(len(fl),1) if fl else 0
        dr = f'{min(avg_f/n,1.0):.1%}' if n>0 else 'N/A'
        fpr = f'{max(0, avg_f-1)/n:.1%}' if n>0 else 'N/A'
        at = sum(s['elapsed'])/max(len(s['elapsed']),1)
        lines.append(f'  {t} & {n} & {dr} & {fpr} & {at:.2f} \\\\')
    lines.append(r'\hline')
    lines.append(r'\end{tabular}')
    lines.append(r'\end{table}')

    with open(out, 'w') as f: f.write('\n'.join(lines))
    print(f'LaTeX table: {out}')

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'heap_comparison_results.json'
    data = load(path)
    plot_chart(data)
    latex_table(data)
