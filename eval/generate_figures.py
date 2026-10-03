# 从benchmark CSV(宽格式)生成LaTeX表格和matplotlib图表
import csv, os
from collections import defaultdict

base = os.path.dirname(os.path.abspath(__file__))
rows = list(csv.DictReader(open(os.path.join(base, 'benchmark_results.csv'))))

# CSV是宽格式: sample, ground_truth, BinMind_time, BinMind_findings, BinMind_status, Angr_time, ...
tools = ['BinMind', 'Angr', 'QEMU', 'Ghidra']
stats = {t: {'total':0,'hits':0,'time':0.0} for t in tools}

for r in rows:
    for t in tools:
        findings = r.get(f'{t}_detections', r.get(f'{t}_findings', '0'))
        time_val = r.get(f'{t}_elapsed', r.get(f'{t}_time', '0'))
        try:
            stats[t]['total'] += 1
            stats[t]['time'] += float(time_val)
            if int(findings) > 0:
                stats[t]['hits'] += 1
        except (ValueError, TypeError):
            pass

# LaTeX
lines = [r'\begin{table}[htbp]', r'\centering',
    r'\caption{Heap Overflow Detection: Tool Comparison on %d Samples}' % len(rows),
    r'\label{tab:heap_comparison}',
    r'\begin{tabular}{lccccc}', r'\toprule',
    r'Tool & Samples & Detected & DetectRate & AvgFindings & AvgTime(s) \\',
    r'\midrule']
for t in tools:
    s = stats[t]; n = s['total']
    dr = s['hits']/max(1,n)*100
    det_col = f'{t}_detections'
    avg_f = sum(int(r.get(det_col, r.get(f'{t}_findings','0') or '0')) for r in rows)/max(1,n)
    avg_t = s['time']/max(1,n)
    lines.append(f'{t} & {n} & {s["hits"]} & {dr:.0f}\\% & {avg_f:.1f} & {avg_t:.2f} \\\\')
lines.extend([r'\bottomrule', r'\end{tabular}', r'\end{table}'])
with open(os.path.join(base, 'result_table.tex'), 'w') as f:
    f.write('\n'.join(lines))
print(f'LaTeX table: eval/result_table.tex ({len(rows)} samples)')

# Plot
try:
    import matplotlib; matplotlib.use('Agg')
    import matplotlib.pyplot as plt; import numpy as np
    t_names = tools
    dr = [stats[t]['hits']/max(1,stats[t]['total'])*100 for t in t_names]
    avg_t = [stats[t]['time']/max(1,stats[t]['total']) for t in t_names]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    colors = ['#2196F3', '#FF5722', '#4CAF50', '#FFC107']
    ax1.bar(t_names, dr, color=colors)
    ax1.set_ylabel('Detection Rate (%)'); ax1.set_title('Detection Rate by Tool')
    for i,v in enumerate(dr): ax1.text(i, v+1, f'{v:.0f}%', ha='center')
    ax2.bar(t_names, avg_t, color=colors)
    ax2.set_ylabel('Avg Time (s)'); ax2.set_title('Average Analysis Time by Tool')
    for i,v in enumerate(avg_t): ax2.text(i, v+0.1, f'{v:.1f}s', ha='center')
    plt.tight_layout()
    plt.savefig(os.path.join(base, 'comparison.pdf'), dpi=150)
    print('Plot: eval/comparison.pdf')
except ImportError:
    print('matplotlib not installed')
