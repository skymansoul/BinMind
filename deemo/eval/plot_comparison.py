"""论文级对比柱状图 — 四类漏洞 x 四工具 x 双指标.
创建: 2025-08-05
"""
import json, os, sys
try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print('pip install matplotlib numpy'); sys.exit(0)

DATA_PATH = os.path.join(os.path.dirname(__file__), 'benchmark_data.json')
OUTPUT = os.path.join(os.path.dirname(__file__), 'comparison_chart.png')

def plot():
    with open(DATA_PATH) as f: data = json.load(f)
    types = ['heap_overflow', 'uaf', 'format_string', 'stack_overflow']
    tools = data['tools']
    n_types = len(types); n_tools = len(tools)
    x = np.arange(n_types)
    width = 0.2
    colors = ['#2196F3', '#FF9800', '#4CAF50', '#9C27B0']
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    for i, tool in enumerate(tools):
        f1_vals = [data[t]['f1'][i] for t in types]
        fp_vals = [data[t]['fp_rate'][i] for t in types]
        ax1.bar(x + i*width, f1_vals, width, label=tool, color=colors[i], alpha=0.85)
        ax2.bar(x + i*width, fp_vals, width, label=tool, color=colors[i], alpha=0.85)
    
    for ax, title, ylabel in [(ax1, 'F1 Score (higher=better)', 'F1'),
                               (ax2, 'False Positive Rate (lower=better)', 'FP Rate')]:
        ax.set_xticks(x + width * 1.5)
        ax.set_xticklabels([t.replace('_', '\n') for t in types], fontsize=9)
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.legend(fontsize=8, loc='upper right')
        ax.set_ylim(0, 1.05)
    
    plt.tight_layout()
    plt.savefig(OUTPUT, dpi=150, bbox_inches='tight')
    print(f'Saved: {OUTPUT}')

if __name__ == '__main__': plot()
