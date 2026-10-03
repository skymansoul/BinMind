"""对比实验柱状图 — matplotlib 绘制检出率/误报率/耗时."""

import json
import os
import sys


def load_results(results_path: str) -> dict:
    """加载实验结果 JSON."""
    with open(results_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def plot_comparison(results: dict, output_path: str) -> None:
    """绘制三组柱状图 (检出率/误报率/平均耗时)."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.rcParams['font.size'] = 11
    except ImportError:
        print('matplotlib not installed. Install with: pip install matplotlib')
        return

    by_tool = results.get('by_tool', {})
    if not by_tool:
        print('No results to plot.')
        return

    tools = list(by_tool.keys())
    metrics_f1 = [by_tool[t].get('F1', 0) for t in tools]
    metrics_prec = [by_tool[t].get('precision', 0) for t in tools]
    metrics_rec = [by_tool[t].get('recall', 0) for t in tools]
    metrics_time = [by_tool[t].get('avg_time_s', 0) for t in tools]
    metrics_fp = [1.0 - by_tool[t].get('precision', 0) for t in tools]

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))

    # 图1: 检出率 (F1, Precision, Recall)
    x = range(len(tools))
    w = 0.25
    axes[0].bar([i - w for i in x], metrics_f1, w, label='F1', color='#2196F3')
    axes[0].bar(x, metrics_prec, w, label='Precision', color='#4CAF50')
    axes[0].bar([i + w for i in x], metrics_rec, w, label='Recall', color='#FF9800')
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(tools)
    axes[0].set_ylabel('Score')
    axes[0].set_title('Detection Accuracy')
    axes[0].legend(fontsize=9)
    axes[0].set_ylim(0, 1.05)

    # 图2: 误报率
    axes[1].bar(tools, metrics_fp, color='#f44336', width=0.5)
    axes[1].set_ylabel('False Positive Rate')
    axes[1].set_title('False Positive Rate')

    # 图3: 平均耗时
    axes[2].bar(tools, metrics_time, color='#9C27B0', width=0.5)
    axes[2].set_ylabel('Avg Time (seconds)')
    axes[2].set_title('Average Analysis Time')

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f'Chart saved to {output_path}')


if __name__ == '__main__':
    results_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              'results', 'comparison.json')
    if not os.path.exists(results_dir):
        print(f'No results found at {results_dir}. Run run_experiment.py first.')
        sys.exit(1)
    data = load_results(results_dir)
    output = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                         'results', 'comparison_chart.png')
    plot_comparison(data, output)
