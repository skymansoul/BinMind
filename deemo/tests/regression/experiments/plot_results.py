"""实验数据可视化 -- 从comparison_results.json生成matplotlib柱状图。"""
import json, sys, os

def load_results(path):
    with open(path) as f:
        return json.load(f)

def plot_comparison(results_path, output_path=None):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed. Install: pip install matplotlib")
        return

    data = load_results(results_path)
    results = data.get('results', [])
    if not results:
        print("No results found")
        return

    by_tool = {}
    for r in results:
        t = r['tool']
        if t not in by_tool:
            by_tool[t] = {'detections': [], 'elapsed': []}
        by_tool[t]['detections'].append(r.get('detections', 0))
        by_tool[t]['elapsed'].append(r.get('elapsed', 0))

    tools = sorted(by_tool.keys())
    avg_det = [sum(by_tool[t]['detections'])/max(len(by_tool[t]['detections']),1) for t in tools]
    avg_time = [sum(by_tool[t]['elapsed'])/max(len(by_tool[t]['elapsed']),1) for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    x = np.arange(len(tools))
    width = 0.5

    ax1.bar(x, avg_det, width, color=['#2196F3','#4CAF50','#FF9800','#9C27B0'][:len(tools)])
    ax1.set_ylabel('Avg Detections')
    ax1.set_title('Detection Rate by Tool')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools)

    ax2.bar(x, avg_time, width, color=['#2196F3','#4CAF50','#FF9800','#9C27B0'][:len(tools)])
    ax2.set_ylabel('Avg Time (s)')
    ax2.set_title('Average Analysis Time')
    ax2.set_xticks(x)
    ax2.set_xticklabels(tools)

    plt.tight_layout()
    out = output_path or os.path.join(os.path.dirname(results_path), 'comparison_chart.png')
    plt.savefig(out, dpi=150)
    print(f'Saved chart to {out}')
    plt.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python plot_results.py <comparison_results.json> [output.png]")
        sys.exit(1)
    plot_comparison(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
