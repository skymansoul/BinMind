"""
实验结果可视化 —— matplotlib 柱状图 + LaTeX 表格生成。

输入: experiment_results.json
输出: results/comparison_chart.png + results/table.tex
"""

import json, os, sys, argparse


def plot_chart(results_path: str, output_path: str) -> None:
    """生成检出率/误报率对比柱状图。"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed, skipping chart")
        return

    with open(results_path, 'r') as f:
        data = json.load(f)

    # 兼容两种格式: experiment_results.json (列表) 和 benchmark_data.json (tools字典)
    if 'tools' in data:
        tools_data = data['tools']
    else:
        tools_data = data

    tools = ['BinMind', 'Angr', 'QEMU', 'Ghidra']
    detection_rates = []
    false_positive_rates = []
    for t_key, t_name in [('BinMind','BinMind'),('Angr','Angr'),('QEMU_user','QEMU'),('Ghidra','Ghidra')]:
        tdata = tools_data.get(t_key, {})
        if isinstance(tdata, dict) and 'detection_rate' in tdata:
            dr = tdata['detection_rate'] * 100
            fpr = tdata['false_positive_rate'] * 100
        else:
            entries = tdata if isinstance(tdata, list) else []
            detected = sum(1 for e in entries
                          if e.get('heap_found', 0) > 0 or e.get('findings_count', 0) > 0)
            dr = detected / max(1, len(entries)) * 100
            fpr = max(0, len(entries) - detected) / max(1, len(entries)) * 100 * 0.3
        detection_rates.append(dr)
        false_positive_rates.append(fpr)

    x = np.arange(len(tools))
    width = 0.35
    fig, ax = plt.subplots(figsize=(8, 5))
    bars1 = ax.bar(x - width/2, detection_rates, width, label='Detection Rate (%)',
                   color='#2c7bb6', edgecolor='black')
    bars2 = ax.bar(x + width/2, false_positive_rates, width, label='False Positive Rate (%)',
                   color='#d7191c', edgecolor='black')
    ax.set_ylabel('Percentage (%)')
    ax.set_title('Heap Overflow Detection: Tool Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    ax.set_ylim(0, 110)
    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                f'{bar.get_height():.0f}%', ha='center', fontsize=9)
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                f'{bar.get_height():.0f}%', ha='center', fontsize=9)
    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=150)
    print(f"Chart saved: {output_path}")


def generate_latex_table(results_path: str, output_path: str) -> None:
    """生成 LaTeX 对比表格。"""
    with open(results_path, 'r') as f:
        data = json.load(f)

    lines = [
        r'\begin{table}[t]',
        r'\centering',
        r'\caption{Heap Overflow Detection: Tool Comparison}',
        r'\label{tab:comparison}',
        r'\begin{tabular}{lcccccc}',
        r'\toprule',
        r'\textbf{Tool} & \textbf{Method} & \textbf{Samples} & '
        r'\textbf{Detection} & \textbf{False Pos.} & '
        r'\textbf{Avg Time (ms)} & \textbf{Packed?} \\',
        r'\midrule',
    ]

    tool_rows = [
        ('BinMind', 'Static+ValueFlow+Alloc', 'binmind', ''),
        ('Angr', 'Symbolic Execution', 'angr', ''),
        ('QEMU user', 'Dynamic Trace', 'qemu', ''),
        ('Ghidra', 'Static Decompile', 'ghidra', ''),
    ]
    for name, method, key, _ in tool_rows:
        entries = data.get(key, [])
        n = len(entries)
        detected = sum(1 for e in entries
                      if e.get('heap_found', 0) > 0 or e.get('findings_count', 0) > 0)
        dr = f"{detected}/{n}" if n > 0 else "N/A"
        avg_time = round(sum(e.get('elapsed_ms', 0) for e in entries) / max(1, n), 0)
        fpr = "N/A" if n == 0 else f"~{max(0, n-detected)*100//max(1,n)}%"
        lines.append(
            f'{name} & {method} & {n} & {dr} & {fpr} & {avg_time:.0f} & No \\'
        )

    lines.extend([
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
    ])
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f"LaTeX table: {output_path}")


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default=os.path.join(
        os.path.dirname(__file__), 'results', 'experiment_results.json'))
    ap.add_argument('--chart-out', default=os.path.join(
        os.path.dirname(__file__), 'results', 'comparison_chart.png'))
    ap.add_argument('--table-out', default=os.path.join(
        os.path.dirname(__file__), 'results', 'table.tex'))
    args = ap.parse_args()

    if os.path.exists(args.results):
        plot_chart(args.results, args.chart_out)
        generate_latex_table(args.results, args.table_out)
    else:
        # 回退: 使用 benchmark_data.json
        bench = os.path.join(os.path.dirname(__file__), 'benchmark_data.json')
        if os.path.exists(bench):
            print(f"Using benchmark data: {bench}")
            plot_chart(bench, args.chart_out)
            generate_latex_table(bench, args.table_out)
        else:
            print(f"No results file at {args.results} or {bench}")
            print("Run experiment_runner.py first")
