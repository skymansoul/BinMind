"""LaTeX 对比表格生成 — 从基准报告生成多工具对比 LaTeX 表格.

创建: 2025-03-28
"""

from datetime import datetime
from pathlib import Path

from .plot_data import COLORS


def generate_latex(report: dict, output_path: str = None, results_dir=None):
    """生成 LaTeX 对比表格 (指标表 + 加速比表)."""
    tools = report.get('tools', [])
    if not tools:
        return None

    lines = [
        f'% 多工具对比表格 — 自动生成于 {datetime.now().strftime("%Y-%m-%d %H:%M")}',
        r'\begin{table}[htbp]',
        r'  \centering',
        r'  \caption{Multi-Tool Vulnerability Detection Comparison}',
        r'  \label{tab:multitool}',
        r'  \begin{tabular}{lcccccr}',
        r'    \toprule',
        r'    \textbf{Tool} & \textbf{Recall} & \textbf{Precision} '
        r'& \textbf{F1} & \textbf{Time (ms)} & \textbf{Mode} \\',
        r'    \midrule',
    ]

    for t in tools:
        name = t['tool'].replace('_', r'\_')
        recall = f"{t['recall']:.1f}\\%"
        precision = f"{t['precision']:.1f}\\%"
        f1 = f"{t['f1']:.1f}"
        time_ms = f"{t['avg_time_ms']:.1f}"
        mode = t.get('mode', '—')

        if any(k in t['tool'] for k in
               ('AVHO-G', 'UAF-', 'Fmt-', 'Int-')):
            lines.append(r'    \rowcolor{blue!10}')
            lines.append(rf'    \textbf{{{name}}} & \textbf{{{recall}}} & '
                        rf'\textbf{{{precision}}} & \textbf{{{f1}}} & '
                        rf'\textbf{{{time_ms}}} & \textbf{{{mode}}} \\')
        else:
            lines.append(rf'    {name} & {recall} & {precision} & '
                        rf'{f1} & {time_ms} & {mode} \\')

    lines.extend([r'    \bottomrule', r'  \end{tabular}', r'\end{table}', ''])

    # 加速比表
    lines.extend([
        '% 加速比分析', r'\begin{table}[htbp]', r'  \centering',
        r'  \caption{Analysis Speed Comparison}',
        r'  \label{tab:speedup}',
        r'  \begin{tabular}{lcc}', r'    \toprule',
        r'    \textbf{Tool} & \textbf{Time (ms)} & \textbf{Speedup} \\',
        r'    \midrule',
    ])

    baseline_ms = tools[0]['avg_time_ms'] if tools else 1
    for t in tools:
        name = t['tool'].replace('_', r'\_')
        time_ms = f"{t['avg_time_ms']:.1f}"
        speedup = t['avg_time_ms'] / baseline_ms if baseline_ms > 0 else 1
        speedup_str = f"{speedup:.0f}$\\times$" if speedup > 1 \
            else "1$\\times$ (baseline)"

        if any(k in t['tool'] for k in
               ('AVHO-G', 'UAF-', 'Fmt-', 'Int-')):
            lines.append(r'    \rowcolor{blue!10}')
            lines.append(rf'    \textbf{{{name}}} & \textbf{{{time_ms}}} & '
                        rf'\textbf{{{speedup_str}}} \\')
        else:
            lines.append(rf'    {name} & {time_ms} & {speedup_str} \\')

    lines.extend([r'    \bottomrule', r'  \end{tabular}', r'\end{table}'])

    latex = '\n'.join(lines)

    out_dir = Path(results_dir or Path(__file__).resolve().parent / 'results')
    out_dir.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = str(out_dir / f'result_table_{ts}.tex')
    else:
        output_path = str(output_path)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(latex)
    print(f'LaTeX: {output_path}')
    return output_path
