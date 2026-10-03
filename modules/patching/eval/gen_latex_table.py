# 生成LaTeX对比表格 — 从benchmark_summary.json生成result_table.tex
"""输出完整指标的LaTeX三线表。
含加壳/未加壳分组的各工具指标。
用法: python eval/gen_latex_table.py
"""

import os, json

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
SUMMARY_PATH = os.path.join(EVAL_DIR, 'benchmark_summary.json')
OUT_TEX = os.path.join(EVAL_DIR, 'result_table.tex')


def main():
    with open(SUMMARY_PATH, encoding='utf-8') as f:
        summary = json.load(f)

    tools = summary.get('tools', {})
    if not tools:
        print("No summary data")
        return 1

    lines = []
    lines.append('% 自动生成: Heap Overflow Detection Benchmark')
    lines.append('\\begin{table}[t]')
    lines.append('\\centering')
    lines.append('\\caption{Heap Overflow Detection on %d CVE Samples '
                 '(%d vulnerable, %d safe)}' % (
                     summary['total_samples'],
                     summary['tp_expected'], summary['fp_expected']))
    lines.append('\\label{tab:heap-benchmark}')
    lines.append('\\begin{tabular}{lccccc}')
    lines.append('\\toprule')
    lines.append('Tool & Variant & Recall & FP Rate & Precision & Time (s) \\\\')
    lines.append('\\midrule')

    order = ['BinMind', 'Angr', 'QEMU+Trace', 'Ghidra']
    for tool in order:
        if tool not in tools:
            continue
        variants = tools[tool]
        for variant in ('plain', 'packed'):
            if variant not in variants:
                continue
            v = variants[variant]
            lines.append(
                '%s & %s & %.1f\\%% & %.1f\\%% & %.1f\\%% & %.2f \\\\' % (
                    tool.replace('_', '\\_'), variant,
                    v['recall_pct'], v['fp_rate_pct'],
                    v['precision_pct'], v['avg_time']))
            if variant == 'plain' and tool != order[-1]:
                pass
        if tool != order[-1]:
            pass
    lines.append('\\midrule')
    lines.append('\\multicolumn{6}{l}{\\emph{Recall: TP detected / vulnerable '
                 'samples; FP Rate: false alarms on safe samples}} \\\\')
    lines.append('\\bottomrule')
    lines.append('\\end{tabular}')
    lines.append('\\end{table}')

    with open(OUT_TEX, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"Saved: {OUT_TEX}")
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
