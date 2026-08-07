"""生成 LaTeX 对比表 — 从 benchmark_summary.json 输出 result_table.tex.

创建: 2026-07-27
输出列: 工具 | 检出数 | 误报数 | 漏报数 | Recall | Precision | F1 | FP率 | 总耗时
用法:
  python gen_result_table.py [--results <dir>] [--out <file>]
"""

import argparse
import json
from pathlib import Path

_HERE = Path(__file__).resolve().parent

_TOOL_LABELS = {
    'acpe': r'\textbf{ACPE (ours)}',
    'baseline': 'Baseline (DP-TVRA)',
    'angr': 'Angr (CFG)',
    'qemu': 'QEMU runtime trace',
    'ghidra': 'Ghidra headless (sim.)',
}


def tex_cell(v, bold_max=True):
    return f'{v:.3f}'


def generate(summary: dict) -> str:
    lines = []
    lines.append('% 多工具堆溢出检测对比表 (ACPE benchmark, 46 binaries)')
    lines.append('% 样本: 15 CVE 复现 + 8 良性对照 × 2 编译档 (O0/O2)')
    lines.append('\\begin{table}[t]')
    lines.append('\\centering')
    lines.append('\\caption{Heap-Overflow Detection: ACPE vs. Baseline and '
                 'General-Purpose Tools. Recall/P/F1 at sample level.}')
    lines.append('\\label{tab:acpe-comparison}')
    lines.append('\\small')
    lines.append('\\begin{tabular}{lrrrrrrrr}')
    lines.append('\\hline')
    lines.append('Tool & TP & FP & FN & Recall & Precision & F1 '
                 '& FP rate & Time(s) \\\\')
    lines.append('\\hline')

    def fmt(x):
        return f'{x:.3f}'

    best_f1 = max(summary[t]['f1'] for t in _TOOL_LABELS)
    for tool in _TOOL_LABELS:
        m = summary[tool]
        name = _TOOL_LABELS[tool]
        if tool == 'acpe':
            line = (f'  {name} & {m["tp"]} & {m["fp"]} & {m["fn"]} '
                    f'& {fmt(m["recall"])} & {fmt(m["precision"])} '
                    f'& {fmt(m["f1"])} & {fmt(m["fp_rate"])} '
                    f'& {m["total_sec"]:.2f} \\\\')
        else:
            line = (f'  {name} & {m["tp"]} & {m["fp"]} & {m["fn"]} '
                    f'& {fmt(m["recall"])} & {fmt(m["precision"])} '
                    f'& {fmt(m["f1"])} & {fmt(m["fp_rate"])} '
                    f'& {m["total_sec"]:.2f} \\\\')
        lines.append(line)
    lines.append('\\hline')
    lines.append('\\end{tabular}')
    lines.append('\\end{table}')
    return '\n'.join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default='results')
    ap.add_argument('--out', default='result_table.tex')
    args = ap.parse_args()
    results = _HERE / args.results
    summary = json.loads(
        (results / 'benchmark_summary.json').read_text(encoding='utf-8'))
    out = _HERE / args.out
    out.write_text(generate(summary), encoding='utf-8')
    print(f'[tex] {out}')


if __name__ == '__main__':
    main()
