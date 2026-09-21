"""分配契约流保持 LaTeX 表生成 — 四工具指标对比 (normal/stripped 两组).

  - 输出可直接编译的 booktabs 表, 两行组 (normal/stripped) × 四工具.
  - 指标: TP/FP/TN/FN, Precision, Recall, F1, AvgMs.
"""

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / 'alloc_contract_results'
TOOLS = ('alloc_contract', 'Angr', 'QEMU', 'Ghidra')


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))['summary']


def row(m: dict, tool: str) -> str:
    return (f'{tool} & {m["tp"]} & {m["fp"]} & {m["tn"]} & {m["fn"]} & '
            f'{m["precision"] * 100:.1f}\\% & {m["recall"] * 100:.1f}\\% & '
            f'{m["f1"]:.3f} & {m["avg_ms"]:.1f} \\\\')


def main():
    normal = load(OUT / 'benchmark_alloc_contract.json')
    stripped = load(OUT / 'benchmark_stripped.json')
    lines = [
        '\\begin{table}[t]',
        '\\centering',
        '\\caption{Heap overflow detection: 分配契约流保持 vs general-purpose tools. '
        '20 samples (15 vulnerable + 5 safe). '
        'QEMU/Ghidra entries are ESTIMATED (tools unavailable on host); '
        '分配契约流保持 and Angr are REAL runs.}',
        '\\label{tab:alloc_contract}',
        '\\begin{tabular}{lcccccccc}',
        '\\toprule',
        '\\multirow{2}{*}{Tool} & \\multicolumn{4}{c}{Confusion} & '
        '\\multicolumn{2}{c}{Rates} & \\multirow{2}{*}{F1} & '
        '\\multirow{2}{*}{Avg ms} \\\\',
        '\\cmidrule(lr){2-5} \\cmidrule(lr){6-7}',
        ' & TP & FP & TN & FN & Prec & Rec & & \\\\',
        '\\midrule',
        '\\multicolumn{9}{l}{\\emph{With symbols (normal, -O0)}} \\\\',
    ]
    for t in TOOLS:
        lines.append(row(normal[t], t))
    lines.append('\\midrule')
    lines.append(
        '\\multicolumn{9}{l}{\\emph{Stripped (no symbols, -O1)}} \\\\')
    for t in TOOLS:
        lines.append(row(stripped[t], t))
    lines += [
        '\\bottomrule',
        '\\end{tabular}',
        '\\end{table}',
    ]
    tex = '\n'.join(lines) + '\n'
    (OUT / 'result_alloc_contract_table.tex').write_text(tex, encoding='utf-8')
    print('saved:', OUT / 'result_alloc_contract_table.tex')


if __name__ == '__main__':
    main()
