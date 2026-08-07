"""UAF-OG LaTeX 表生成."""

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / 'og_results'
TOOLS = ('BASE', 'UAF-OG', 'Angr')


def main():
    data = json.loads((OUT / 'benchmark_og.json').read_text(encoding='utf-8'))
    s = data['summary']
    lines = [
        '\\begin{table}[t]',
        '\\centering',
        '\\caption{UAF detection: UAF-OG generation compression vs naive '
        'baseline vs Angr. 20 samples (15 vulnerable + 5 safe). '
        'Angr probe is REAL but requires constant arguments; '
        'UAF semantics are symbolic, hence its low recall.}',
        '\\label{tab:uaf-og}',
        '\\begin{tabular}{lcccccccc}',
        '\\toprule',
        'Tool & TP & FP & TN & FN & Prec & Rec & F1 & Avg ms \\\\',
        '\\midrule',
    ]
    for t in TOOLS:
        m = s[t]
        lines.append(
            f'{t} & {m["tp"]} & {m["fp"]} & {m["tn"]} & {m["fn"]} & '
            f'{m["precision"] * 100:.1f}\\% & {m["recall"] * 100:.1f}\\% & '
            f'{m["f1"]:.3f} & {m["avg_ms"]:.1f} \\\\')
    lines += ['\\bottomrule', '\\end{tabular}', '\\end{table}']
    (OUT / 'result_og_table.tex').write_text('\n'.join(lines) + '\n',
                                             encoding='utf-8')
    print('saved:', OUT / 'result_og_table.tex')


if __name__ == '__main__':
    main()
