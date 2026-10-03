"""UAF-OG LaTeX 表生成."""

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / 'og_results'
TOOLS = ('BASE', 'UAF-OG', 'Angr')


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))['summary']


def row(m: dict, tool: str) -> str:
    return (f'{tool} & {m["tp"]} & {m["fp"]} & {m["tn"]} & {m["fn"]} & '
            f'{m["precision"] * 100:.1f}\\% & {m["recall"] * 100:.1f}\\% & '
            f'{m["f1"]:.3f} & {m["avg_ms"]:.1f} \\\\')


def main():
    normal = load(OUT / 'benchmark_og.json')
    stripped = load(OUT / 'benchmark_og_stripped.json')
    lines = [
        '\\begin{table}[t]',
        '\\centering',
        '\\caption{UAF detection: UAF-OG generation compression vs naive '
        'baseline vs Angr. 20 samples (15 vulnerable + 5 safe). '
        'Stripped group shows the cost of losing main-symbol user-range '
        'localization; ACFPC-style IAT support is the mitigation.}',
        '\\label{tab:uaf-og}',
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
    lines.append('\\multicolumn{9}{l}{\\emph{Stripped (no symbols, -O1)}} \\\\')
    for t in TOOLS:
        lines.append(row(stripped[t], t))
    lines += ['\\bottomrule', '\\end{tabular}', '\\end{table}']
    (OUT / 'result_og_table.tex').write_text('\n'.join(lines) + '\n',
                                             encoding='utf-8')
    print('saved:', OUT / 'result_og_table.tex')


if __name__ == '__main__':
    main()
