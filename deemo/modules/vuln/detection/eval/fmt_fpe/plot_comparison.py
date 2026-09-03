"""FPE 格式字符串多工具对比可视化与 LaTeX 表.

输入: results/benchmark_results.csv / benchmark_summary.json
输出: fig_detection_rate.png / fig_fp_rate.png / fig_f1.png / result_table.tex
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

_HERE = Path(__file__).resolve().parent
TOOLS = ['fpe', 'baseline', 'angr', 'qemu', 'ghidra']
TIERS = ['plain', 'packed']
LABELS = {'fpe': 'FPE (ours)', 'baseline': 'Baseline', 'angr': 'Angr (CFG)',
          'qemu': 'QEMU trace', 'ghidra': 'Ghidra headless (sim.)'}


def load_rows(results: Path) -> list:
    with open(results / 'benchmark_results.csv', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def by_tool_tier(rows: list) -> dict:
    manifest = (_HERE.parent.parent / 'tests' / 'fmt_fpe'
                / 'samples' / 'manifest.json')
    exp = {}
    if manifest.exists():
        exp = {d['id']: d['expected']
               for d in json.loads(manifest.read_text(encoding='utf-8'))}
    agg = defaultdict(lambda: defaultdict(
        lambda: {'detected': 0, 'total': 0, 'fp': 0,
                 'clean_total': 0, 'vuln_total': 0}))
    for r in rows:
        tool, sid = r['tool'], r['sample_id']
        tier = sid.split(':')[-1]
        name = sid.split(':')[0]
        a = agg[tool][tier]
        a['total'] += 1
        a['detected'] += int(r['detected'])
        a['fp'] += int(r['fp'])
        if exp.get(name) == 'clean':
            a['clean_total'] += 1
        else:
            a['vuln_total'] += 1
    return agg


def plot_main() -> None:
    results = _HERE / 'results'
    agg = by_tool_tier(load_rows(results))
    det = {t: {} for t in TOOLS}
    fp = {t: {} for t in TOOLS}
    for t in TOOLS:
        for tier in TIERS:
            a = agg[t][tier]
            det[t][tier] = a['detected'] / a['total'] if a['total'] else 0.0
            fp[t][tier] = (a['fp'] / a['clean_total']
                           if a['clean_total'] else 0.0)

    def bar(ax, values, title, ylabel):
        x = range(len(TOOLS))
        width = 0.8 / len(TIERS)
        for i, tier in enumerate(TIERS):
            ax.bar([p + i * width for p in x], [values[t][tier] for t in TOOLS],
                   width, label=tier, color=f'C{i}')
        ax.set_xticks([p + width * (len(TIERS) - 1) / 2 for p in x])
        ax.set_xticklabels([LABELS[t] for t in TOOLS])
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.set_ylim(0, 1.1)
        ax.legend()

    fig, ax = plt.subplots(figsize=(9, 5))
    bar(ax, det, 'Format-String Detection Rate by Tool and Tier', 'Recall')
    fig.tight_layout()
    fig.savefig(_HERE / 'fig_detection_rate.png', dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 5))
    bar(ax, fp, 'Format-String FP Rate on Clean by Tool and Tier', 'FP rate')
    fig.tight_layout()
    fig.savefig(_HERE / 'fig_fp_rate.png', dpi=150)
    plt.close(fig)

    summary = json.loads((results / 'benchmark_summary.json')
                         .read_text(encoding='utf-8'))
    fig, ax = plt.subplots(figsize=(8, 5))
    vals = [summary[t]['f1'] for t in TOOLS]
    ax.bar([LABELS[t] for t in TOOLS], vals,
           color=['#2e8b57', '#d0a020', '#b0b0b0', '#6a9fd8', '#b0b0b0'])
    for i, v in enumerate(vals):
        ax.text(i, v + 0.02, f'{v:.3f}', ha='center')
    ax.set_ylim(0, 1.1)
    ax.set_title('Format-String F1 Score by Tool (all 46 binaries)')
    ax.set_ylabel('F1')
    fig.tight_layout()
    fig.savefig(_HERE / 'fig_f1.png', dpi=150)
    plt.close(fig)
    print('[plot] fmt charts written')


def tex_main() -> None:
    results = _HERE / 'results'
    summary = json.loads((results / 'benchmark_summary.json')
                         .read_text(encoding='utf-8'))
    lines = [
        '% Format-string 多工具检测对比表 (FPE benchmark, 46 binaries)',
        '\\begin{table}[t]',
        '\\centering',
        '\\caption{Format-String Detection: FPE vs. Baseline and '
        'General-Purpose Tools (23 samples, O0/O2).}',
        '\\label{tab:fmt-fpe-comparison}',
        '\\small',
        '\\begin{tabular}{lrrrrrrrr}',
        '\\hline',
        'Tool & TP & FP & FN & Recall & Precision & F1 '
        '& FP rate & Time(s) \\\\',
        '\\hline',
    ]
    for t in TOOLS:
        m = summary[t]
        name = f'\\textbf{{{LABELS[t]}}}' if t == 'fpe' else LABELS[t]
        lines.append(
            f'  {name} & {m["tp"]} & {m["fp"]} & {m["fn"]} '
            f'& {m["recall"]:.3f} & {m["precision"]:.3f} '
            f'& {m["f1"]:.3f} & {m["fp_rate"]:.3f} '
            f'& {m["total_sec"]:.2f} \\\\')
    lines += ['\\hline', '\\end{tabular}', '\\end{table}']
    (_HERE / 'result_table.tex').write_text('\n'.join(lines),
                                            encoding='utf-8')
    print('[tex] fmt result_table.tex written')


if __name__ == '__main__':
    if 'tex' in sys.argv:
        tex_main()
    else:
        plot_main()
