"""UAF 对比绘图与表格 — TOVS vs 基线 (O0/O2).

创建: 2023-11-10
用法: python eval/fp_cve_experiment/plot_uaf_comparison.py
输出: results/uaf_comparison.png, results/uaf_result_table_O0.tex,
      results/uaf_result_table_O2.tex
"""
import json
import os
import sys

from _common import HERE as _HERE
RESULTS = os.path.join(_HERE, 'results')

from _common import try_import
matplotlib = try_import('matplotlib')
MPL_OK = matplotlib is not None
if MPL_OK:
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    MPL_OK = True


def load(path: str) -> dict:
    with open(os.path.join(RESULTS, path), encoding='utf-8') as f:
        return json.load(f)


def plot(o0: dict, o2: dict):
    tools = ('baseline', 'tovs')
    labels = ('UAF baseline (DT-HSA)', 'TOVS (Ours)')
    metrics = ('precision', 'recall', 'f1')
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    for ax, m in zip(axes, metrics):
        x = list(range(2))
        w = 0.34
        v0 = [o0['metrics'][t][m] for t in tools]
        v2 = [o2['metrics'][t][m] for t in tools]
        b0 = ax.bar([i - w / 2 for i in x], v0, w, label='O0',
                    color='#4c72b0')
        b2 = ax.bar([i + w / 2 for i in x], v2, w, label='O2',
                    color='#dd8452')
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylim(0, 1.05)
        ax.set_title(m.capitalize())
        ax.grid(axis='y', alpha=0.3)
        for b in list(b0) + list(b2):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02,
                    '%.2f' % b.get_height(), ha='center', fontsize=7)
    axes[0].legend()
    fig.suptitle('UAF Detection: TOVS vs Baseline (30-sample corpus)')
    fig.tight_layout()
    out = os.path.join(RESULTS, 'uaf_comparison.png')
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print('saved ->', out)


def latex(o0: dict, o2: dict, label: str, fname: str):
    m = o0 if label == 'O0' else o2
    lines = ['%% Auto-generated (UAF corpus, %s variant)' % label,
             '\\begin{table}[htbp]', '\\centering',
             '\\caption{UAF detection comparison (%s; 15 TP + 15 safe). '
             'TOVS verifies temporal ordering via post-dominance and '
             'pointer identity, eliminating exclusive-branch and '
             'redefinition false positives.}' % label,
             '\\label{tab:uaf-%s}' % label.lower(), '\\small',
             '\\begin{tabular}{lcccccc}', '\\toprule',
             'Tool & TP & FP & FN & Precision & Recall & F1 \\\\',
             '\\midrule']
    for tool, disp in (('baseline', 'UAF baseline (DT-HSA)'),
                       ('tovs', '\\textbf{TOVS (Ours)}')):
        mm = m['metrics'][tool]
        lines.append('%s & %d & %d & %d & %.3f & %.3f & %.3f \\\\' % (
            disp, mm['tp'], mm['fp'], mm['fn'], mm['precision'],
            mm['recall'], mm['f1']))
    lines += ['\\bottomrule', '\\end{tabular}', '\\end{table}']
    out = os.path.join(RESULTS, fname)
    with open(out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print('saved ->', out)


def main():
    o0 = load('uaf_baseline_vs_tovs.json')
    o2 = load('uaf_baseline_vs_tovs_o2.json')
    if MPL_OK:
        plot(o0, o2)
    latex(o0, o2, 'O0', 'uaf_result_table_O0.tex')
    latex(o0, o2, 'O2', 'uaf_result_table_O2.tex')


if __name__ == '__main__':
    main()
