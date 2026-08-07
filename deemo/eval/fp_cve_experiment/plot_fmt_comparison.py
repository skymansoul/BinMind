"""FMT 对比绘图与表格 — FMT-SAC vs 基线 (O0/O2).

创建: 2026-06-05
用法: python eval/fp_cve_experiment/plot_fmt_comparison.py
输出: results/fmt_comparison.png, fmt_result_table_O0.tex, fmt_result_table_O2.tex
"""
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(_HERE, 'results')

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    MPL_OK = True
except ImportError:
    MPL_OK = False


def load(path: str) -> dict:
    with open(os.path.join(RESULTS, path), encoding='utf-8') as f:
        return json.load(f)


def plot(o0: dict, o2: dict):
    tools = ('baseline', 'sac')
    labels = ('FMT baseline', 'FMT-SAC (Ours)')
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
    fig.suptitle('Format String Detection: FMT-SAC vs Baseline')
    fig.tight_layout()
    out = os.path.join(RESULTS, 'fmt_comparison.png')
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print('saved ->', out)


def latex(o0: dict, o2: dict, label: str, fname: str):
    m = o0 if label == 'O0' else o2
    lines = ['%% Auto-generated (FMT corpus, %s variant)' % label,
             '\\begin{table}[htbp]', '\\centering',
             '\\caption{Format-string detection comparison (%s; 15 TP + '
             '15 safe). FMT-SAC classifies the format source and verifies '
             'specifier-argument consistency, cutting false positives '
             'from 15 to 1.}' % label,
             '\\label{tab:fmt-%s}' % label.lower(), '\\small',
             '\\begin{tabular}{lcccccc}', '\\toprule',
             'Tool & TP & FP & FN & Precision & Recall & F1 \\\\',
             '\\midrule']
    for tool, disp in (('baseline', 'FMT baseline (detector)'),
                       ('sac', '\\textbf{FMT-SAC (Ours)}')):
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
    o0 = load('fmt_baseline_vs_sac.json')
    o2 = load('fmt_baseline_vs_sac_o2.json')
    if MPL_OK:
        plot(o0, o2)
    latex(o0, o2, 'O0', 'fmt_result_table_O0.tex')
    latex(o0, o2, 'O2', 'fmt_result_table_O2.tex')


if __name__ == '__main__':
    main()
