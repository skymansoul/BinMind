"""对比实验绘图 — 检出率/误报率/F1 柱状图 (O0 vs O2 分组).

用法: python eval/fp_cve_experiment/plot_comparison.py
输出: eval/fp_cve_experiment/results/comparison_precision.png
      eval/fp_cve_experiment/results/comparison_recall.png
      eval/fp_cve_experiment/results/comparison_f1.png
      eval/fp_cve_experiment/results/comparison_fp_rate.png
"""
import csv
import os
import sys

from _common import try_import
matplotlib = try_import('matplotlib')
MPL_OK = matplotlib is not None
if MPL_OK:
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    MPL_OK = True

from _common import HERE as _HERE
RESULTS = os.path.join(_HERE, 'results')

TOOL_ORDER = ['pcfv', 'baseline', 'angr', 'ghidra', 'asan']
TOOL_LABEL = {'pcfv': 'PCFV (Ours)', 'baseline': 'DP-TVRA baseline',
              'angr': 'Angr', 'ghidra': 'Ghidra (heuristic)',
              'asan': 'Runtime (shim)'}


def load_metrics(csv_path: str) -> dict:
    rows = list(csv.DictReader(open(csv_path, encoding='utf-8')))
    by_tool = {}
    for tool in TOOL_ORDER:
        tr = [r for r in rows if r['tool'] == tool]
        if not tr:
            continue
        tp = sum(1 for r in tr
                 if r['expected_vuln'] == 'True' and r['fn_count'] == '0')
        fn = sum(int(r['fn_count']) for r in tr)
        fp = sum(int(r['fp_count']) for r in tr)
        tn = sum(1 for r in tr
                 if r['expected_vuln'] == 'False' and r['fp_count'] == '0')
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fp_rate = fp / (fp + tn) if fp + tn else 0.0
        by_tool[tool] = {'precision': prec, 'recall': rec, 'f1': f1,
                         'fp_rate': fp_rate, 'tp': tp, 'fp': fp}
    return by_tool


def _bar_chart(o0: dict, o2: dict, key: str, title: str, fname: str,
               ymax: float = 1.05):
    tools = [t for t in TOOL_ORDER if t in o0 and t in o2]
    x = list(range(len(tools)))
    w = 0.38
    v0 = [o0[t][key] for t in tools]
    v2 = [o2[t][key] for t in tools]
    fig, ax = plt.subplots(figsize=(9, 5))
    b0 = ax.bar([i - w / 2 for i in x], v0, w, label='O0 (-O0, unstripped)',
                color='#4c72b0')
    b2 = ax.bar([i + w / 2 for i in x], v2, w, label='O2 (-O2, -fno-dce)',
                color='#dd8452')
    ax.set_xticks(x)
    ax.set_xticklabels([TOOL_LABEL.get(t, t) for t in tools],
                       rotation=12, ha='right')
    ax.set_ylabel(title)
    ax.set_ylim(0, ymax)
    ax.legend(loc='lower right')
    ax.grid(axis='y', alpha=0.3)
    for b in list(b0) + list(b2):
        ax.text(b.get_x() + b.get_width() / 2,
                b.get_height() + 0.02, '%.2f' % b.get_height(),
                ha='center', fontsize=7)
    fig.suptitle(title + ' by Tool and Optimization Level', fontsize=11)
    fig.tight_layout()
    path = os.path.join(RESULTS, fname)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print('saved ->', path)


def main():
    o0 = load_metrics(os.path.join(RESULTS, 'benchmark_o0.csv'))
    o2 = load_metrics(os.path.join(RESULTS, 'benchmark_o2.csv'))
    if not MPL_OK:
        print('matplotlib unavailable, skip plots')
        return
    _bar_chart(o0, o2, 'precision', 'Precision',
               'comparison_precision.png')
    _bar_chart(o0, o2, 'recall', 'Recall',
               'comparison_recall.png')
    _bar_chart(o0, o2, 'f1', 'F1 Score', 'comparison_f1.png')
    _bar_chart(o0, o2, 'fp_rate', 'False Positive Rate',
               'comparison_fp_rate.png', ymax=1.05)
    # 加壳/未加壳分组
    packed_path = os.path.join(RESULTS, 'benchmark_packed.csv')
    if os.path.exists(packed_path):
        pk = load_metrics(packed_path)
        _bar_chart(o0, pk, 'precision', 'Precision (packed vs unpacked)',
                   'comparison_packed_precision.png')
        _bar_chart(o0, pk, 'recall', 'Recall (packed vs unpacked)',
                   'comparison_packed_recall.png')
        _bar_chart(o0, pk, 'f1', 'F1 Score (packed vs unpacked)',
                   'comparison_packed_f1.png')
        _bar_chart(o0, pk, 'fp_rate',
                   'False Positive Rate (packed vs unpacked)',
                   'comparison_packed_fp_rate.png', ymax=1.05)
    # SysV ABI 分组
    sysv_path = os.path.join(RESULTS, 'benchmark_sysv.csv')
    if os.path.exists(sysv_path):
        sv = load_metrics(sysv_path)
        _bar_chart(o0, sv, 'precision', 'Precision (SysV vs Win64 ABI)',
                   'comparison_sysv_precision.png')
        _bar_chart(o0, sv, 'recall', 'Recall (SysV vs Win64 ABI)',
                   'comparison_sysv_recall.png')
        _bar_chart(o0, sv, 'f1', 'F1 Score (SysV vs Win64 ABI)',
                   'comparison_sysv_f1.png')
        _bar_chart(o0, sv, 'fp_rate',
                   'False Positive Rate (SysV vs Win64 ABI)',
                   'comparison_sysv_fp_rate.png', ymax=1.05)
    print('all plots generated')


if __name__ == '__main__':
    main()
