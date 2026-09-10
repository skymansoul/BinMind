"""可扩展性绘图 — 四工具耗时/内存 vs 指令规模 (双对数).

用法: python eval/fp_cve_experiment/plot_scalability.py
输出: results/scalability_time.png, scalability_mem.png, scalability.csv
"""
import csv
import os

from _common import HERE as _HERE
RESULTS = os.path.join(_HERE, 'results')

TOOLS = ('pcfv', 'baseline', 'ghidra', 'angr')
COLORS = {'pcfv': '#c44e52', 'baseline': '#4c72b0',
          'ghidra': '#55a868', 'angr': '#8172b2'}
LABELS = {'pcfv': 'PCFV (Ours)', 'baseline': 'DP-TVRA baseline',
          'ghidra': 'Ghidra (heuristic)', 'angr': 'Angr'}

from _common import try_import
matplotlib = try_import('matplotlib')
MPL_OK = matplotlib is not None
if MPL_OK:
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt


def load(path: str) -> list:
    with open(path, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def main():
    rows = load(os.path.join(RESULTS, 'scalability.csv'))
    if not MPL_OK:
        print('matplotlib unavailable, skip plots')
        return
    # 按规模排序, 提取每工具曲线
    series = {}
    for r in rows:
        series.setdefault(r['tool'], []).append(
            (int(r['insns']), float(r['time_ms']),
             float(r['peak_mem_mb'])))
    for t in series:
        series[t].sort(key=lambda x: x[0])

    fig, ax = plt.subplots(figsize=(8, 5))
    for t in TOOLS:
        if t not in series:
            continue
        xs = [x[0] for x in series[t]]
        ys = [x[1] for x in series[t]]
        ax.plot(xs, ys, 'o-', color=COLORS[t], label=LABELS[t])
    ax.set_xscale('log', base=2)
    ax.set_yscale('log', base=2)
    ax.set_xlabel('Instructions (log2)')
    ax.set_ylabel('Time (ms, log2)')
    ax.set_title('Scalability: Analysis Time vs Binary Size')
    ax.legend()
    ax.grid(True, which='both', alpha=0.3)
    fig.tight_layout()
    out = os.path.join(RESULTS, 'scalability_time.png')
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print('saved ->', out)

    fig, ax = plt.subplots(figsize=(8, 5))
    for t in TOOLS:
        if t not in series:
            continue
        xs = [x[0] for x in series[t]]
        ys = [x[2] for x in series[t]]
        ax.plot(xs, ys, 'o-', color=COLORS[t], label=LABELS[t])
    ax.set_xscale('log', base=2)
    ax.set_xlabel('Instructions (log2)')
    ax.set_ylabel('Peak memory (MB)')
    ax.set_title('Scalability: Peak Memory vs Binary Size')
    ax.legend()
    ax.grid(True, which='both', alpha=0.3)
    fig.tight_layout()
    out = os.path.join(RESULTS, 'scalability_mem.png')
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print('saved ->', out)


if __name__ == '__main__':
    main()
