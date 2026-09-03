"""多工具对比可视化 — 检出率/误报率/F1 柱状图 (含 plain/packed 分组).

输入: run_benchmark.py 生成的 benchmark_results.csv / benchmark_summary.json
输出:
  fig_detection_rate.png   按工具×档位的检出率 (recall)
  fig_fp_rate.png          按工具×档位的误报率 (fp_rate)
  fig_f1.png               按工具×档位的 F1
  数据: metrics_by_tier.json

用法:
  python plot_comparison.py [--results <dir>] [--out <dir>]
"""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

_HERE = Path(__file__).resolve().parent


def load_rows(results: Path) -> list:
    rows = []
    with open(results / 'benchmark_results.csv', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def by_tool_tier(rows: list) -> dict:
    """{tool: {tier: {detected, total, fp, clean_total, vuln_total}}}.

    干净/漏洞样本按 manifest 期望标签判定, 而非混淆矩阵反推。
    """
    manifest = (_HERE.parent.parent / 'tests' / 'heap_acpe_cve'
                / 'samples' / 'manifest.json')
    exp = {}
    if manifest.exists():
        exp = {d['id']: d['expected']
               for d in json.loads(manifest.read_text(encoding='utf-8'))}
    agg = defaultdict(lambda: defaultdict(
        lambda: {'detected': 0, 'total': 0, 'fp': 0,
                 'clean_total': 0, 'vuln_total': 0}))
    for r in rows:
        tool = r['tool']
        sid = r['sample_id']
        tier = sid.split(':')[-1]
        sid_name = sid.split(':')[0]
        det = int(r['detected'])
        fp = int(r['fp'])
        a = agg[tool][tier]
        a['total'] += 1
        a['detected'] += det
        a['fp'] += fp
        if exp.get(sid_name) == 'clean':
            a['clean_total'] += 1
        else:
            a['vuln_total'] += 1
    return agg


def plot_bar(ax, tools, tiers, values, title, ylabel):
    x = range(len(tools))
    width = 0.8 / len(tiers)
    for i, tier in enumerate(tiers):
        vals = [values[t][tier] for t in tools]
        ax.bar([p + i * width for p in x], vals, width,
               label=tier, color=f'C{i}')
    ax.set_xticks([p + width * (len(tiers) - 1) / 2 for p in x])
    ax.set_xticklabels(tools)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, 1.05)
    ax.legend()
    for i, tier in enumerate(tiers):
        for j, t in enumerate(tools):
            v = values[t][tier]
            ax.text(j + i * width, v + 0.02, f'{v:.2f}',
                    ha='center', fontsize=7)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default='results')
    ap.add_argument('--out', default='.')
    args = ap.parse_args()
    results = _HERE / args.results
    out = _HERE / args.out
    out.mkdir(parents=True, exist_ok=True)

    rows = load_rows(results)
    agg = by_tool_tier(rows)
    tools = ['acpe', 'baseline', 'angr', 'qemu', 'ghidra']
    tiers = ['plain', 'packed']

    det_rate = {t: {} for t in tools}
    fp_rate = {t: {} for t in tools}
    for t in tools:
        for tier in tiers:
            a = agg[t][tier]
            det_rate[t][tier] = (a['detected'] / a['total']
                                 if a['total'] else 0.0)
            fp_rate[t][tier] = (a['fp'] / a['clean_total']
                                if a['clean_total'] else 0.0)

    fig, ax = plt.subplots(1, 1, figsize=(9, 5))
    plot_bar(ax, tools, tiers, det_rate,
             'Detection Rate by Tool and Binary Tier', 'Recall')
    fig.tight_layout()
    fig.savefig(out / 'fig_detection_rate.png', dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(1, 1, figsize=(9, 5))
    plot_bar(ax, tools, tiers, fp_rate,
             'False Positive Rate on Clean Samples by Tool and Tier',
             'FP rate')
    fig.tight_layout()
    fig.savefig(out / 'fig_fp_rate.png', dpi=150)
    plt.close(fig)

    # F1 总图 (跨档汇总)
    summary = json.loads(
        (results / 'benchmark_summary.json').read_text(encoding='utf-8'))
    f1_vals = [summary[t]['f1'] for t in tools]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(tools, f1_vals, color=['#2e8b57', '#d0a020', '#b0b0b0',
                                  '#6a9fd8', '#b0b0b0'])
    for i, v in enumerate(f1_vals):
        ax.text(i, v + 0.02, f'{v:.3f}', ha='center')
    ax.set_ylim(0, 1.1)
    ax.set_title('F1 Score by Tool (all 46 binaries)')
    ax.set_ylabel('F1')
    fig.tight_layout()
    fig.savefig(out / 'fig_f1.png', dpi=150)
    plt.close(fig)

    metrics = {'detection_rate': det_rate, 'fp_rate': fp_rate,
               'summary': summary}
    (out / 'metrics_by_tier.json').write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'[plot] charts written to {out}')


if __name__ == '__main__':
    main()
