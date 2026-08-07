"""
"""
import os, json, csv, time

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


def save_outputs(metrics, results, ts, samples, results_dir):
    """保存 JSON / CSV / LaTeX / 图表."""
    _save_json(metrics, results, ts, samples, results_dir)
    _save_csv(metrics, results, ts, results_dir)
    _save_latex(metrics, ts, results_dir)
    _save_chart(metrics, results, ts, samples, results_dir)

    jname = f'cve_full_comparison_{ts}.json'
    cname = f'cve_full_comparison_{ts}.csv'
    tname = f'cve_full_comparison_{ts}.tex'
    print(f'\nJSON:  {jname}')
    print(f'CSV:   {cname}')
    print(f'LaTeX: {tname}')


def _save_json(metrics, results, ts, samples, results_dir):
    jpath = os.path.join(results_dir, f'cve_full_comparison_{ts}.json')
    with open(jpath, 'w', encoding='utf-8') as f:
        json.dump({
            'metrics': metrics,
            'n_samples': len(samples),
            'results': {t: [{k: v for k, v in r.items()
                             if k not in ('pipeline_stats',)}
                           for r in results[t]] for t in results},
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }, f, indent=2, ensure_ascii=False)


def _save_csv(metrics, results, ts, results_dir):
    cpath = os.path.join(results_dir, f'cve_full_comparison_{ts}.csv')
    with open(cpath, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Tool', 'TP', 'FP', 'TN', 'FN',
                    'Precision', 'Recall', 'F1', 'Avg_ms'])
        for tool, m in metrics.items():
            avg_ms = int(sum(r.get('duration_ms', 0)
                            for r in results[tool])
                        / max(len(results[tool]), 1))
            w.writerow([tool, m['TP'], m['FP'], m['TN'], m['FN'],
                        f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                        f"{m['f1']:.4f}", avg_ms])


def _save_latex(metrics, ts, results_dir):
    tpath = os.path.join(results_dir, f'cve_full_comparison_{ts}.tex')
    with open(tpath, 'w') as f:
        f.write(r'\begin{table}[htbp]' + '\n')
        f.write(r'\centering' + '\n')
        f.write(r'\caption{CVE Heap Overflow: Full Pipeline Multi-Tool Comparison}' + '\n')
        f.write(r'\label{tab:cve-full-comparison}' + '\n')
        f.write(r'\begin{tabular}{lrrrrrrr}' + '\n')
        f.write(r'\toprule' + '\n')
        f.write(r'Tool & TP & FP & TN & FN & Prec. & Rec. & F1 \\' + '\n')
        f.write(r'\midrule' + '\n')
        for tool in ['BinMind-Full', 'Angr', 'Ghidra', 'QEMU']:
            m = metrics[tool]
            f.write(f'{tool} & {m["TP"]} & {m["FP"]} & {m["TN"]} & {m["FN"]} '
                    f'& {m["precision"]:.2f} & {m["recall"]:.2f} '
                    f'& {m["f1"]:.2f} \\\\\n')
        f.write(r'\bottomrule' + '\n')
        f.write(r'\end{tabular}' + '\n')
        f.write(r'\end{table}' + '\n')


def _save_chart(metrics, results, ts, samples, results_dir):
    tool_list = ['BinMind-Full', 'Angr', 'Ghidra', 'QEMU']
    x = np.arange(len(tool_list))
    width = 0.35
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    # (a) Recall & F1
    ax = axes[0]
    recalls = [metrics[t]['recall'] for t in tool_list]
    f1s = [metrics[t]['f1'] for t in tool_list]
    ax.bar(x - width/2, recalls, width, label='Recall', color='#2196F3', alpha=0.85)
    ax.bar(x + width/2, f1s, width, label='F1', color='#4CAF50', alpha=0.85)
    ax.set_ylabel('Score')
    ax.set_title(f'(a) CVE Detection (n={len(samples)})')
    ax.set_xticks(x)
    ax.set_xticklabels(tool_list, rotation=15, ha='right', fontsize=8)
    ax.legend()
    ax.set_ylim(0, 1.15)

    # (b) TP/FN
    ax = axes[1]
    tps = [metrics[t]['TP'] for t in tool_list]
    fns = [metrics[t]['FN'] for t in tool_list]
    ax.bar(x, tps, 0.6, label='TP', color='#4CAF50')
    ax.bar(x, fns, 0.6, bottom=tps, label='FN', color='#F44336')
    ax.set_ylabel('Samples')
    ax.set_title(f'(b) Detection Count (n={len(samples)})')
    ax.set_xticks(x)
    ax.set_xticklabels(tool_list, rotation=15, ha='right', fontsize=8)
    ax.legend()
    for i, (tp, fn) in enumerate(zip(tps, fns)):
        ax.text(i, tp/2, str(tp), ha='center', fontweight='bold', color='white')
        if fn > 0:
            ax.text(i, tp + fn/2, str(fn), ha='center', fontweight='bold')

    # (c) Avg time
    ax = axes[2]
    avg_times = [sum(r.get('duration_ms', 0) for r in results[t])
                 / max(len(results[t]), 1) for t in tool_list]
    colors = ['#2196F3', '#FF9800', '#9C27B0', '#607D8B']
    ax.bar(x, avg_times, 0.6, color=colors)
    ax.set_ylabel('Avg Time (ms)')
    ax.set_title('(c) Average Analysis Time')
    ax.set_xticks(x)
    ax.set_xticklabels(tool_list, rotation=15, ha='right', fontsize=8)
    for i, val in enumerate(avg_times):
        ax.text(i, val + 0.5, f'{val:.0f}ms', ha='center', fontsize=8)

    plt.tight_layout()
    cpath_chart = os.path.join(results_dir, f'cve_full_comparison_{ts}.png')
    plt.savefig(cpath_chart, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'\nChart: {os.path.basename(cpath_chart)}')
