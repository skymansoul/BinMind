"""
综合多工具对比实验辅助模块 — 样本加载与结果保存(LaTeX/CSV/JSON/图表).
"""
import os, json, time, csv
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE, 'eval', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

BVF_EXPECTED = {
    'bvf_01_shared_var_safe': False,
    'bvf_02_shared_var_overflow': True,
    'bvf_03_arith_safe': False,
    'bvf_04_arith_overflow': True,
    'bvf_05_multihop_chain': False,
    'bvf_06_no_shared_unrelated': False,
    'bvf_07_offset_safe': False,
    'bvf_08_offset_overflow': True,
    'bvf_09_taint_unbounded': True,
    'bvf_10_guard_capped_safe': False,
    'bvf_11_calloc_safe': False,
    'bvf_12_calloc_overflow': True,
    'bvf_13_realloc_expand_safe': False,
    'bvf_14_realloc_noexpand_overflow': True,
    'bvf_15_loop_accum_overflow': True,
    'bvf_16_loop_safe': False,
    'bvf_17_struct_field_safe': False,
    'bvf_18_struct_field_overflow': True,
}

PCBVF_EXPECTED = {
    'pcbvf_01': False, 'pcbvf_02': True, 'pcbvf_03': False,
    'pcbvf_04': True, 'pcbvf_05': False, 'pcbvf_06': False,
    'pcbvf_07': True, 'pcbvf_08': False, 'pcbvf_09': False,
    'pcbvf_10': True, 'pcbvf_11': False, 'pcbvf_12': False,
}


def load_samples():
    """加载所有样本, 返回(name, source, expected_vuln)列表."""
    samples = []

    bench_dir = os.path.join(BASE, 'tests', 'heap_overflow_benchmark')
    for d in sorted(Path(bench_dir).iterdir()):
        if not d.is_dir(): continue
        c = list(d.glob('*.c'))
        if not c: continue
        expected = d.name.startswith('tp_')
        with open(c[0], encoding='utf-8', errors='replace') as f:
            samples.append((d.name, f.read(), expected))

    bvf_dir = os.path.join(BASE, 'tests', 'bvf_samples')
    for d in sorted(Path(bvf_dir).iterdir()):
        if not d.is_dir(): continue
        c = list(d.glob('*.c'))
        if not c: continue
        expected = BVF_EXPECTED.get(d.name, 'overflow' in d.name)
        with open(c[0], encoding='utf-8', errors='replace') as f:
            samples.append((d.name, f.read(), expected))

    pcbvf_dir = os.path.join(BASE, 'tests', 'pcbvf_samples')
    for d in sorted(Path(pcbvf_dir).iterdir()):
        if not d.is_dir(): continue
        c = list(d.glob('*.c'))
        if not c: continue
        expected = PCBVF_EXPECTED.get(d.name, 'vuln' in d.name.lower())
        with open(c[0], encoding='utf-8', errors='replace') as f:
            samples.append((d.name, f.read(), expected))

    cve_dir = os.path.join(BASE, 'samples', 'cve_heap_overflow')
    for d in sorted(Path(cve_dir).iterdir()):
        if not d.is_dir(): continue
        c = list(d.glob('*.c'))
        if not c: continue
        with open(c[0], encoding='utf-8', errors='replace') as f:
            samples.append((d.name, f.read(), True))

    return samples


def save_results(metrics, results, samples, ts):
    """保存JSON/CSV/LaTeX/图表."""
    jpath = os.path.join(RESULTS_DIR, f'comprehensive_comparison_{ts}.json')
    with open(jpath, 'w', encoding='utf-8') as f:
        json.dump({
            'metrics': metrics,
            'n_samples': len(samples),
            'n_vuln': sum(1 for _, _, e in samples if e),
            'n_safe': sum(1 for _, _, e in samples if not e),
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }, f, indent=2, ensure_ascii=False)

    cpath = os.path.join(RESULTS_DIR, f'comprehensive_comparison_{ts}.csv')
    with open(cpath, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Tool', 'TP', 'FP', 'TN', 'FN',
                    'Precision', 'Recall', 'F1', 'FPR'])
        for tool, m in metrics.items():
            w.writerow([tool, m['TP'], m['FP'], m['TN'], m['FN'],
                        f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                        f"{m['f1']:.4f}", f"{m['fpr']:.4f}"])

    tpath = os.path.join(RESULTS_DIR, f'comprehensive_comparison_{ts}.tex')
    _write_latex(tpath, metrics, samples)

    _generate_chart(metrics, samples, ts)

    print(f'JSON:  {os.path.basename(jpath)}')
    print(f'CSV:   {os.path.basename(cpath)}')
    print(f'LaTeX: {os.path.basename(tpath)}')


def _write_latex(tpath, metrics, samples):
    n_total = len(samples)
    n_vuln = sum(1 for _, _, e in samples if e)
    n_safe = sum(1 for _, _, e in samples if not e)
    with open(tpath, 'w') as f:
        f.write(r'\begin{table}[htbp]' + '\n')
        f.write(r'\centering' + '\n')
        f.write(f'\\caption{{Comprehensive Comparison ({n_total} samples: {n_vuln} VULN + {n_safe} SAFE)}}\n')
        f.write(r'\label{tab:comprehensive-comparison}' + '\n')
        f.write(r'\begin{tabular}{lrrrrrrrr}' + '\n')
        f.write(r'\toprule' + '\n')
        f.write(r'Tool & TP & FP & TN & FN & Prec. & Rec. & F1 & FPR \\' + '\n')
        f.write(r'\midrule' + '\n')
        for tool in ['BinMind-Full', 'Regex-Baseline', 'Angr-Source']:
            m = metrics[tool]
            f.write(f'{tool} & {m["TP"]} & {m["FP"]} & {m["TN"]} & {m["FN"]} '
                    f'& {m["precision"]:.2f} & {m["recall"]:.2f} '
                    f'& {m["f1"]:.2f} & {m["fpr"]:.2f} \\\\\n')
        f.write(r'\bottomrule' + '\n')
        f.write(r'\end{tabular}' + '\n')
        f.write(r'\end{table}' + '\n')


def _generate_chart(metrics, samples, ts):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np

        fig, axes = plt.subplots(1, 3, figsize=(16, 5))
        tools_list = ['BinMind-Full', 'Regex-Baseline', 'Angr-Source']
        x = np.arange(len(tools_list))
        width = 0.25

        ax = axes[0]
        ps = [metrics[t]['precision'] for t in tools_list]
        rs = [metrics[t]['recall'] for t in tools_list]
        fs = [metrics[t]['f1'] for t in tools_list]
        ax.bar(x - width, ps, width, label='Precision', color='#2196F3', alpha=0.85)
        ax.bar(x, rs, width, label='Recall', color='#4CAF50', alpha=0.85)
        ax.bar(x + width, fs, width, label='F1', color='#FF9800', alpha=0.85)
        ax.set_ylabel('Score')
        ax.set_title(f'(a) P/R/F1 ({len(samples)} samples)')
        ax.set_xticks(x)
        ax.set_xticklabels(tools_list, rotation=15, ha='right', fontsize=8)
        ax.legend(fontsize=8)
        ax.set_ylim(0, 1.15)

        ax = axes[1]
        tps = [metrics[t]['TP'] for t in tools_list]
        fps = [metrics[t]['FP'] for t in tools_list]
        tns = [metrics[t]['TN'] for t in tools_list]
        fns = [metrics[t]['FN'] for t in tools_list]
        ax.bar(x - 1.5*width, tps, width, label='TP', color='#4CAF50')
        ax.bar(x - 0.5*width, fps, width, label='FP', color='#F44336')
        ax.bar(x + 0.5*width, tns, width, label='TN', color='#2196F3')
        ax.bar(x + 1.5*width, fns, width, label='FN', color='#FF9800')
        ax.set_ylabel('Count')
        ax.set_title(f'(b) Confusion Matrix')
        ax.set_xticks(x)
        ax.set_xticklabels(tools_list, rotation=15, ha='right', fontsize=8)
        ax.legend(fontsize=7)

        ax = axes[2]
        fprs = [metrics[t]['fpr'] for t in tools_list]
        colors = ['#2196F3', '#FF9800', '#9C27B0']
        bars = ax.bar(x, fprs, 0.5, color=colors)
        ax.set_ylabel('False Positive Rate')
        ax.set_title('(c) FPR (lower is better)')
        ax.set_xticks(x)
        ax.set_xticklabels(tools_list, rotation=15, ha='right', fontsize=8)
        ax.set_ylim(0, 1.15)
        for bar, val in zip(bars, fprs):
            ax.text(bar.get_x() + bar.get_width()/2, val + 0.02,
                    f'{val:.0%}', ha='center', fontsize=9)

        plt.tight_layout()
        chart_path = os.path.join(RESULTS_DIR, f'comprehensive_comparison_{ts}.png')
        plt.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f'\nChart: {os.path.basename(chart_path)}')
    except ImportError:
        pass
