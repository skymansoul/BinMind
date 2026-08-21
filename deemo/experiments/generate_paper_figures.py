"""堆溢出FP过滤基准 — heap_overflow_pipeline 实测，输出 JSON 数据、matplotlib 图表和 LaTeX 表格。"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.heap_overflow_pipeline import detect_heap_overflows_full

BENCHMARKS = {
    # (ir_lines, expected_overflow, description)
    'HO-01': (['buf = malloc(64)', 'store qword [buf + 100] = 0'], True, 'malloc(64) write offset 100'),
    'HO-02': (['buf = calloc(4, 4)', 'store dword [buf + 20] = 0'], True, 'calloc(16) write offset 20'),
    'HO-03': (['p = malloc(64)', 'free(p)', 'p = malloc(32)', 'store qword [p + 40] = 0'], True, 'free+realloc(32) write offset 40'),
    'FP-01': (['buf = malloc(64)', 'store qword [buf + 56] = 0'], False, 'malloc(64) write aligned offset 56'),
    'FP-02': (['a = malloc(64)', 'a = realloc(a, 256)', 'store qword [a + 200] = 0'], False, 'realloc(256) write offset 200 (legal)'),
    'FP-03': (['s = malloc(64)', 'store dword [s] = 0', 'store dword [s+4] = 0', 'store dword [s+8] = 0', 'store dword [s+72] = 0'], False, 'struct multi-field access pattern'),
}


def main():
    results = []
    tp = fp = tn = fn = 0
    for name, (ir, expected, desc) in BENCHMARKS.items():
        cands, stats = detect_heap_overflows_full(ir)
        detected = len(cands) > 0
        if expected and detected: tp += 1
        elif expected and not detected: fn += 1
        elif not expected and detected: fp += 1
        elif not expected and not detected: tn += 1
        results.append({'id': name, 'desc': desc, 'expected': expected, 'detected': detected,
                        'candidates': len(cands), 'stats': stats})

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    data = {'benchmarks': results, 'summary': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(precision, 2), 'recall': round(recall, 2), 'f1': round(f1, 2),
            'fp_reduction': f'{tn}/{fp+tn} ({tn/max(1,fp+tn):.0%})'}}

    out_dir = os.path.dirname(__file__)
    with open(os.path.join(out_dir, 'heap_fp_benchmark.json'), 'w') as f:
        json.dump(data, f, indent=2)
    print(f'Data: {json.dumps(data["summary"])}')

    # LaTeX table
    latex = r'''\begin{table}[t]
    \centering
    \caption{Heap overflow detection with false positive reduction. Benchmarks
    cover six scenarios: three true overflows (HO-01--03) and three false positive
    scenarios (FP-01--03) representing alignment-compatible writes, \texttt{realloc}
    expansion, and struct field access patterns. The four-stage pipeline achieves
    %.0f\%% precision and %.0f\%% recall on this benchmark.}
    \label{tab:heap_fp}
    \begin{tabular}{@{}l c c c c c@{}}
    \toprule
    \textbf{ID} & \textbf{Scenario} & \textbf{Expected} & \textbf{Detected} & \textbf{Raw} & \textbf{Filtered} \\
    \midrule
    ''' % (precision * 100, recall * 100)
    for r in results:
        latex += f'  {r["id"]} & {r["desc"][:48]} & {"overflow" if r["expected"] else "safe"} & {"Yes" if r["detected"] else "No"} & {r["stats"]["stage_detect"]} & {r["candidates"]} \\\\\n'
    latex += r'''\midrule
    \multicolumn{6}{@{}l@{}}{\textbf{Summary:} TP=%d, FP=%d, TN=%d, FN=%d, Precision=%.2f, Recall=%.2f, F1=%.2f} \\
    \bottomrule
    \end{tabular}
    \end{table}
    ''' % (tp, fp, tn, fn, precision, recall, f1)

    with open(os.path.join(out_dir, 'paper_table.tex'), 'w') as f:
        f.write(latex)
    print('LaTeX table: experiments/paper_table.tex')

    # matplotlib plot
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        labels = [r['id'] for r in results]
        detected_vals = [1 if r['detected'] else 0 for r in results]
        expected_vals = [1 if r['expected'] else 0 for r in results]
        x = np.arange(len(labels))
        w = 0.35
        ax1.bar(x - w/2, expected_vals, w, label='Expected', color='#4CAF50', alpha=0.7)
        ax1.bar(x + w/2, detected_vals, w, label='Detected', color='#2196F3', alpha=0.7)
        ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=8)
        ax1.set_ylabel('Overflow? (1=Yes)'); ax1.legend()
        ax1.set_title('Detection Accuracy per Scenario')
        # Right: FP reduction pie
        ax2.pie([tp, tn, fp, fn], labels=['TP', 'TN', 'FP', 'FN'], autopct='%1.0f%%',
                colors=['#4CAF50', '#2196F3', '#F44336', '#FF9800'])
        ax2.set_title(f'Overall (P={precision:.0%} R={recall:.0%})')
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, 'heap_fp_plot.png'), dpi=300, bbox_inches='tight')
        print('Plot: experiments/heap_fp_plot.png')
    except ImportError:
        print('matplotlib not available - skipping plot')


if __name__ == "__main__":
    main()
