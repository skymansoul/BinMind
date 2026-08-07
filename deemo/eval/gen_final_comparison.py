# 最终统一多工具对比报告生成器 — 汇总所有实验数据输出CSV/LaTeX/图表.
# 聚合来源: final_multi_tool_comparison.json (123样本) + cve_multi_tool_20260809_150130.json (16 CVE)
#          + regression_*.json (消融) + gapsbv_final_metrics.json (17 CVE CJ基准)
# 创建: 2026-05-10

import json, os, csv
from pathlib import Path

EVAL = Path(__file__).resolve().parent
OUT = EVAL / 'final_deliverables'
OUT.mkdir(exist_ok=True)

DATA_SOURCES = {
    'cross_type_123': EVAL / 'final_multi_tool_comparison.json',
    'cve_16': EVAL / 'cve_multi_tool_20260809_150130.json',
    'heap_ensemble': EVAL / 'regression_heap_ensemble.json',
    'uaf_ensemble': EVAL / 'regression_uaf_ensemble.json',
    'fmt_regression': EVAL / 'regression_format_string.json',
    'int_regression': EVAL / 'regression_int_overflow.json',
    'gapsbv_cj_17': EVAL / 'gapsbv_final_metrics.json',
}


def _load(name):
    p = DATA_SOURCES.get(name)
    if p and p.exists():
        with open(p, encoding='utf-8') as f:
            return json.load(f)
    return {}


def gen_csv():
    """生成统一CSV — 每行一个工具的汇总指标."""
    rows = []

    # 123样本跨类型基准
    ct = _load('cross_type_123')
    for tool, d in ct.get('tools', {}).items():
        rows.append({
            'benchmark': 'cross_type_123',
            'tool': tool,
            'samples': d.get('total', 123),
            'TP': d.get('tp_count', 0),
            'FP': d.get('fp_count', 0),
            'TN': d.get('tn_count', 0),
            'FN': d.get('fn_count', 0),
            'precision': d.get('precision', 0),
            'recall': d.get('recall', 0),
            'f1': d.get('f1', 0),
            'fp_rate': d.get('fp_rate', 0),
            'avg_time_ms': d.get('avg_time_ms', 0),
        })

    # 16 CVE多工具对比 (只有metrics, 无FP/TN因全TP)
    cve = _load('cve_16')
    for tool, d in cve.get('metrics', {}).items():
        rows.append({
            'benchmark': 'cve_16',
            'tool': tool,
            'samples': d.get('total', 16),
            'TP': d.get('TP', 0),
            'FP': d.get('FP', 0),
            'TN': d.get('TN', 0),
            'FN': d.get('FN', 0),
            'precision': d.get('precision', 0),
            'recall': d.get('recall', 0),
            'f1': d.get('f1', 0),
            'fp_rate': 0,
            'avg_time_ms': 0,
        })

    # 17 CVE GAPSBV-CJ基准 — 从core_innovation.md Section 20.7的实验数据
    cj_17_data = {
        'BinMind-baseline': {'tp': 12, 'fp': 3, 'tn': 1, 'fn': 1,
                             'precision': 0.800, 'recall': 0.923,
                             'f1': 0.857, 'fpr': 0.750, 'avg_ms': 0.5},
        'BinMind-HOSV': {'tp': 13, 'fp': 0, 'tn': 4, 'fn': 0,
                         'precision': 1.000, 'recall': 1.000,
                         'f1': 1.000, 'fpr': 0.000, 'avg_ms': 4.8},
        'BinMind-GAPSBV-CJ': {'tp': 13, 'fp': 0, 'tn': 4, 'fn': 0,
                              'precision': 1.000, 'recall': 1.000,
                              'f1': 1.000, 'fpr': 0.000, 'avg_ms': 0.1},
        'Angr': {'tp': 13, 'fp': 4, 'tn': 0, 'fn': 0,
                 'precision': 0.765, 'recall': 1.000,
                 'f1': 0.867, 'fpr': 1.000, 'avg_ms': 817.3},
    }
    for tool, d in cj_17_data.items():
        rows.append({
            'benchmark': 'gapsbv_cj_17',
            'tool': tool,
            'samples': 17,
            'TP': d['tp'], 'FP': d['fp'], 'TN': d['tn'], 'FN': d['fn'],
            'precision': d['precision'], 'recall': d['recall'],
            'f1': d['f1'], 'fp_rate': d['fpr'], 'avg_time_ms': d['avg_ms'],
        })

    csv_path = OUT / 'unified_comparison.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['benchmark', 'tool', 'samples',
                        'TP', 'FP', 'TN', 'FN', 'precision', 'recall',
                        'f1', 'fp_rate', 'avg_time_ms'])
        w.writeheader()
        w.writerows(rows)
    print(f'CSV: {csv_path} ({len(rows)} rows)')
    return rows


def gen_latex(rows):
    """生成论文级LaTeX对比表."""
    lines = [
        r'% Auto-generated unified comparison table',
        r'% Generated: 2026-08-09',
        r'',
        r'% Table 1: Cross-type 123-sample benchmark',
        r'\begin{table}[htbp]',
        r'\centering',
        r'\caption{Cross-Type Vulnerability Detection (123 samples, 5 vuln classes)}',
        r'\label{tab:cross-type}',
        r'\begin{tabular}{lrrrrrr}',
        r'\toprule',
        r'\textbf{Tool} & \textbf{N} & \textbf{P} & \textbf{R} & \textbf{F1} & \textbf{FPR} & \textbf{ms} \\',
        r'\midrule',
    ]
    for r in rows:
        if r['benchmark'] == 'cross_type_123':
            lines.append(
                f"{r['tool'].replace('_', '-')} & {r['samples']} & "
                f"{r['precision']:.1%} & {r['recall']:.1%} & {r['f1']:.3f} & "
                f"{r['fp_rate']:.1%} & {r['avg_time_ms']} \\\\")
    lines.extend([
        r'\bottomrule', r'\end{tabular}', r'\end{table}', r'',
        r'% Table 2: 16 CVE multi-tool comparison',
        r'\begin{table}[htbp]',
        r'\centering',
        r'\caption{CVE-Level Multi-Tool Detection (16 real-world CVEs)}',
        r'\label{tab:cve}',
        r'\begin{tabular}{lrrrr}',
        r'\toprule',
        r'\textbf{Tool} & \textbf{TP} & \textbf{FN} & \textbf{F1} & \textbf{Avg ms} \\',
        r'\midrule',
    ])
    for r in rows:
        if r['benchmark'] == 'cve_16':
            lines.append(
                f"{r['tool']} & {r['TP']} & {r['FN']} & {r['f1']:.3f} & "
                f"{r['avg_time_ms']:.0f} \\\\")
    lines.extend([
        r'\bottomrule', r'\end{tabular}', r'\end{table}', r'',
        r'% Table 3: GAPSBV-CJ 17 CVE benchmark',
        r'\begin{table}[htbp]',
        r'\centering',
        r'\caption{GAPSBV-CJ Constraint-Join Detection (17 CVE + safe samples)}',
        r'\label{tab:cj}',
        r'\begin{tabular}{lrrrrr}',
        r'\toprule',
        r'\textbf{Tool} & \textbf{P} & \textbf{R} & \textbf{F1} & \textbf{FPR} & \textbf{ms} \\',
        r'\midrule',
    ])
    for r in rows:
        if r['benchmark'] == 'gapsbv_cj_17':
            lines.append(
                f"{r['tool']} & {r['precision']:.1%} & {r['recall']:.1%} & "
                f"{r['f1']:.3f} & {r['fp_rate']:.1%} & {r['avg_time_ms']:.1f} \\\\")
    lines.extend([
        r'\bottomrule', r'\end{tabular}', r'\end{table}',
    ])

    tex_path = OUT / 'unified_comparison.tex'
    with open(tex_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'LaTeX: {tex_path}')


def gen_summary_json(rows):
    """生成人类可读的JSON汇总."""
    summary = {}
    for r in rows:
        bm = r['benchmark']
        if bm not in summary:
            summary[bm] = []
        summary[bm].append(r)

    # 消融数据
    for name, key in [('heap_ablation', 'heap_ensemble'),
                      ('uaf_ablation', 'uaf_ensemble'),
                      ('fmt_ablation', 'fmt_regression'),
                      ('int_ablation', 'int_regression')]:
        d = _load(key)
        if d:
            summary[name] = d

    json_path = OUT / 'unified_summary.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f'JSON: {json_path}')


def gen_chart_text(rows):
    """生成纯文本ASCII图表（无matplotlib依赖时的fallback）."""
    lines = ['=' * 72, 'UNIFIED MULTI-TOOL COMPARISON', '=' * 72, '']

    # 123样本
    lines.append('Cross-Type 123-Sample Benchmark:')
    lines.append(f'{"Tool":<22} {"P":>6} {"R":>6} {"F1":>6} {"FPR":>6} {"ms":>6}')
    lines.append('-' * 52)
    for r in rows:
        if r['benchmark'] == 'cross_type_123':
            lines.append(f"{r['tool']:<22} {r['precision']:>5.1%} {r['recall']:>5.1%} "
                        f"{r['f1']:>6.3f} {r['fp_rate']:>5.1%} {r['avg_time_ms']:>6}")

    lines.append('')
    lines.append('16 CVE Multi-Tool Benchmark:')
    lines.append(f'{"Tool":<22} {"TP":>4} {"FN":>4} {"F1":>6}')
    lines.append('-' * 36)
    for r in rows:
        if r['benchmark'] == 'cve_16':
            lines.append(f"{r['tool']:<22} {r['TP']:>4} {r['FN']:>4} {r['f1']:>6.3f}")

    lines.append('')
    lines.append('17 CVE GAPSBV-CJ Benchmark:')
    lines.append(f'{"Tool":<25} {"P":>6} {"R":>6} {"F1":>6} {"FPR":>6} {"ms":>6}')
    lines.append('-' * 55)
    for r in rows:
        if r['benchmark'] == 'gapsbv_cj_17':
            lines.append(f"{r['tool']:<25} {r['precision']:>5.1%} {r['recall']:>5.1%} "
                        f"{r['f1']:>6.3f} {r['fp_rate']:>5.1%} {r['avg_time_ms']:>6.1f}")

    lines.append('')
    lines.append('=' * 72)
    txt_path = OUT / 'unified_comparison.txt'
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'TXT:  {txt_path}')
    print('\n'.join(lines))


if __name__ == '__main__':
    rows = gen_csv()
    gen_latex(rows)
    gen_summary_json(rows)
    gen_chart_text(rows)
    print(f'\nAll deliverables in: {OUT}')
