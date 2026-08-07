"""
HOVF 多工具对比主实验.

对全部堆溢出样本运行 基线/HOVF/Angr/Ghidra/QEMU 五条通道, 输出:
  hovf_benchmark.csv        逐样本统一格式明细
  hovf_metrics.json         逐工具 TP/FP/TN/FN + 指标
  hovf_result_table.tex     LaTeX 对比表格

样本集: tests/cve_samples/heap_overflow (60, 带 ground truth) +
        samples/cve_heap_overflow (16 真实 CVE) + samples_heap CVE-*.
判定阈值 0.40 与回归一致.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from typing import Dict, List

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EVAL_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if EVAL_DIR not in sys.path:
    sys.path.insert(0, EVAL_DIR)

from tests.regression.hovf_regression.ground_truth import load_all
from eval.hovf_runner import run_all

_ACCEPT = 'OVERFLOW'


def _compute_metrics(results: List[Dict]) -> Dict[str, Dict]:
    tools: Dict[str, Dict] = {}
    for r in results:
        tool = r.get('tool', '')
        if not tool or not r.get('success'):
            continue
        m = tools.setdefault(tool, {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
                                    'total_ms': 0.0, 'peak_max': 0.0})
        gt = r['ground_truth']
        pred = r['verdict'] == _ACCEPT
        if gt and pred:
            m['tp'] += 1
        elif gt:
            m['fn'] += 1
        elif pred:
            m['fp'] += 1
        else:
            m['tn'] += 1
        m['total_ms'] += r.get('elapsed_ms', 0)
        m['peak_max'] = max(m['peak_max'], r.get('peak_mb', 0))
    for m in tools.values():
        tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
        denom_p = tp + fp
        denom_r = tp + fn
        m['precision'] = round(tp / denom_p, 4) if denom_p else 0.0
        m['recall'] = round(tp / denom_r, 4) if denom_r else 0.0
        pr = m['precision'] + m['recall']
        m['f1'] = round(2 * m['precision'] * m['recall'] / pr, 4) if pr else 0.0
        m['fpr'] = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
        m['avg_ms'] = round(m['total_ms'] / (tp + fp + tn + fn), 1)
    return tools


def _write_csv(results: List[Dict], path: str) -> None:
    cols = ['sample', 'cve_id', 'ground_truth', 'tool', 'verdict',
            'detections', 'elapsed_ms', 'peak_mb', 'success', 'error']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in results:
            w.writerow(r)


def _write_latex(metrics: Dict, path: str, n_samples: int) -> None:
    lines = [
        '% Auto-generated: BinMind-HOVF multi-tool heap overflow benchmark',
        '% Generated: ' + time.strftime('%Y-%m-%d'), '',
        r'\begin{table}[htbp]', r'\centering',
        r'\caption{Multi-Tool Heap Overflow Detection Comparison '
        r'(HOVF benchmark, %d samples)}' % n_samples,
        r'\label{tab:hovf-multitool}',
        r'\begin{tabular}{lrrrrrrrrrr}', r'\toprule',
        r'\textbf{Tool} & \textbf{TP} & \textbf{FP} & \textbf{TN} & '
        r'\textbf{FN} & \textbf{Prec} & \textbf{Recall} & \textbf{F1} & '
        r'\textbf{FPR} & \textbf{Time(ms)} \\',
        r'\midrule',
    ]
    for tool in sorted(metrics):
        m = metrics[tool]
        lines.append(
            f'{tool} & {m["tp"]} & {m["fp"]} & {m["tn"]} & {m["fn"]} & '
            f'{m["precision"]*100:.1f}\\% & {m["recall"]*100:.1f}\\% & '
            f'{m["f1"]:.4f} & {m["fpr"]*100:.1f}\\% & {m["avg_ms"]:.0f} \\\\'
        )
    lines.extend([r'\bottomrule', r'\end{tabular}', r'\end{table}'])
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _find_binary(sample_dir: str) -> str:
    """在样本目录中查找可执行文件, 供外部二进制工具使用."""
    import glob
    for pat in ('*.exe', 'vuln', 'vuln.exe', 'a.out'):
        hits = glob.glob(os.path.join(sample_dir, pat))
        if hits:
            return hits[0]
    return ''


def main() -> None:
    t0 = time.perf_counter()
    samples = load_all()
    print(f'[hovf-benchmark] {len(samples)} samples')

    all_results: List[Dict] = []
    for s in samples:
        meta = {'sample': s['name'], 'cve_id': s.get('cve_id', ''),
                'ground_truth': s['is_vuln']}
        binary = _find_binary(s.get('dir', ''))
        for r in run_all(s['source'], binary):
            r.update(meta)
            all_results.append(r)

    csv_path = os.path.join(EVAL_DIR, 'hovf_benchmark.csv')
    json_path = os.path.join(EVAL_DIR, 'hovf_metrics.json')
    tex_path = os.path.join(EVAL_DIR, 'hovf_result_table.tex')
    _write_csv(all_results, csv_path)
    metrics = _compute_metrics(all_results)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    _write_latex(metrics, tex_path, len(samples))

    print(f'\n耗时 {time.perf_counter() - t0:.1f}s')
    print(f'  CSV : {csv_path}\n  JSON: {json_path}\n  LaTeX: {tex_path}\n')
    for tool, m in sorted(metrics.items()):
        print(f'  {tool:18s} TP={m["tp"]:>3} FP={m["fp"]:>3} '
              f'Prec={m["precision"]:.3f} Recall={m["recall"]:.3f} '
              f'F1={m["f1"]:.3f} FPR={m["fpr"]:.3f} {m["avg_ms"]:.0f}ms')


if __name__ == '__main__':
    main()
