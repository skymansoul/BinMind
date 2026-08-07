"""
UOVF 多工具对比主实验 (UAF).

对全部 UAF 样本运行 既有/UOVF/Angr/Ghidra/QEMU 五通道, 输出:
  uovf_benchmark.csv   逐样本统一格式
  uovf_metrics.json    逐工具指标
  uovf_result_table.tex LaTeX 对比表
"""

from __future__ import annotations

import csv
import glob
import json
import os
import sys
import time
from typing import Dict, List

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EVAL_DIR)
for p in (PROJECT_ROOT, EVAL_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from tests.regression.uovf_regression.ground_truth import load_all
from eval.uovf_runner import run_all


def _find_binary(sample_dir: str) -> str:
    for pat in ('*.exe', 'vuln', 'vuln.exe'):
        hits = glob.glob(os.path.join(sample_dir, pat))
        if hits:
            return hits[0]
    return ''


def _metrics(results: List[Dict]) -> Dict[str, Dict]:
    tools: Dict[str, Dict] = {}
    for r in results:
        if not r.get('success') or not r.get('tool'):
            continue
        m = tools.setdefault(r['tool'], {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
                                         'total_ms': 0.0})
        gt, pred = r['ground_truth'], r['verdict'] == 'OVERFLOW'
        if gt and pred:
            m['tp'] += 1
        elif gt:
            m['fn'] += 1
        elif pred:
            m['fp'] += 1
        else:
            m['tn'] += 1
        m['total_ms'] += r.get('elapsed_ms', 0)
    for m in tools.values():
        tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
        m['precision'] = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
        m['recall'] = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
        pr = m['precision'] + m['recall']
        m['f1'] = round(2 * m['precision'] * m['recall'] / pr, 4) if pr else 0.0
        m['fpr'] = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
        m['avg_ms'] = round(m['total_ms'] / (tp + fp + tn + fn), 1)
    return tools


def _write_csv(results: List[Dict], path: str) -> None:
    cols = ['sample', 'cve_id', 'ground_truth', 'tool', 'verdict',
            'detections', 'elapsed_ms', 'success', 'error']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in results:
            w.writerow(r)


def _write_latex(metrics: Dict, path: str, n: int) -> None:
    lines = [
        '% Auto-generated: UOVF multi-tool UAF benchmark',
        '% Generated: ' + time.strftime('%Y-%m-%d'), '',
        r'\begin{table}[htbp]', r'\centering',
        r'\caption{Multi-Tool UAF Detection Comparison (UOVF benchmark, '
        r'%d samples)}' % n,
        r'\label{tab:uovf-multitool}',
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
            f'{m["precision"] * 100:.1f}\\% & {m["recall"] * 100:.1f}\\% & '
            f'{m["f1"]:.4f} & {m["fpr"] * 100:.1f}\\% & {m["avg_ms"]:.0f} \\\\'
        )
    lines.extend([r'\bottomrule', r'\end{tabular}', r'\end{table}'])
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main() -> None:
    t0 = time.perf_counter()
    samples = load_all()
    print(f'[uovf-benchmark] {len(samples)} samples')
    all_results: List[Dict] = []
    for s in samples:
        meta = {'sample': s['name'], 'cve_id': s.get('cve_id', ''),
                'ground_truth': s['is_vuln']}
        for r in run_all(s['source'], _find_binary(s.get('dir', ''))):
            r.update(meta)
            all_results.append(r)
    csv_path = os.path.join(EVAL_DIR, 'uovf_benchmark.csv')
    json_path = os.path.join(EVAL_DIR, 'uovf_metrics.json')
    tex_path = os.path.join(EVAL_DIR, 'uovf_result_table.tex')
    _write_csv(all_results, csv_path)
    metrics = _metrics(all_results)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    _write_latex(metrics, tex_path, len(samples))
    print(f'\n耗时 {time.perf_counter() - t0:.1f}s')
    for tool, m in sorted(metrics.items()):
        print(f'  {tool:14s} TP={m["tp"]:>3} FP={m["fp"]:>3} '
              f'Prec={m["precision"]:.3f} Recall={m["recall"]:.3f} '
              f'F1={m["f1"]:.3f} FPR={m["fpr"]:.3f} {m["avg_ms"]:.0f}ms')


if __name__ == '__main__':
    main()
