"""结果收集与对比模块 — 汇总扫描结果并计算混淆矩阵指标.

  - ground truth 来源: 样本目录 truth.json {"class": "TP"|"TN"}.
  - TP 判定: 检出 (kept>0) 且样本为 TP → TP; 未检出 → FN.
    TN 判定: 未检出且样本为 TN → TN; 检出 → FP.
  - 输出两组指标: BASE (压缩前) 与 分配契约流保持 (压缩后), 对比出
    误报降低率与召回保持率.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'


def load_truth() -> Dict[str, str]:
    truth = {}
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        t = d / 'truth.json'
        if t.exists():
            try:
                data = json.loads(t.read_text(encoding='utf-8'))
                truth[d.name] = data.get('class', '')
            except Exception:
                truth[d.name] = ''
    return truth


def confusion(detected: Dict[str, bool], truth: Dict[str, str]):
    tp = sum(1 for s in truth if truth[s] == 'TP' and detected.get(s))
    fn = sum(1 for s in truth if truth[s] == 'TP' and not detected.get(s))
    tn = sum(1 for s in truth if truth[s] == 'TN' and not detected.get(s))
    fp = sum(1 for s in truth if truth[s] == 'TN' and detected.get(s))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1, precision + recall) if \
        (precision + recall) else 0.0
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4)}


def evaluate(scan_results: List[dict]) -> dict:
    truth = load_truth()
    det_base = {r['sample']: r.get('base', 0) > 0 for r in scan_results}
    det_acfpc = {r['sample']: r.get('kept', 0) > 0 for r in scan_results}
    base = confusion(det_base, truth)
    acfpc = confusion(det_acfpc, truth)
    fp_reduction = 0.0
    if base['fp'] > 0:
        fp_reduction = round((base['fp'] - acfpc['fp']) / base['fp'] * 100, 1)
    recall_delta = round(acfpc['recall'] - base['recall'], 4)
    return {
        'base': base,
        'acfpc': acfpc,
        'fp_reduction_pct': fp_reduction,
        'recall_delta': recall_delta,
        'truth': truth,
        'per_sample': [
            {'sample': r['sample'],
             'truth': truth.get(r['sample'], '?'),
             'base_detected': det_base.get(r['sample']),
             'acfpc_detected': det_acfpc.get(r['sample']),
             'base': r.get('base', 0),
             'kept': r.get('kept', 0),
             'suppressed': r.get('suppressed', 0),
             'elapsed_ms': r.get('elapsed_ms', 0)}
            for r in scan_results],
    }


def main():
    ap = argparse.ArgumentParser(description='ACFPC 结果收集与对比')
    ap.add_argument('input', nargs='?', default='scan_results.json')
    ap.add_argument('--json', type=str, default='eval_report.json')
    ap.add_argument('--csv', type=str, default='eval_report.csv')
    args = ap.parse_args()
    scan = json.loads(Path(args.input).read_text(encoding='utf-8'))
    report = evaluate(scan.get('samples', []))
    print(f"BASE  : {report['base']}")
    print(f"ACFPC : {report['acfpc']}")
    print(f"FP reduction: {report['fp_reduction_pct']}%  "
          f"recall delta: {report['recall_delta']}")
    for s in report['per_sample']:
        print(f"  {s['sample']:<34} {s['truth']:<3} "
              f"base={s['base']} kept={s['kept']} sup={s['suppressed']}")
    Path(args.json).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    if args.csv:
        import csv
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(report['per_sample'][0]))
            w.writeheader()
            w.writerows(report['per_sample'])
    print(f'saved: {args.json} {args.csv}')


if __name__ == '__main__':
    main()
