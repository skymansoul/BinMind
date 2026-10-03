"""UAF-OG 结果收集 — 混淆矩阵与误报压缩指标.

  - ground truth: 样本目录 truth.json (TP=漏洞, TN=安全对照).
  - BASE (朴素扫描) 与 UAF-OG (代际压缩) 两套指标并行输出,
    误报降低率 = (BASE_FP - OG_FP) / BASE_FP.
"""

import argparse
import json
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'


def load_truth() -> dict:
    truth = {}
    for d in sorted(SAMPLES_DIR.iterdir()):
        if d.is_dir():
            tj = d / 'truth.json'
            if tj.exists():
                truth[d.name] = json.loads(tj.read_text(encoding='utf-8')) \
                    .get('class', '')
    return truth


def confusion(detected: dict, truth: dict) -> dict:
    tp = sum(1 for s in truth if truth[s] == 'TP' and detected.get(s))
    fn = sum(1 for s in truth if truth[s] == 'TP' and not detected.get(s))
    tn = sum(1 for s in truth if truth[s] == 'TN' and not detected.get(s))
    fp = sum(1 for s in truth if truth[s] == 'TN' and detected.get(s))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1, precision + recall)
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4)}


def evaluate(scan: list) -> dict:
    truth = load_truth()
    det_base = {r['sample']: r.get('base', 0) > 0 for r in scan}
    det_og = {r['sample']: r.get('kept', 0) > 0 for r in scan}
    base = confusion(det_base, truth)
    og = confusion(det_og, truth)
    fp_reduction = round((base['fp'] - og['fp']) / max(1, base['fp']) * 100, 1)
    return {
        'base': base, 'og': og,
        'fp_reduction_pct': fp_reduction,
        'recall_delta': round(og['recall'] - base['recall'], 4),
        'truth': truth,
        'per_sample': [
            {'sample': r['sample'],
             'truth': truth.get(r['sample'], '?'),
             'base_detected': det_base.get(r['sample']),
             'og_detected': det_og.get(r['sample']),
             'base': r.get('base', 0),
             'kept': r.get('kept', 0),
             'suppressed': r.get('suppressed', 0),
             'elapsed_ms': r.get('elapsed_ms', 0)}
            for r in scan],
    }


def main():
    ap = argparse.ArgumentParser(description='UAF-OG 结果收集')
    ap.add_argument('input', nargs='?', default='scan_results.json')
    ap.add_argument('--json', type=str, default='eval_report.json')
    ap.add_argument('--csv', type=str, default='eval_report.csv')
    args = ap.parse_args()
    scan = json.loads(Path(args.input).read_text(encoding='utf-8'))
    report = evaluate(scan.get('samples', []))
    print(f"BASE : {report['base']}")
    print(f"UAF-OG: {report['og']}")
    print(f"FP reduction: {report['fp_reduction_pct']}%  "
          f"recall delta: {report['recall_delta']}")
    for s in report['per_sample']:
        print(f"  {s['sample']:<30} {s['truth']:<3} base={s['base']} "
              f"kept={s['kept']} sup={s['suppressed']}")
    jp = Path(args.json)
    jp.parent.mkdir(parents=True, exist_ok=True)
    jp.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                  encoding='utf-8')
    if args.csv:
        import csv
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(report['per_sample'][0]))
            w.writeheader()
            w.writerows(report['per_sample'])
    print(f'saved: {args.json} {args.csv}')


if __name__ == '__main__':
    main()
