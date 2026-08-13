"""ALPR UAF 回归结果收集与指标计算.

创建: 2025-05-12
输入: scan_runner 生成的 results/*.json (含 manifest 期望标签)
输出: report.json / report.csv (混淆矩阵与 recall/precision/F1/fp率/削减率)
用法:
  python collect_results.py [样本根目录] [--results results]
"""

import argparse
import csv
import json
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def load_results(root: Path, results_dir: Path) -> list:
    rows = []
    for f in sorted(results_dir.glob('*.json')):
        if f.name.startswith('_'):
            continue
        try:
            rows.append(json.loads(f.read_text(encoding='utf-8')))
        except (json.JSONDecodeError, OSError):
            continue
    return rows


def expected_map(root: Path) -> dict:
    manifest = root / 'manifest.json'
    if not manifest.exists():
        return {}
    return {d['id']: d['expected']
            for d in json.loads(manifest.read_text(encoding='utf-8'))}


def metrics(detected: dict, expected: dict) -> dict:
    tp = fp = tn = fn = 0
    for sid, exp in expected.items():
        d = detected.get(sid, False)
        if exp == 'vuln':
            tp += int(d)
            fn += int(not d)
        else:
            fp += int(d)
            tn += int(not d)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'recall': round(recall, 4), 'precision': round(precision, 4),
            'f1': round(f1, 4), 'fp_rate': round(fp_rate, 4)}


def collect(root: Path, results_dir: Path) -> dict:
    rows = load_results(root, results_dir)
    expected = expected_map(root)
    alpr_det, base_det = {}, {}
    alpr_kept, base_kept = {}, {}
    for r in rows:
        sid = r.get('id', '')
        alpr_det[sid] = r.get('alpr', {}).get('detected', False)
        base_det[sid] = r.get('baseline', {}).get('detected', False)
        alpr_kept[sid] = r.get('alpr', {}).get('kept', 0)
        base_kept[sid] = r.get('baseline', {}).get('kept', 0)

    alpr_m = metrics(alpr_det, expected)
    base_m = metrics(base_det, expected)
    fp_red = ((base_m['fp'] - alpr_m['fp']) / base_m['fp'] * 100
              if base_m['fp'] else 0.0)
    kept_red = ((sum(base_kept.values()) - sum(alpr_kept.values()))
                / sum(base_kept.values()) * 100 if sum(base_kept.values()) else 0.0)

    report = {
        'sample_count': len(expected),
        'baseline': base_m,
        'alpr': alpr_m,
        'fp_reduction_pct': round(fp_red, 2),
        'alert_reduction_pct': round(kept_red, 2),
        'per_sample': [
            {
                'id': sid,
                'expected': expected.get(sid, 'vuln'),
                'alpr_detected': alpr_det.get(sid, False),
                'baseline_detected': base_det.get(sid, False),
                'alpr_kept': alpr_kept.get(sid, 0),
                'baseline_kept': base_kept.get(sid, 0),
            } for sid in sorted(expected)
        ],
    }
    return report


def write_report(report: dict, results_dir: Path) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / 'report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    with open(results_dir / 'report.csv', 'w', newline='',
              encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=[
            'id', 'expected', 'alpr_detected', 'baseline_detected',
            'alpr_kept', 'baseline_kept'])
        w.writeheader()
        for p in report['per_sample']:
            w.writerow(p)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default=None)
    ap.add_argument('--results', default='results')
    args = ap.parse_args()
    root = Path(args.root) if args.root else _HERE / 'samples'
    results_dir = _HERE / args.results
    report = collect(root, results_dir)
    write_report(report, results_dir)
    print(json.dumps({'baseline': report['baseline'], 'alpr': report['alpr'],
                      'fp_reduction_pct': report['fp_reduction_pct']},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
