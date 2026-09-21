"""分配容量溯源回归结果收集与指标计算 — 汇总扫描结果为可量化指标.

创建: 2025-03-03
输入: scan_runner 生成的 results/*.json (含 manifest 期望标签)
输出:
  report.json         汇总指标 (recall/precision/F1/FP率/削减率)
  report.csv          逐样本行
  reduction.json      分配容量溯源 vs 基线 的误报削减对照

指标定义 (以"样本级检测"计):
  TP   vuln 样本被检出
  FN   vuln 样本漏检
  FP   clean 样本被误报
  TN   clean 样本正确放行
  recall = TP/(TP+FN); precision = TP/(TP+FP)
  fp_rate = FP/(FP+TN)          (clean 样本上的误报比例)
  fp_reduction = (base_fp - acpe_fp)/base_fp
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
            res = json.loads(f.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            continue
        rows.append(res)
    return rows


def expected_map(root: Path) -> dict:
    manifest = root / 'manifest.json'
    if not manifest.exists():
        return {}
    data = json.loads(manifest.read_text(encoding='utf-8'))
    return {d['id']: d['expected'] for d in data}


def metrics(detected: dict, expected: dict) -> dict:
    """按样本级检测计算混淆与指标."""
    tp = fp = tn = fn = 0
    per = []
    for sid, exp in expected.items():
        d = detected.get(sid, False)
        if exp == 'vuln':
            if d:
                tp += 1
            else:
                fn += 1
        else:
            if d:
                fp += 1
            else:
                tn += 1
        per.append({'id': sid, 'expected': exp, 'detected': d})
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'recall': round(recall, 4),
        'precision': round(precision, 4),
        'f1': round(f1, 4),
        'fp_rate': round(fp_rate, 4),
        'per_sample': per,
    }


def collect(root: Path, results_dir: Path) -> dict:
    rows = load_results(root, results_dir)
    expected = expected_map(root)
    acpe_det = {}
    base_det = {}
    acpe_kept = {}
    base_kept = {}
    for r in rows:
        sid = r.get('id', '')
        acpe_det[sid] = r.get('acpe', {}).get('detected', False)
        base_det[sid] = r.get('baseline', {}).get('detected', False)
        acpe_kept[sid] = r.get('acpe', {}).get('kept', 0)
        base_kept[sid] = r.get('baseline', {}).get('kept', 0)

    acpe_m = metrics(acpe_det, expected)
    base_m = metrics(base_det, expected)

    base_fp = base_m['fp']
    acpe_fp = acpe_m['fp']
    fp_reduction = ((base_fp - acpe_fp) / base_fp * 100
                    if base_fp else 0.0)
    # 告警级削减: 保留写入总数的相对下降
    kept_red = ((sum(base_kept.values()) - sum(acpe_kept.values()))
                / sum(base_kept.values()) * 100 if sum(base_kept.values()) else 0.0)

    report = {
        'sample_count': len(expected),
        'baseline': base_m,
        'acpe': acpe_m,
        'fp_reduction_pct': round(fp_reduction, 2),
        'alert_reduction_pct': round(kept_red, 2),
        'per_sample': [
            {
                'id': p['id'], 'expected': p['expected'],
                'acpe_detected': acpe_det.get(p['id'], False),
                'baseline_detected': base_det.get(p['id'], False),
                'acpe_kept': acpe_kept.get(p['id'], 0),
                'baseline_kept': base_kept.get(p['id'], 0),
            }
            for p in acpe_m['per_sample']
        ],
    }
    return report


def write_report(report: dict, root: Path, results_dir: Path) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / 'report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    with open(results_dir / 'report.csv', 'w', newline='',
              encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=[
            'id', 'expected', 'acpe_detected', 'baseline_detected',
            'acpe_kept', 'baseline_kept'])
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
    write_report(report, root, results_dir)
    print(json.dumps({
        'acpe': report['acpe'], 'baseline': report['baseline'],
        'fp_reduction_pct': report['fp_reduction_pct'],
        'alert_reduction_pct': report['alert_reduction_pct'],
    }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
