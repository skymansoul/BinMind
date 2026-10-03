"""结果收集与对比模块 — 汇总逐样本扫描结果。

按工具计算混淆矩阵与指标 (precision/recall/F1/FPR/accuracy),
输出 per_sample 表与 summary CSV/JSON, 供图表与论文表格取数。
用法: python tests/collect_results.py [--class heap|uaf]
"""

import argparse
import csv
import json
from pathlib import Path

from .backends import CLASS_ROOTS

TESTS = Path(__file__).resolve().parent


def load_all(res_dir: Path) -> list:
    out = []
    for f in sorted(res_dir.glob('*.json')):
        try:
            out.append(json.loads(f.read_text(encoding='utf-8')))
        except (json.JSONDecodeError, OSError):
            continue
    return out


def compute_metrics(results: list) -> dict:
    tools = {}
    for r in results:
        truth = bool(r['is_vuln'])
        for tool, info in r['tools'].items():
            m = tools.setdefault(tool, {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
                                        'total_ms': 0.0})
            m['total_ms'] += info['ms']
            if truth and info['detected']:
                m['tp'] += 1
            elif truth and not info['detected']:
                m['fn'] += 1
            elif not truth and info['detected']:
                m['fp'] += 1
            else:
                m['tn'] += 1
    for m in tools.values():
        tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
        m['precision'] = round(tp / (tp + fp), 4) if tp + fp else 0.0
        m['recall'] = round(tp / (tp + fn), 4) if tp + fn else 0.0
        pr = m['precision'] + m['recall']
        m['f1'] = round(2 * m['precision'] * m['recall'] / pr, 4) if pr else 0.0
        m['fpr'] = round(fp / (fp + tn), 4) if fp + tn else 0.0
        total = tp + fp + tn + fn
        m['accuracy'] = round((tp + tn) / total, 4) if total else 0.0
        m['avg_ms'] = round(m['total_ms'] / total, 3) if total else 0.0
    return tools


def write_artifacts(results: list, metrics: dict, sample_class: str,
                    tool: str) -> None:
    """写汇总 JSON/CSV/per-sample CSV。"""
    summary_json = TESTS / f'regression_results_{sample_class}.json'
    summary_csv = TESTS / f'regression_summary_{sample_class}.csv'
    per_sample_csv = TESTS / f'per_sample_{sample_class}.csv'

    with open(summary_json, 'w', encoding='utf-8') as f:
        json.dump({'samples': len(results), 'class': sample_class,
                   'tools': metrics}, f, ensure_ascii=False, indent=2)

    with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['tool', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall',
                    'f1', 'fpr', 'accuracy', 'avg_ms'])
        for name, m in sorted(metrics.items()):
            w.writerow([name, m['tp'], m['fp'], m['tn'], m['fn'],
                        m['precision'], m['recall'], m['f1'], m['fpr'],
                        m['accuracy'], m['avg_ms']])

    with open(per_sample_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['sample', 'truth', 'cve', 'pattern',
                    tool, f'{tool}_ms', 'Baseline', 'Baseline_ms'])
        for r in sorted(results, key=lambda x: x['name']):
            c = r['tools'].get(tool, {})
            b = r['tools']['Baseline']
            w.writerow([r['name'], 'vuln' if r['is_vuln'] else 'safe',
                        r.get('cve', ''), r.get('pattern', ''),
                        'HIT' if c.get('detected') else '-', c.get('ms', 0),
                        'HIT' if b['detected'] else '-', b['ms']])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    args = ap.parse_args()
    cfg = CLASS_ROOTS[args.sample_class]
    _, _, tool = load_backend(args.sample_class)
    results = load_all(cfg['results'])
    if not results:
        print('[collect] no scan results; run scan_scheduler first')
        return
    metrics = compute_metrics(results)
    write_artifacts(results, metrics, args.sample_class, tool)

    print(f'[collect] {args.sample_class}: {len(results)} samples, '
          f'{len(metrics)} tools')
    for name, m in sorted(metrics.items()):
        print(f'  {name:10s} P={m["precision"]:.3f} R={m["recall"]:.3f} '
              f'F1={m["f1"]:.3f} FPR={m["fpr"]:.3f} '
              f'({m["tp"]}T/{m["fp"]}F/{m["tn"]}N/{m["fn"]}Fn) '
              f'{m["avg_ms"]}ms')


def load_backend(sample_class: str):
    from .backends import load_detectors
    return load_detectors(sample_class)


if __name__ == '__main__':
    main()
