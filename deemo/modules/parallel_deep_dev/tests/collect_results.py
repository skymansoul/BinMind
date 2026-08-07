"""结果收集与对比模块 — 汇总逐样本扫描结果。

按工具计算混淆矩阵与指标 (precision/recall/F1/FPR/accuracy),
输出 per_sample 表与 summary CSV/JSON, 供图表与论文表格取数。
"""

import csv
import json
from pathlib import Path

RESULT_DIR = Path(__file__).resolve().parent / 'results'
SUMMARY_JSON = Path(__file__).resolve().parent / 'regression_results.json'
SUMMARY_CSV = Path(__file__).resolve().parent / 'regression_summary.csv'
PER_SAMPLE_CSV = Path(__file__).resolve().parent / 'per_sample.csv'


def load_all() -> list:
    out = []
    for f in sorted(RESULT_DIR.glob('*.json')):
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


def write_artifacts(results: list, metrics: dict) -> None:
    """写汇总 JSON/CSV/per-sample CSV。"""
    with open(SUMMARY_JSON, 'w', encoding='utf-8') as f:
        json.dump({'samples': len(results), 'tools': metrics},
                  f, ensure_ascii=False, indent=2)

    with open(SUMMARY_CSV, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['tool', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall',
                    'f1', 'fpr', 'accuracy', 'avg_ms'])
        for tool, m in sorted(metrics.items()):
            w.writerow([tool, m['tp'], m['fp'], m['tn'], m['fn'],
                        m['precision'], m['recall'], m['f1'], m['fpr'],
                        m['accuracy'], m['avg_ms']])

    with open(PER_SAMPLE_CSV, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['sample', 'truth', 'cve', 'pattern',
                    'CACBV', 'CACBV_ms', 'Baseline', 'Baseline_ms'])
        for r in sorted(results, key=lambda x: x['name']):
            c = r['tools']['CACBV']
            b = r['tools']['Baseline']
            w.writerow([r['name'], 'vuln' if r['is_vuln'] else 'safe',
                        r.get('cve', ''), r.get('pattern', ''),
                        'HIT' if c['detected'] else '-', c['ms'],
                        'HIT' if b['detected'] else '-', b['ms']])


def main() -> None:
    results = load_all()
    if not results:
        print('[collect] no scan results; run scan_scheduler first')
        return
    metrics = compute_metrics(results)
    write_artifacts(results, metrics)

    print(f'[collect] {len(results)} samples, {len(metrics)} tools')
    for tool, m in sorted(metrics.items()):
        print(f'  {tool:10s} P={m["precision"]:.3f} R={m["recall"]:.3f} '
              f'F1={m["f1"]:.3f} FPR={m["fpr"]:.3f} '
              f'({m["tp"]}T/{m["fp"]}F/{m["tn"]}N/{m["fn"]}Fn) '
              f'{m["avg_ms"]}ms')


if __name__ == '__main__':
    main()
