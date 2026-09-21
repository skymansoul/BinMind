"""
格式串溢出验证结果收集与对比模块.

汇总扫描结果, 计算既有检测器与格式串溢出验证两档的 TP/FP/TN/FN 及指标,
输出 CSV 明细与 JSON 汇总. 与 uovf 收集模块同构, 键名用 fovf.
"""

from __future__ import annotations

import csv
import json
from typing import Dict, List


def _confusion(predicted: bool, gt: bool):
    if gt and predicted:
        return 'tp'
    if gt and not predicted:
        return 'fn'
    if not gt and predicted:
        return 'fp'
    return 'tn'


def tool_metrics(results: List[Dict], mode: str) -> Dict:
    m = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'total_ms': 0.0}
    for r in results:
        rec = r.get(mode) or {}
        if not rec.get('success'):
            continue
        m[_confusion(rec.get('verdict') == 'OVERFLOW',
                     r.get('is_vuln', True))] += 1
        m['total_ms'] += rec.get('elapsed_ms', 0)
    tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(prec, 4), 'recall': round(recall, 4),
            'f1': round(f1, 4), 'fpr': round(fpr, 4),
            'avg_ms': round(m['total_ms'] / total, 1) if total else 0.0}


def summarize(results: List[Dict]) -> Dict:
    base = tool_metrics(results, 'existing')
    full = tool_metrics(results, 'fovf')
    return {
        'tools': {'Existing': base, 'FOVF': full},
        'fp_reduction_ratio': round(
            (base['fp'] - full['fp']) / base['fp'] if base['fp'] > 0 else 0.0,
            4),
        'recall_delta': round(full['recall'] - base['recall'], 4),
        'f1_delta': round(full['f1'] - base['f1'], 4),
        'samples_total': len(results),
    }


def write_csv(results: List[Dict], path: str) -> None:
    cols = ['name', 'cve_id', 'is_vuln',
            'existing_verdict', 'existing_detections', 'existing_ms',
            'fovf_verdict', 'fovf_detections', 'fovf_ms',
            'existing_correct', 'fovf_correct']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in results:
            e, u = r.get('existing') or {}, r.get('fovf') or {}
            gt = r.get('is_vuln', True)
            w.writerow({
                'name': r['name'], 'cve_id': r.get('cve_id', ''),
                'is_vuln': gt,
                'existing_verdict': e.get('verdict', ''),
                'existing_detections': e.get('detections', 0),
                'existing_ms': e.get('elapsed_ms', 0),
                'fovf_verdict': u.get('verdict', ''),
                'fovf_detections': u.get('detections', 0),
                'fovf_ms': u.get('elapsed_ms', 0),
                'existing_correct': (e.get('verdict') == 'OVERFLOW') == gt,
                'fovf_correct': (u.get('verdict') == 'OVERFLOW') == gt,
            })


def write_json(summary: Dict, results: List[Dict], path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({'summary': summary, 'per_sample': results}, f,
                  indent=2, ensure_ascii=False)
