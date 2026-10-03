"""
结果收集与对比模块.

汇总扫描结果, 计算基线与堆溢出验证两档的 TP/FP/TN/FN 及
precision/recall/F1/FPR, 输出 CSV 明细与 JSON 汇总.
指标对比聚焦两类结论:
  1. FP 削减: hovf_fp < baseline_fp 的幅度
  2. 召回保持: hovf_recall >= baseline_recall 的验证
"""

from __future__ import annotations

import csv
import json
import os
from typing import Dict, List

_ACCEPT_VERDICT = 'OVERFLOW'


def _confusion(predicted: bool, gt: bool):
    if gt and predicted:
        return 'tp'
    if gt and not predicted:
        return 'fn'
    if not gt and predicted:
        return 'fp'
    return 'tn'


def compute_tool_metrics(results: List[Dict], mode: str) -> Dict:
    """按档位 (baseline|hovf) 统计指标."""
    m = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'total_ms': 0.0}
    for r in results:
        rec = r.get(mode) or {}
        if not rec.get('success'):
            continue
        cell = _confusion(rec.get('verdict') == _ACCEPT_VERDICT,
                          r.get('is_vuln', True))
        m[cell] += 1
        m['total_ms'] += rec.get('elapsed_ms', 0)
    tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (
        precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'f1': round(f1, 4), 'fpr': round(fpr, 4),
        'accuracy': round((tp + tn) / total, 4) if total else 0.0,
        'avg_ms': round(m['total_ms'] / total, 1) if total else 0.0,
    }


def summarize(results: List[Dict]) -> Dict:
    """生成对比汇总, 含 FP 削减与召回保持结论."""
    base = compute_tool_metrics(results, 'baseline')
    full = compute_tool_metrics(results, 'hovf')
    fp_reduction = ((base['fp'] - full['fp']) / base['fp']
                    if base['fp'] > 0 else 0.0)
    return {
        'tools': {
            'Baseline': base,
            'HOVF': full,
        },
        'fp_reduction_ratio': round(fp_reduction, 4),
        'recall_delta': round(full['recall'] - base['recall'], 4),
        'f1_delta': round(full['f1'] - base['f1'], 4),
        'samples_total': len(results),
    }


def write_csv(results: List[Dict], path: str) -> None:
    cols = ['name', 'cve_id', 'is_vuln',
            'baseline_verdict', 'baseline_detections', 'baseline_ms',
            'hovf_verdict', 'hovf_detections', 'hovf_ms',
            'baseline_correct', 'hovf_correct']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in results:
            b = r.get('baseline') or {}
            h = r.get('hovf') or {}
            gt = r.get('is_vuln', True)
            w.writerow({
                'name': r.get('name', ''),
                'cve_id': r.get('cve_id', ''),
                'is_vuln': gt,
                'baseline_verdict': b.get('verdict', ''),
                'baseline_detections': b.get('detections', 0),
                'baseline_ms': b.get('elapsed_ms', 0),
                'hovf_verdict': h.get('verdict', ''),
                'hovf_detections': h.get('detections', 0),
                'hovf_ms': h.get('elapsed_ms', 0),
                'baseline_correct': (
                    b.get('verdict') == _ACCEPT_VERDICT) == gt,
                'hovf_correct': (
                    h.get('verdict') == _ACCEPT_VERDICT) == gt,
            })


def write_json(summary: Dict, results: List[Dict], path: str) -> None:
    payload = {'summary': summary, 'per_sample': results}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
