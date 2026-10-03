"""
结果解析模块 — 汇总扫描结果, 计算指标, 输出报告.

职责: 接收扫描原始结果, 与ground truth比对, 计算TP/FP/FN/TN.
不参与编译或扫描.
"""

import json
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional


# 每个样本的ground truth — 预期应检出的漏洞类型
GROUND_TRUTH = {
    'heartbleed': {'types': ['heap-overflow', 'heap-buffer-overflow']},
    'ghost': {'types': ['heap-overflow', 'heap-buffer-overflow']},
    'cryptsetup': {'types': ['privilege-escalation']},
    'pie': {'types': ['stack-overflow']},
    'exim': {'types': ['heap-overflow', 'heap-buffer-overflow']},
    'sudo': {'types': ['stack-overflow']},
    'smbghost': {'types': ['heap-overflow']},
    'dirtypipe': {'types': ['privilege-escalation']},
    'looney': {'types': ['heap-overflow', 'heap-buffer-overflow']},
}


def match_gt(sample_name: str, detected_types: List[str]) -> Dict[str, bool]:
    """将检测结果与ground truth匹配."""
    gt = None
    for key, val in GROUND_TRUTH.items():
        if key in sample_name.lower():
            gt = val
            break
    if gt is None:
        return {'matched': False, 'expected': [], 'found': detected_types}
    expected = set(gt['types'])
    found = set(detected_types)
    return {
        'matched': len(expected & found) > 0,
        'expected': sorted(expected),
        'found': sorted(found),
        'true_positives': sorted(expected & found),
        'false_negatives': sorted(expected - found),
        'false_positives': sorted(found - expected),
    }


def evaluate(results: List[Dict]) -> Dict[str, Any]:
    """评估扫描结果, 计算汇总指标.

    Returns: {summary, per_sample, confusion_matrix}.
    """
    total_tp = 0
    total_fp = 0
    total_fn = 0
    per_sample = []

    for r in results:
        binary = r.get('binary', '')
        sample_name = binary.replace('\\', '/').split('/')[-2] if '/' in binary else binary
        detected = set()
        for det_name, det_result in r.get('detectors', {}).items():
            if det_result.get('success'):
                for f in det_result.get('findings', []):
                    detected.add(f.get('type', ''))
        gt = match_gt(sample_name, list(detected))
        per_sample.append({
            'sample': sample_name,
            'binary': binary,
            'detected': sorted(detected),
            'ground_truth': gt,
        })
        tp = len(gt.get('true_positives', []))
        fn = len(gt.get('false_negatives', []))
        fp = len(gt.get('false_positives', []))
        total_tp += tp
        total_fn += fn
        total_fp += fp

    n_samples = len(results)
    detection_rate = total_tp / max(total_tp + total_fn, 1)
    false_positive_rate = total_fp / max(n_samples, 1)

    return {
        'summary': {
            'n_samples': n_samples,
            'n_detected': sum(1 for s in per_sample if s['detected']),
            'total_tp': total_tp,
            'total_fp': total_fp,
            'total_fn': total_fn,
            'detection_rate': round(detection_rate, 4),
            'false_positive_rate': round(false_positive_rate, 4),
        },
        'per_sample': per_sample,
    }


def print_report(eval_result: Dict[str, Any]):
    """打印人类可读的评估报告."""
    s = eval_result['summary']
    print('=' * 60)
    print('VULNERABILITY DETECTION REGRESSION TEST REPORT')
    print('=' * 60)
    print(f'Samples tested:  {s["n_samples"]}')
    print(f'Vulnerabilities found: {s["n_detected"]}')
    print(f'True Positives:  {s["total_tp"]}')
    print(f'False Positives: {s["total_fp"]}')
    print(f'False Negatives: {s["total_fn"]}')
    print(f'Detection Rate:  {s["detection_rate"]:.2%}')
    print(f'FP Rate:         {s["false_positive_rate"]:.2%}')
    print('-' * 60)
    for ps in eval_result['per_sample']:
        gt = ps['ground_truth']
        status = 'PASS' if gt['matched'] else 'MISS'
        print(f'  [{status}] {ps["sample"]}')
        if not gt['matched']:
            print(f'         expected: {gt["expected"]}, found: {gt["found"]}')
    print('=' * 60)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python result_parser.py <results.json>')
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        raw_results = json.load(f)
    eval_result = evaluate(raw_results)
    print_report(eval_result)
