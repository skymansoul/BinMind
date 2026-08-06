# tests/framework/parser.py
# 结果解析模块: 汇总扫描结果, 计算检出率/误报率/漏报率
import json
from dataclasses import dataclass, field
from typing import List, Dict
from collections import defaultdict

# Ground truth for each CVE sample
GROUND_TRUTH = {
    'CVE-2016-6301_heap_overflow': {'type': 'heap_overflow', 'vuln': True},
    'CVE-2014-0160_heartbleed': {'type': 'heap_overflow', 'vuln': True},
    'CVE-2019-0708_uaf': {'type': 'uaf', 'vuln': True},
    'CVE-2020-7460_uaf': {'type': 'uaf', 'vuln': True},
    'CVE-2001-0017_format_string': {'type': 'format_string', 'vuln': True},
    'CVE-2012-0809_format_string': {'type': 'format_string', 'vuln': True},
    'CVE-2023-0179_stack_overflow': {'type': 'stack_overflow', 'vuln': True},
    'CVE-2022-2588_double_free': {'type': 'double_free', 'vuln': True},
    'CVE-2024-21762_off_by_one': {'type': 'heap_overflow', 'vuln': True},
    'CVE-2023-44487_use_after_scope': {'type': 'uaf', 'vuln': True},
}


@dataclass
class AggregateMetrics:
    total_samples: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    avg_duration_sec: float = 0.0
    max_memory_mb: float = 0.0
    per_type: Dict[str, dict] = field(default_factory=dict)
    per_optimize: Dict[str, dict] = field(default_factory=dict)


def compute_metrics(scan_results: List,
                    ground_truth: Dict = None) -> AggregateMetrics:
    """Compute detection metrics from scan results."""
    if ground_truth is None:
        ground_truth = GROUND_TRUTH
    m = AggregateMetrics()
    m.total_samples = len(scan_results)
    type_stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'total': 0})
    opt_stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'total': 0})

    for r in scan_results:
        gt = ground_truth.get(r.sample_name)
        if gt is None:
            continue
        gt_type = gt['type']
        has_vuln = gt['vuln']
        detected = len(r.findings) > 0 and any(
            f.get('confidence', 0) > 0.4 for f in r.findings)

        opt_stats[r.optimize_level]['total'] += 1
        type_stats[gt_type]['total'] += 1

        if has_vuln and detected:
            m.true_positives += 1
            type_stats[gt_type]['tp'] += 1
            opt_stats[r.optimize_level]['tp'] += 1
        elif has_vuln and not detected:
            m.false_negatives += 1
            type_stats[gt_type]['fn'] += 1
            opt_stats[r.optimize_level]['fn'] += 1
        elif not has_vuln and detected:
            m.false_positives += 1
            type_stats[gt_type]['fp'] += 1
            opt_stats[r.optimize_level]['fp'] += 1

    total = max(m.total_samples, 1)
    m.detection_rate = round(m.true_positives / total, 3)
    m.false_positive_rate = round(
        m.false_positives / max(m.false_positives + m.true_positives, 1), 3)
    m.avg_duration_sec = round(
        sum(getattr(r, 'duration_sec', 0) for r in scan_results) / total, 3)

    for t, s in type_stats.items():
        tot = max(s['total'], 1)
        m.per_type[t] = {
            'detection_rate': round(s['tp'] / tot, 3),
            'false_positive_rate': round(s['fp'] / max(s['fp'] + s['tp'], 1), 3),
            'total': s['total'],
        }
    for o, s in opt_stats.items():
        tot = max(s['total'], 1)
        m.per_optimize[o] = {
            'detection_rate': round(s['tp'] / tot, 3),
            'total': s['total'],
        }

    return m


def metrics_to_json(metrics: AggregateMetrics) -> str:
    """Serialize metrics to JSON."""
    return json.dumps({
        'total_samples': metrics.total_samples,
        'true_positives': metrics.true_positives,
        'false_positives': metrics.false_positives,
        'false_negatives': metrics.false_negatives,
        'detection_rate': metrics.detection_rate,
        'false_positive_rate': metrics.false_positive_rate,
        'avg_duration_sec': metrics.avg_duration_sec,
        'per_type': dict(metrics.per_type),
        'per_optimize': dict(metrics.per_optimize),
    }, indent=2)


if __name__ == '__main__':
    # Quick test with empty results
    m = compute_metrics([])
    print(metrics_to_json(m))
