"""结果解析模块 -- 从扫描结果JSON生成统计报告。

输出: 检出率/误报率/漏报率/平均耗时表格
"""
import json, sys
from collections import defaultdict

# 每个样本的期望漏洞类型和数量(ground truth)
GROUND_TRUTH = {
    'cve_sample_01_stack_overflow': {'type': 'stack_overflow', 'expected': 1},
    'cve_sample_02_format_string': {'type': 'format_string', 'expected': 1},
    'cve_sample_03_heap_overflow': {'type': 'heap', 'expected': 1},
    'cve_sample_04_double_free': {'type': 'heap', 'expected': 1},
    'cve_sample_05_uaf': {'type': 'heap', 'expected': 1},
    'cve_sample_06_stack_canary': {'type': 'stack_overflow', 'expected': 1},
    'cve_sample_07_format_indirect': {'type': 'format_string', 'expected': 1},
    'cve_sample_08_heap_overflow_large': {'type': 'heap', 'expected': 1},
    'cve_sample_09_uaf_complex': {'type': 'heap', 'expected': 1},
    'cve_sample_10_stack_off_by_one': {'type': 'stack_overflow', 'expected': 1},
}

def parse_findings(stdout_json):
    try:
        data = json.loads(stdout_json) if isinstance(stdout_json, str) else stdout_json
        findings = data.get('findings', data.get('results', []))
        if isinstance(findings, list):
            return findings
        return []
    except (json.JSONDecodeError, TypeError):
        return []

def compute_metrics(results_json_path):
    with open(results_json_path) as f:
        data = json.load(f)

    results = data.get('results', [])
    by_scan_type = defaultdict(lambda: {
        'tp': 0, 'fp': 0, 'fn': 0, 'elapsed': [], 'detections': 0,
    })

    for r in results:
        sample = r.get('sample', '')
        stype = r.get('scan_type', '')
        gt = GROUND_TRUTH.get(sample, {})
        expected_type = gt.get('type', '')
        expected_count = gt.get('expected', 0)

        findings = parse_findings(r.get('stdout', ''))
        n_found = len(findings)
        stats = by_scan_type[stype]
        stats['elapsed'].append(r.get('elapsed', 0))

        if stype == expected_type and n_found >= expected_count:
            stats['tp'] += 1
            stats['detections'] += n_found
        elif stype == expected_type and n_found < expected_count:
            stats['fn'] += 1
        elif n_found > 0:
            stats['fp'] += 1
            stats['detections'] += n_found

    # 生成报告
    report = {}
    for stype, stats in sorted(by_scan_type.items()):
        total = stats['tp'] + stats['fn']
        precision = stats['tp'] / max(stats['tp'] + stats['fp'], 1)
        recall = stats['tp'] / max(total, 1)
        avg_time = sum(stats['elapsed']) / max(len(stats['elapsed']), 1)
        report[stype] = {
            'true_positives': stats['tp'],
            'false_positives': stats['fp'],
            'false_negatives': stats['fn'],
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1': round(2 * precision * recall / max(precision + recall, 0.001), 3),
            'avg_elapsed_sec': round(avg_time, 2),
            'total_detections': stats['detections'],
        }
    return report

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python result_parser.py <results.json>")
        sys.exit(1)
    report = compute_metrics(sys.argv[1])
    print(json.dumps(report, indent=2))
