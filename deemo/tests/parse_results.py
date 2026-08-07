# 创建: 2026-05-28
"""结果解析模块 — 汇总 scan_results.json, 计算检出率/误报率/耗时分布。

已知 ground truth (硬编码): 每个样本的预期漏洞类型和数量。
"""

import json, os, sys
from collections import defaultdict

SCAN_JSON = os.path.join(os.path.dirname(__file__), 'scan_results.json')

# 每个样本的 ground truth: {sample_name: expected_vuln_type}
GROUND_TRUTH = {
    'heap_overflow_01': {'type': 'heap_overflow', 'count': 1},
    'heap_overflow_02': {'type': 'heap_overflow', 'count': 1},
    'uaf_01': {'type': 'use_after_free', 'count': 1},
    'uaf_02': {'type': 'use_after_free', 'count': 1},
    'format_string_01': {'type': 'format_string', 'count': 1},
    'format_string_02': {'type': 'format_string', 'count': 1},
    'stack_overflow_01': {'type': 'stack_overflow', 'count': 1},
    'stack_overflow_02': {'type': 'stack_overflow', 'count': 1},
    'double_free_01': {'type': 'double_free', 'count': 1},
    'integer_overflow_01': {'type': 'integer_overflow', 'count': 1},
}


def load_scan_results() -> list[dict]:
    with open(SCAN_JSON) as f:
        return json.load(f)


def analyze(results: list[dict]) -> dict:
    by_type = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'total': 0, 'times': []})
    overall = {'total_samples': len(results), 'detected': 0, 'missed': 0,
               'avg_time': 0.0, 'by_compiler': defaultdict(list)}

    for r in results:
        name = r.get('sample_name', '')
        gt = GROUND_TRUTH.get(name)
        if gt is None:
            continue

        vuln_type = gt['type']
        detected = r.get('findings', 0) > 0
        elapsed = r.get('elapsed_sec', 0)

        stats = by_type[vuln_type]
        stats['total'] += 1
        stats['times'].append(elapsed)
        if detected:
            stats['tp'] += 1
            overall['detected'] += 1
        else:
            stats['fn'] += 1
            overall['missed'] += 1

        compiler_key = r.get('compiler', 'unknown')
        overall['by_compiler'][compiler_key].append(1 if detected else 0)

    # 计算比率
    for vt, s in by_type.items():
        s['detection_rate'] = round(s['tp'] / max(1, s['total']), 3)
        s['avg_time'] = round(sum(s['times']) / max(1, len(s['times'])), 1)

    overall['detection_rate'] = round(overall['detected'] / max(1, overall['total_samples']), 3)
    all_times = [r.get('elapsed_sec', 0) for r in results]
    overall['avg_time'] = round(sum(all_times) / max(1, len(all_times)), 1)

    for ck, detections in overall['by_compiler'].items():
        overall['by_compiler'][ck] = round(sum(detections) / max(1, len(detections)), 3)

    return {'by_type': dict(by_type), 'overall': overall}


def print_report(analysis: dict):
    print('=' * 60)
    print('  REGRESSION TEST REPORT')
    print('=' * 60)
    overall = analysis['overall']
    print(f'\n  Overall: {overall["detection_rate"]:.1%} detection rate '
          f'({overall["detected"]}/{overall["total_samples"]}), '
          f'avg {overall["avg_time"]}s')
    print(f'\n  By compiler:')
    for ck, rate in overall['by_compiler'].items():
        print(f'    {ck}: {rate:.1%}')

    print(f'\n  By vulnerability type:')
    print(f'  {"Type":<22} {"Samples":<8} {"Detected":<9} {"Rate":<7} {"Avg Time":<8}')
    for vt, s in sorted(analysis['by_type'].items()):
        print(f'  {vt:<22} {s["total"]:<8} {s["tp"]:<9} '
              f'{s["detection_rate"]:<7.1%} {s["avg_time"]:<8}s')


def main():
    if not os.path.isfile(SCAN_JSON):
        print(f'Scan results not found: {SCAN_JSON}')
        print('Run run_scanner.py first.')
        return
    results = load_scan_results()
    report = analyze(results)
    print_report(report)
    out_path = os.path.join(os.path.dirname(__file__), 'regression_report.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f'\nFull report saved to: {out_path}')


if __name__ == '__main__':
    main()
