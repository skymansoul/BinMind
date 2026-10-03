"""
回归测试管道 — 结果收集阶段。

从扫描结果提取 TP/FP/TN/FN 分类,
计算 Precision/Recall/F1/FPR,
生成 JSON + CSV 报告和逐样本明细。
"""
import os
import sys
import json
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXPECTED = {
    'CVE-2014-0160': ('heap-overflow', True),
    'CVE-2016-6301': ('heap-overflow', True),
    'CVE-2017-11176': ('use-after-free', True),
    'CVE-2018-6552': ('integer-overflow', True),
    'CVE-2019-1010298': ('heap-overflow', True),
    'CVE-2020-10711': ('heap-overflow', True),
    'CVE-2021-3156': ('heap-overflow', True),
    'CVE-2022-0185': ('heap-overflow', True),
    'CVE-2022-23222': ('heap-overflow', True),
    'CVE-2023-0461': ('heap-overflow', True),
    'CVE-2024-21894': ('heap-overflow', True),
    'HEAP-OVERFLOW-BASIC-01': ('heap-overflow', True),
    'HEAP-OVERFLOW-LOOP-02': ('heap-overflow', True),
    'HEAP-OVERFLOW-COND-03': ('heap-overflow', True),
    'HEAP-OVERFLOW-MULTI-06': ('heap-overflow', True),
    'HEAP-OVERFLOW-REALLOC-07': ('heap-overflow', True),
    'heap_aliased_ptr': ('heap-overflow', True),
    'heap_dynamic_index': ('heap-overflow', True),
    'heap_int_overflow_to_heap': ('heap-overflow', True),
    'heap_loop_overflow': ('heap-overflow', True),
    'heap_no_guard_check': ('heap-overflow', True),
    'heap_off_by_one': ('heap-overflow', True),
    'heap_realloc_misuse': ('heap-overflow', True),
    'heap_simple_overflow': ('heap-overflow', True),
    'heap_strcpy_overflow': ('heap-overflow', True),
    'heap_struct_write': ('heap-overflow', True),
    'HEAP-OVERFLOW-FP-04': ('heap-overflow', True),
    'HEAP-OVERFLOW-ALIGN-05': ('heap-overflow', True),
    'heap_slack_space': ('heap-overflow', True),
    'heap_guard_protected': ('heap-overflow', False),
}


def classify(expected: tuple, detected: bool) -> str:
    should_detect = expected[1]
    if should_detect and detected:
        return 'TP'
    elif should_detect and not detected:
        return 'FN'
    elif not should_detect and detected:
        return 'FP'
    else:
        return 'TN'


def compute_metrics(tp, fp, tn, fn_count):
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn_count, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)
    fp_rate = fp / max(fp + tn, 1)
    return precision, recall, f1, fp_rate


def collect_and_report(scan_results: dict, out_dir: str = None) -> dict:
    """收集扫描结果, 分类并生成报告。"""
    odir = out_dir or os.path.join(BASE, 'tests')
    tp = fp = tn = fn_count = unk = 0
    details = []

    for name, sr in scan_results.items():
        exp = EXPECTED.get(name)
        if exp is None:
            unk += 1
            exp = ('unknown', True)
        detected = sr.get('detected', False)
        verdict = classify(exp, detected)
        if verdict == 'TP':
            tp += 1
        elif verdict == 'FP':
            fp += 1
        elif verdict == 'TN':
            tn += 1
        elif verdict == 'FN':
            fn_count += 1
        details.append({
            'sample': name,
            'expected_type': exp[0],
            'should_detect': exp[1],
            'detected': detected,
            'verdict': verdict,
            'baseline_count': sr.get('baseline_count', 0),
            'gapsbv_filtered': sr.get('gapsbv_filtered', 0),
            'final_count': sr.get('findings_count', 0),
            'duration_ms': sr.get('duration_ms', 0),
            'error': sr.get('error', ''),
        })

    precision, recall, f1, fp_rate = compute_metrics(tp, fp, tn, fn_count)
    total = tp + fp + tn + fn_count

    _print_report(total, tp, fp, tn, fn_count, precision, recall, f1,
                  fp_rate, unk, details)
    _save_report(odir, total, tp, fp, tn, fn_count, precision, recall,
                 f1, fp_rate, unk, details)

    return {'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn_count,
            'precision': precision, 'recall': recall, 'f1': f1,
            'fp_rate': fp_rate, 'details': details}


def _print_report(total, tp, fp, tn, fn_count, precision, recall, f1,
                  fp_rate, unk, details):
    """打印检测报告。"""
    print(f'\n{"=" * 60}')
    print('检测结果报告')
    print(f'{"=" * 60}')
    print(f'| TP (正确检出) | {tp}                        |')
    print(f'| FP (误报)   | {fp}                        |')
    print(f'| TN (正确过滤) | {tn}                        |')
    print(f'| FN (漏报)   | {fn_count}                        |')
    print(f'| Precision   | {precision:.1%}                       |')
    print(f'| Recall      | {recall:.1%}                       |')
    print(f'| F1 Score    | {f1:.4f}                     |')
    print(f'| FP Rate     | {fp_rate:.1%}                       |')
    if unk > 0:
        print(f'| 未分类      | {unk}                        |')

    emoji = {'TP': '[TP]', 'FP': '[FP]', 'TN': '[TN]', 'FN': '[FN]'}
    for d in sorted(details, key=lambda x: (x['verdict'], x['sample'])):
        print(f"  {emoji[d['verdict']]} {d['sample']:<40s} "
              f"baseline={d['baseline_count']} "
              f"filtered={d['gapsbv_filtered']} final={d['final_count']}")


def _save_report(out_dir, total, tp, fp, tn, fn_count, precision, recall,
                 f1, fp_rate, unk, details):
    """保存 JSON 和 CSV 报告。"""
    report = {
        'summary': {
            'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn_count,
            'precision': round(precision, 4), 'recall': round(recall, 4),
            'f1': round(f1, 4), 'fp_rate': round(fp_rate, 4),
            'unclassified': unk,
        },
        'details': details,
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    json_path = os.path.join(out_dir, 'detection_report.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    csv_path = os.path.join(out_dir, 'detection_metrics.csv')
    with open(csv_path, 'w') as f:
        f.write('sample,expected_type,should_detect,detected,verdict,'
                'baseline_count,gapsbv_filtered,final_count,'
                'duration_ms,error\n')
        for d in details:
            f.write(f"{d['sample']},{d['expected_type']},"
                    f"{d['should_detect']},{d['detected']},{d['verdict']},"
                    f"{d['baseline_count']},{d['gapsbv_filtered']},"
                    f"{d['final_count']},{d['duration_ms']},{d['error']}\n")

    print(f'\n报告已保存: {json_path}')
    print(f'CSV已保存:   {csv_path}')


if __name__ == '__main__':
    print('结果收集模块 — 需配合 pipeline_compile + pipeline_scan_dispatch 使用')
