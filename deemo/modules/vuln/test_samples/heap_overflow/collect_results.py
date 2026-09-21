"""结果收集与报告生成 — 聚合 compile + scan 结果, 输出 CSV + JSON + 终端表格.

创建: 2024-10-11
用途: 读取 compile_results.json + scan_results.json, 生成:
  - results.csv (per-sample 详细表)
  - results_summary.json (含对比基准)
  - 终端 Markdown 表格

运行: python collect_results.py [--csv results.csv] [--json results_summary.json]
"""

import json
import csv
import sys
from pathlib import Path
from typing import Dict, List


SAMPLE_DIR = Path(__file__).resolve().parent

# 基线对比 (来自多工具对比)
# BinMind 行: 真实二进制链路口径实测值 (binary_pipeline_full.json, 2026-09-16,
#   n=121, TP=107, FP=14, FN=0, TN=0; 95% Wilson recall CI [0.965, 1.0])
# 其余各行为 legacy 手写对比数据，非实测计算，口径不明不可作为实测依据，仅作历史记录
# 历史: 原 BinMind (AVHO-G v3.2.1) 行 f1=1.000 系源码正则小集与手写标签同源互洽的
#   自证结果，2026-09-16 审计废置，由上述真实口径值替换
BASELINE = {
    'BinMind (binary_pipeline_full, n=121)': {'precision': 0.884, 'recall': 1.00, 'f1': 0.939},
    'BinMind (AVHO v3.2, legacy)':     {'precision': 0.94, 'recall': 0.88, 'f1': 0.91},
    'Naive Regex (legacy)':            {'precision': 0.85, 'recall': 0.40, 'f1': 0.54},
    'angr (symbolic exec, legacy)':    {'precision': 0.35, 'recall': 0.85, 'f1': 0.50},
    'Ghidra (pattern, legacy)':        {'precision': 0.25, 'recall': 0.75, 'f1': 0.38},
    'QEMU (dynamic trace, legacy)':    {'precision': 0.90, 'recall': 0.70, 'f1': 0.79},
}

# 合成样本的模拟漏洞模式编号 (SIM-xx)
# 2026-09-16 审计修正: 原映射使用编造的连号 CVE-2024-0001/0003/0004... 及冒用
# 真实 CVE 编号 (如 CVE-2016-2208), 会误导读者以为样本对应真实 CVE, 已废置;
# 本批样本为团队自制场景构造代码, 编号仅描述漏洞模式, 非真实 CVE 对应
CVE_MAP = {
    'sample01_direct_overflow': 'SIM-01-direct-overflow',
    'sample02_int_overflow_to_heap': 'SIM-02-int-overflow-to-heap',
    'sample03_insufficient_guard': 'SIM-03-insufficient-guard',
    'sample04_cross_function_overflow': 'SIM-04-cross-function-overflow',
    'sample05_loop_cumulative_overflow': 'SIM-05-loop-cumulative-overflow',
    'sample06_sprintf_overflow': 'SIM-06-sprintf-overflow',
    'sample07_memcpy_computed_size': 'SIM-07-memcpy-computed-size',
    'sample08_alignment_padding_safe': 'SAFE',
    'sample09_strncpy_truncation_overflow': 'SIM-09-strncpy-truncation-overflow',
    'sample10_realloc_shrink_overflow': 'SIM-10-realloc-shrink-overflow',
    'sample11_calloc_wraparound': 'SIM-11-calloc-wraparound',
    'sample12_conditional_overflow': 'SIM-12-conditional-overflow',
    'sample13_multi_alloc_pointer_confusion': 'SIM-13-multi-alloc-pointer-confusion',
    'sample14_nested_struct_overflow': 'SIM-14-nested-struct-overflow',
    'sample15_properly_guarded_safe': 'SAFE',
    'sample16_exact_boundary_safe': 'SAFE',
    'sample17_large_offset_small_write': 'SAFE',
    'sample18_16bit_overflow_to_heap': 'SIM-18-16bit-overflow-to-heap',
}


def load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {}


def main():
    scan_results = load_json(SAMPLE_DIR / 'scan_results.json')
    compile_results = load_json(SAMPLE_DIR / 'compile_results.json')

    if not scan_results:
        print('No scan results found. Run run_scanner.py first.')
        return

    per_sample = scan_results.get('per_sample', {})

    # CSV 输出
    csv_path = SAMPLE_DIR / 'results.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Sample', 'CVE', 'Expected', 'Verdict', 'Correct',
            'Findings', 'Real Findings', 'Top Confidence',
            'Time (ms)', 'Compile Status'])
        for name, info in sorted(per_sample.items()):
            cve = CVE_MAP.get(name, '')
            c_status = 'OK' if compile_results.get(
                name, {}).get('success') else 'FAIL'
            writer.writerow([
                name, cve, info['expected'], info['verdict'],
                'YES' if info['verdict'] in ('TP', 'TN') else 'NO',
                info.get('n_findings', 0),
                info.get('n_real_findings', 0),
                f"{info.get('top_confidence', 0):.3f}",
                info.get('time_ms', 0),
                c_status])

    print(f'CSV saved: {csv_path}')

    # JSON 汇总 (含基线对比)
    summary = load_json(SAMPLE_DIR / 'scan_results.json')
    summary['baseline_comparison'] = BASELINE
    summary['cve_map'] = CVE_MAP
    summary['metadata'] = {
        'tool': 'BinMind AVHO-G',
        'date': '2024-10-11',
        'n_samples': len(per_sample),
        'n_tp_expected': scan_results.get('tp', 0) + scan_results.get('fn', 0),
        'n_tn_expected': scan_results.get('tn', 0) + scan_results.get('fp', 0),
    }

    json_path = SAMPLE_DIR / 'results_summary.json'
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f'JSON saved: {json_path}')

    # 终端 Markdown 表格
    tp = scan_results.get('tp', 0)
    tn = scan_results.get('tn', 0)
    fp = scan_results.get('fp', 0)
    fn = scan_results.get('fn', 0)
    total_tp = sum(1 for v in per_sample.values() if v['expected'] == 'TP')
    total_tn = sum(1 for v in per_sample.values() if v['expected'] == 'TN')

    print(f'\n### BinMind AVHO-G Heap Overflow Detection Results\n')
    print(f'| Metric | Value |')
    print(f'|--------|-------|')
    print(f'| Samples | {len(per_sample)} ({total_tp} TP + {total_tn} TN) |')
    print(f'| TP | {tp} |')
    print(f'| TN | {tn} |')
    print(f'| FP | {fp} |')
    print(f'| FN | {fn} |')
    print(f'| Precision | {scan_results.get("precision", 0):.1%} |')
    print(f'| Recall | {scan_results.get("recall", 0):.1%} |')
    print(f'| F1 | {scan_results.get("f1", 0):.3f} |')
    print(f'| Avg Time | {scan_results.get("avg_time_ms", 0):.0f}ms |')

    # 对比表
    print(f'\n### Multi-Tool Comparison\n')
    print(f'| Tool | Precision | Recall | F1 |')
    print(f'|------|-----------|--------|-----|')
    binmind_f1 = scan_results.get('f1', 0.94)
    for tool, metrics in BASELINE.items():
        print(f'| {tool} | {metrics["precision"]:.1%} | '
              f'{metrics["recall"]:.1%} | {metrics["f1"]:.3f} |')


if __name__ == '__main__':
    main()
