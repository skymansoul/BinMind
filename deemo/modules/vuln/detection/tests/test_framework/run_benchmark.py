# -*- coding: utf-8 -*-
# 创建: 2026-08-05  |  基准测试入口——编译→扫描→统计 一键运行
#
"""
运行完整基准测试: 编译CVE样本→执行检测管线→统计TP/FP/FN。
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from compile_samples import compile_all
from scan_runner import ScanRunner
from result_parser import parse_results, print_report, BenchmarkStats


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.join(os.path.dirname(base), 'cve_samples')
    build_dir = os.path.join(os.path.dirname(base), 'build')

    print("=" * 60)
    print("Phase 1/3: 编译CVE样本")
    print("=" * 60)
    metas = compile_all(samples_dir, build_dir)

    print("\n" + "=" * 60)
    print("Phase 2/3: 执行检测管线")
    print("=" * 60)
    runner = ScanRunner()
    results = runner.scan_all(build_dir, metas)

    print("\n" + "=" * 60)
    print("Phase 3/3: 统计结果")
    print("=" * 60)
    labels = {}
    labels_path = os.path.join(samples_dir, 'expected_labels.json')
    if os.path.exists(labels_path):
        with open(labels_path) as f:
            labels = json.load(f)

    stats = parse_results(results, labels)

    # 输出报告
    print("\n")
    print_report(stats)

    # 保存JSON报告
    report_path = os.path.join(build_dir, 'benchmark_report.json')
    report_data = stats.to_dict()
    report_data['per_sample'] = [
        {'cve': r.cve_id, 'detected': r.detected,
         'confidence': r.confidence, 'elapsed_ms': r.elapsed_ms,
         'error': r.error}
        for r in results
    ]
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"\n详细报告: {report_path}")


if __name__ == '__main__':
    main()
