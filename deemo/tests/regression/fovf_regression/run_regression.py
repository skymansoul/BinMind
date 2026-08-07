"""
FOVF 一键回归入口.

流程: 发现样本 → 扫描(既有检测器 vs FOVF) → 收集对比 → 输出
CSV/JSON. 编译非必需 (格式化字符串为纯源码模式), 直接扫描.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from tests.regression.fovf_regression.ground_truth import load_all
from tests.regression.fovf_regression.scan_scheduler import scan_all
from tests.regression.fovf_regression.collect_results import (
    summarize, write_csv, write_json,
)

_THIS = Path(__file__).parent
_RESULTS = _THIS / 'results'


def main() -> int:
    _RESULTS.mkdir(exist_ok=True)
    t0 = time.perf_counter()
    print('[1/3] 发现格式化字符串样本')
    samples = load_all()
    print(f'      共 {len(samples)} 个')
    print('[2/3] 扫描 (既有检测器 vs FOVF)')
    results = scan_all(samples)
    print('[3/3] 收集对比')
    summary = summarize(results)
    csv_path = _RESULTS / 'fovf_regression_results.csv'
    json_path = _RESULTS / 'fovf_regression_summary.json'
    write_csv(results, str(csv_path))
    write_json(summary, results, str(json_path))
    print(f'\n耗时 {time.perf_counter() - t0:.1f}s')
    print(f'  CSV : {csv_path}\n  JSON: {json_path}\n')
    print(f'{"工具":<10}{"TP":>4}{"FP":>4}{"TN":>4}{"FN":>4}'
          f'{"Prec":>8}{"Recall":>8}{"F1":>7}{"FPR":>8}')
    for tool, m in summary['tools'].items():
        print(f'{tool:<10}{m["tp"]:>4}{m["fp"]:>4}{m["tn"]:>4}{m["fn"]:>4}'
              f'{m["precision"]:>8.3f}{m["recall"]:>8.3f}'
              f'{m["f1"]:>7.3f}{m["fpr"]:>8.3f}')
    print(f'\nFP 削减: {summary["fp_reduction_ratio"] * 100:.1f}%'
          f'  召回变化: {summary["recall_delta"] * 100:+.1f}pp'
          f'  F1 变化: {summary["f1_delta"] * 100:+.1f}pp')
    return 0


if __name__ == '__main__':
    sys.exit(main())
