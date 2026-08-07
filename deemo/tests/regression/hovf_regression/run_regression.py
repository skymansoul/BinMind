"""
一键回归入口.

执行流程: 发现样本 → 编译 → 扫描(基线 vs HOVF) → 收集对比 → 输出
CSV/JSON 到 tests/regression/hovf_regression/results/. 打印摘要表.

返回码: 0 正常完成, 1 存在失败样本.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from tests.regression.hovf_regression.ground_truth import load_all
from tests.regression.hovf_regression.build_samples import build_samples
from tests.regression.hovf_regression.scan_scheduler import scan_all
from tests.regression.hovf_regression.collect_results import (
    summarize, write_csv, write_json,
)

_THIS_DIR = Path(__file__).parent
_RESULTS_DIR = _THIS_DIR / 'results'


def main() -> int:
    _RESULTS_DIR.mkdir(exist_ok=True)
    t0 = time.perf_counter()

    print('[1/4] 发现样本')
    samples = load_all()
    print(f'      共 {len(samples)} 个堆溢出样本')

    # FIXME: 无 gcc 环境时全部回退源码扫描, 二进制通道不可用
    print('[2/4] 编译样本')
    builds = build_samples()
    failed_builds = [b for b in builds if not b['ok']]
    if failed_builds:
        print(f'      {len(failed_builds)} 个编译失败, 回退源码级扫描')

    print('[3/4] 扫描 (基线 vs HOVF)')
    results = scan_all(samples)

    print('[4/4] 收集对比')
    summary = summarize(results)
    csv_path = _RESULTS_DIR / 'regression_results.csv'
    json_path = _RESULTS_DIR / 'regression_summary.json'
    write_csv(results, str(csv_path))
    write_json(summary, results, str(json_path))

    elapsed = time.perf_counter() - t0
    print(f'\n总耗时 {elapsed:.1f}s, 输出:')
    print(f'  CSV : {csv_path}')
    print(f'  JSON: {json_path}\n')
    print(f'{"工具":<10}{"TP":>4}{"FP":>4}{"TN":>4}{"FN":>4}'
          f'{"Prec":>8}{"Recall":>8}{"F1":>7}{"FPR":>8}')
    for tool, m in summary['tools'].items():
        print(f'{tool:<10}{m["tp"]:>4}{m["fp"]:>4}{m["tn"]:>4}{m["fn"]:>4}'
              f'{m["precision"]:>8.3f}{m["recall"]:>8.3f}'
              f'{m["f1"]:>7.3f}{m["fpr"]:>8.3f}')
    print(f'\nFP 削减: {summary["fp_reduction_ratio"]*100:.1f}%'
          f'  召回变化: {summary["recall_delta"]*100:+.1f}pp'
          f'  F1 变化: {summary["f1_delta"]*100:+.1f}pp')
    return 0 if not failed_builds else 1


if __name__ == '__main__':
    sys.exit(main())
