"""
完整回归测试管道 — 编译 → 扫描 → 收集 → 报告。
薄编排层: 调用 pipeline_compile / pipeline_scan_dispatch / pipeline_result_collector 三模块。
单文件职责仅限流程编排, 不含具体实现逻辑。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.pipeline_compile import compile_all_samples, print_compile_summary
from tests.pipeline_scan_dispatch import scan_all, scan_failed_placeholder
from tests.pipeline_result_collector import collect_and_report


def main():
    print('=' * 60)
    print('BinMind GAPSBV 回归测试管道')
    print('=' * 60)

    # Stage 1: 编译
    print('\n[Stage 1/3] 编译样本...')
    compilations = compile_all_samples()
    ok, bad = print_compile_summary(compilations)

    # Stage 2: 扫描
    print(f'\n[Stage 2/3] 扫描 {len(ok)} 个二进制...')
    scan_results = scan_all(ok)
    scan_results.update(scan_failed_placeholder(bad))

    # Stage 3: 收集 + 分类 + 报告
    print(f'\n[Stage 3/3] 分类结果...')
    report = collect_and_report(scan_results)
    return report


if __name__ == '__main__':
    main()
