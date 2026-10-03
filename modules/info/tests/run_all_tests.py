#!/usr/bin/env python3
# tests/run_all_tests — 一键回归测试主入口
# 按序执行: 编译 → 扫描 → 收集结果, 输出完整报告。
#
# 用法:
#   python tests/run_all_tests.py              # 全部样本, 两种方法
#   python tests/run_all_tests.py --quick       # 仅堆溢出相关样本
#   python tests/run_all_tests.py --method v2   # 仅 v2

import sys, os
from pathlib import Path

_TESTS = Path(__file__).parent
sys.path.insert(0, str(_TESTS.parent))


def main():
    # 依赖导入延迟至入口内: 编译/收集模块按当前目录布局取实际符号
    try:
        from tests.compile_samples import build_all
    except ImportError:
        from tests.compile_samples import compile_all as build_all
    from tests.run_scanner import run_all as scan_all
    try:
        from tests.collect_results import run_analysis
    except ImportError:
        run_analysis = None
    import argparse
    parser = argparse.ArgumentParser(description="BinMind Heap Overflow Regression Test")
    parser.add_argument("--quick", action="store_true",
                        help="仅扫描堆溢出和负样本")
    parser.add_argument("--method", choices=["v1", "v2", "all"], default="all")
    parser.add_argument("--skip-build", action="store_true",
                        help="跳过编译 (已编译过)")
    args = parser.parse_args()

    if args.quick:
        # 限制到堆溢出正样本 + 负样本
        all_dirs = sorted(
            d.name for d in (Path(__file__).parent / "regression" / "samples").iterdir()
            if d.is_dir() and d.name != "tests" and
            ("heap" in d.name.lower() or "overflow" in d.name.lower() or
             d.name.startswith("NEG-"))
        )
        print(f"Quick mode: {len(all_dirs)} samples")
        targets = all_dirs
    else:
        targets = None

    print("=" * 60)
    print("BINMIND HEAP OVERFLOW REGRESSION TEST SUITE")
    print("=" * 60)

    # 编译
    if not args.skip_build:
        print("\n[STEP 1/3] Compiling samples...")
        build_all(targets=targets)
    else:
        print("\n[STEP 1/3] Skipping build (--skip-build)")

    # 扫描
    print("\n[STEP 2/3] Running scanners...")
    methods = ["v1", "v2"] if args.method == "all" else [args.method]
    scan_all(targets=targets, methods=methods)

    # 收集结果
    print("\n[STEP 3/3] Collecting results...")
    if run_analysis is not None:
        run_analysis()
    else:
        print("[STEP 3/3] run_analysis 不可用, 跳过收集")

    print("\nDone. Reports in tests/regression/reports/")


if __name__ == "__main__":
    main()
