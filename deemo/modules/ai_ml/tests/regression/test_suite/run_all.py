#!/usr/bin/env python3
# 一键回归测试——编译→扫描→结果收集 全流程
# 用法: python run_all.py [--heap-only] [--skip-compile]
# 退出码: 0=全部通过, 1=部分失败

import sys
import subprocess
from pathlib import Path

SUITE_DIR = Path(__file__).parent


def run_step(script_name: str, description: str) -> int:
    """运行单个步骤脚本并返回退出码"""
    script = SUITE_DIR / script_name
    if not script.exists():
        print(f"  [SKIP] {script_name} not found")
        return 0

    print(f"\n{'='*60}")
    print(f"  STEP: {description}")
    print(f"{'='*60}")

    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=False,  # 实时输出
        timeout=300)
    return proc.returncode


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Heap Overflow Regression Test Suite')
    parser.add_argument('--heap-only', action='store_true', default=True,
                       help='Only test heap overflow samples (default)')
    parser.add_argument('--skip-compile', action='store_true',
                       help='Skip compilation step')
    args = parser.parse_args()

    print("=" * 60)
    print("  HEAP OVERFLOW REGRESSION TEST SUITE")
    print("=" * 60)

    exit_code = 0

    # 编译
    if not args.skip_compile:
        if run_step('compile_samples.py', 'Compiling Samples') != 0:
            print("WARNING: Some samples failed to compile")
            # 继续执行——部分编译失败不阻止扫描

    # 扫描
    if run_step('run_scanner.py', 'Running Detection Scanners') != 0:
        exit_code = 1

    # 收集与比对
    if run_step('collect_results.py', 'Collecting & Comparing Results') != 0:
        exit_code = 1

    print(f"\n{'='*60}")
    print(f"  TEST SUITE COMPLETE (exit={exit_code})")
    print(f"{'='*60}")

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
