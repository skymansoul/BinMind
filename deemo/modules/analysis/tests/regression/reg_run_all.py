# 回归测试一键入口 - 编译 → 扫描 → 对比
# 用法: python reg_run_all.py [--skip-compile]
# 输出: results/scan_results_v2.json + regression_compare.json + CSV

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def main():
    skip_compile = "--skip-compile" in sys.argv
    from reg_compile import compile_all, BUILD_DIR
    from reg_scanner import scan_all
    from reg_compare import compare_all

    print("=" * 52)
    print("Step 1/3: Compile samples")
    print("=" * 52)
    if not skip_compile:
        compile_all(BUILD_DIR / "manifest_all.json")
    else:
        print("  skipped (--skip-compile)")

    print("\n" + "=" * 52)
    print("Step 2/3: Scan binaries")
    print("=" * 52)
    scan_all()

    print("\n" + "=" * 52)
    print("Step 3/3: Compare & summarize")
    print("=" * 52)
    compare_all()


if __name__ == "__main__":
    main()
