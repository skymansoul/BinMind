#!/usr/bin/env python3
"""堆溢出检测回归测试 — 一键运行入口
用法: python -m tests.run_tests [--samples SAMPLES_DIR] [--output OUTPUT_DIR]
"""
import sys, os
from pathlib import Path

# 确保项目根在sys.path中
_PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))


def main():
    samples_root = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == '--samples' else None
    output_dir = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == '--output' else None

    if not samples_root:
        samples_root = str(_PROJ_ROOT / "samples")
    if not output_dir:
        output_dir = str(_PROJ_ROOT / "test_output")

    from tests.collect_results import run_full_pipeline
    summary = run_full_pipeline(samples_root, output_dir)

    # 返回码: 若存在FN则返回1 (CI友好)
    if summary.false_negatives > 0:
        print(f"\nWARNING: {summary.false_negatives} false negatives detected!")
    if summary.false_positives > 0:
        print(f"WARNING: {summary.false_positives} false positives detected!")

    return 0 if summary.false_negatives == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
