#!/usr/bin/env python
# coding: utf-8
# tests/heap_fp_regression/run_regression.py — 堆溢出误报回归一键执行
# 流水线: compile_samples (编译未加壳+加壳变体)
#        → scan_scheduler (内部检测器扫描)
#        → result_collector (对照 truth.json 计算 TP/FP/FN/TN 指标)
# 用法: python run_regression.py
# 可选: python run_regression.py --scan-only  (跳过编译)

import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).parent


def main():
    scan_only = "--scan-only" in sys.argv
    steps = []
    if not scan_only:
        steps.append("compile_samples")
    steps += ["scan_scheduler", "result_collector"]

    for step in steps:
        print(f"\n=== {step} ===")
        r = subprocess.run([sys.executable, str(_HERE / f"{step}.py")],
                           cwd=_HERE)
        if r.returncode != 0:
            print(f"[run_regression] {step} FAILED (rc={r.returncode})")
            sys.exit(r.returncode)
    print("\n[run_regression] all steps completed.")


if __name__ == "__main__":
    main()
