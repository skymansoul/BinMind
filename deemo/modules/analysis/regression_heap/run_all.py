# 一键回归入口 - 编译 → 扫描 → 收集对比.
# 用法: python run_all.py

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import compile_samples  # noqa: E402
import collect_results  # noqa: E402


def main():
    t0 = time.perf_counter()
    print("== Step 1/3: 编译样本 ==")
    compile_samples.compile_all()
    print("\n== Step 2/3: 收集对比结果 ==")
    summary = collect_results.collect()
    print("\n== Step 3/3: 完成 ==")
    elapsed = time.perf_counter() - t0
    print(f"总耗时 {elapsed:.1f}s")
    print("\n结论: 增强(BWR+PCST) vs 基线(legacy):")
    e, b = summary["enhanced"], summary["baseline"]
    print(f"  Recall   {e['recall']}% -> {b['recall']}%")
    print(f"  Precision {e['precision']}% -> {b['precision']}%")
    print(f"  FPR      {e['fpr']}% -> {b['fpr']}%")
    print(f"  F1       {e['f1']} -> {b['f1']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
