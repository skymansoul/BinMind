# 一键回归流水线: 生成样本 -> 编译 -> 扫描 -> 收集对比.
#
# 用法:
#   python run_all.py            # 全流程
#   python run_all.py --pack     # 额外生成加壳变体
#

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def _step(name, *args, extra=None):
    print(f"\n===== [{name}] =====")
    cmd = [PY, str(ROOT / args[0])] + list(args[1:])
    if extra:
        cmd += extra
    t0 = time.perf_counter()
    r = subprocess.run(cmd)
    print(f"----- {name} done in {time.perf_counter()-t0:.1f}s "
          f"(rc={r.returncode}) -----")
    return r.returncode


def main():
    parser = argparse.ArgumentParser(description="heapdet 回归流水线")
    parser.add_argument("--pack", action="store_true",
                        help="编译加壳变体 (需 upx)")
    parser.add_argument("--skip-compile", action="store_true",
                        help="跳过编译, 直接扫描已编译产物")
    parser.add_argument("--skip-scan", action="store_true",
                        help="跳过扫描, 只做结果收集")
    args = parser.parse_args()

    _step("generate samples", "gen_samples.py")
    if not args.skip_compile:
        extra = ["--pack"] if args.pack else None
        _step("compile samples", "compile_samples.py", extra=extra)
    if not args.skip_scan:
        _step("scan samples", "run_scan.py")
    _step("collect results", "collect_results.py")

    summary_path = ROOT / "results" / "summary.json"
    if summary_path.exists():
        print(f"\nsummary -> {summary_path}")
    print("\nAll pipeline stages complete.")


if __name__ == "__main__":
    main()
