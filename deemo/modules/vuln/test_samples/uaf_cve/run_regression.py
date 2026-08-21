# coding: utf-8
#
"""一键回归: compile → scan → collect → report."""

import argparse
import subprocess
import sys
import time
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent


def run_step(name: str, script: str) -> bool:
    p = SAMPLE_DIR / script
    if not p.exists():
        print(f"  [SKIP] {script} not found")
        return False
    print(f"\n===== {name} =====")
    r = subprocess.run([sys.executable, str(p)], cwd=str(SAMPLE_DIR))
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="UAF one-click regression")
    ap.add_argument("--quick", action="store_true", help="skip compile")
    args = ap.parse_args()

    t0 = time.perf_counter()
    if not args.quick:
        if not run_step("Compile", "sample_compiler.py"):
            return 1
    if not run_step("Scan", "scan_scheduler.py"):
        return 1
    if not run_step("Collect", "result_collector.py"):
        return 1
    print(f"\nregression done in {time.perf_counter() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
