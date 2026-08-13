# 一键 UAF 回归流水线: 生成样本 → 编译 → 扫描 → 收集对比.
#
# 用法:
#   python run_all.py
#
# 创建: 2025-01-13

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def _step(name, script):
    print(f"\n===== [{name}] =====")
    t0 = time.perf_counter()
    r = subprocess.run([PY, str(ROOT / script)])
    print(f"----- {name} done in {time.perf_counter() - t0:.1f}s "
          f"(rc={r.returncode}) -----")
    return r.returncode


def main():
    _step("generate uaf samples", "gen_uaf_samples.py")
    _step("compile uaf samples", "compile_uaf.py")
    _step("scan uaf samples", "scan_uaf.py")
    _step("collect uaf results", "collect_uaf.py")
    print("\nAll UAF pipeline stages complete.")


if __name__ == "__main__":
    main()
