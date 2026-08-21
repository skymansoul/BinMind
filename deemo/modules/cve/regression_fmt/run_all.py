# 一键格式化字符串回归流水线: 生成样本 -> 编译 -> 扫描 -> 收集对比.
#

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
    _step("generate fmt samples", "gen_fmt_samples.py")
    _step("compile fmt samples", "compile_fmt.py")
    _step("scan fmt samples", "scan_fmt.py")
    _step("collect fmt results", "collect_fmt.py")
    print("\nAll fmt pipeline stages complete.")


if __name__ == "__main__":
    main()
