# coding: utf-8
"""
样本编译脚本 — 使用 gcc 将源码样本编译为二进制.

用途: 供 Angr/objdump 等二进制级工具对比分析.
输出: 每个样本目录下的 vuln.exe (PE/MinGW) 与 vuln_elf (若有gcc).
"""

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE, "samples")

GCC_CANDIDATES = [
    os.environ.get("GCC", ""),
    r"D:\mingw64\bin\gcc.exe",
    r"C:\Program Files (x86)\Dev-Cpp\MinGW32\bin\gcc.exe",
]


def find_gcc():
    for c in GCC_CANDIDATES:
        if c and os.path.isfile(c):
            return c
    try:
        import shutil
        c = shutil.which("gcc")
        if c:
            return c
    except Exception:
        pass
    return None


def compile_sample(gcc, src_path, out_path):
    r = subprocess.run(
        [gcc, "-O0", "-g", "-o", out_path, src_path],
        capture_output=True, text=True, timeout=60)
    return r.returncode == 0, r.stderr[:300]


def main():
    gcc = find_gcc()
    if gcc is None:
        print("gcc not found; skipping compilation")
        return 1
    print("using gcc:", gcc)
    ok, fail = 0, 0
    for entry in sorted(os.listdir(SAMPLES)):
        d = os.path.join(SAMPLES, entry)
        if not os.path.isdir(d):
            continue
        src_p = os.path.join(d, "vuln.c")
        if not os.path.exists(src_p):
            continue
        out_p = os.path.join(d, "vuln.exe")
        success, err = compile_sample(gcc, src_p, out_p)
        if success:
            ok += 1
        else:
            fail += 1
            print("FAIL", entry, err)
    print("compiled %d OK, %d failed" % (ok, fail))
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
