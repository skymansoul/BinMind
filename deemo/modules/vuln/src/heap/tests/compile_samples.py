"""SHIELD 回归测试 — 样本编译脚本.

递归扫描 samples/ 目录, 对每个 poc.c 用 MinGW 交叉编译为 .exe,
用两档优化级别 (O0/O2) 生成 objdump, 供后续检测器分析.

用法:
  python compile_samples.py                     # 编译所有
  python compile_samples.py --clean             # 清理产物
  python compile_samples.py --sample cve_2021_3156  # 单样本

创建: 2024-11-05
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


SAMPLE_ROOT = Path(__file__).resolve().parent / "samples"
BUILD_ROOT = Path(__file__).resolve().parent / "build"
GCC = "x86_64-w64-mingw32-gcc"
OBJDUMP = "x86_64-w64-mingw32-objdump"
OPT_LEVELS = ["O0", "O2"]


def find_samples(root: Path, filter_name: str = "") -> List[Path]:
    """递归查找所有 poc.c 文件."""
    samples = []
    for poc in sorted(root.rglob("poc.c")):
        if filter_name and filter_name not in str(poc.parent.name):
            continue
        samples.append(poc)
    return samples


def compile_one(poc: Path, opt: str) -> Tuple[bool, str]:
    """编译单个样本 → .exe 并生成 .objdump."""
    sample_name = poc.parent.name
    out_dir = BUILD_ROOT / "gcc" / opt
    out_dir.mkdir(parents=True, exist_ok=True)

    exe_path = out_dir / f"{sample_name}.exe"
    objdump_path = out_dir / f"{sample_name}.objdump"

    # 编译
    cflags = ["-O0" if opt == "O0" else "-O2", "-g", "-Wall", "-Wno-unknown-pragmas"]
    cmd = [GCC] + cflags + ["-o", str(exe_path), str(poc)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
    except subprocess.CalledProcessError as e:
        return False, f"compile error:\n{e.stderr[:200]}"
    except subprocess.TimeoutExpired:
        return False, "compile timeout"

    # 生成 objdump
    try:
        dump = subprocess.run(
            [OBJDUMP, "-d", "-M", "intel", str(exe_path)],
            capture_output=True, text=True, check=True, timeout=10)
        objdump_path.write_text(dump.stdout)
    except subprocess.CalledProcessError as e:
        return False, f"objdump error: {e.stderr[:100]}"

    return True, f"{opt}: {exe_path.name} ({exe_path.stat().st_size} bytes)"


def clean_build():
    """清理构建产物."""
    if BUILD_ROOT.exists():
        import shutil
        shutil.rmtree(BUILD_ROOT)
        print(f"  [CLEAN] removed {BUILD_ROOT}")


def main():
    parser = argparse.ArgumentParser(description="SHIELD 样本编译器")
    parser.add_argument("--clean", action="store_true", help="清理产物")
    parser.add_argument("--sample", type=str, default="", help="单样本名称过滤")
    parser.add_argument("--opt", type=str, default="", help="优化级别 (O0/O2, 默认全部)")
    args = parser.parse_args()

    if args.clean:
        clean_build()
        return

    samples = find_samples(SAMPLE_ROOT, args.sample)
    if not samples:
        print(f"  No samples found in {SAMPLE_ROOT}")
        return

    opts = [args.opt] if args.opt else OPT_LEVELS
    total, ok = 0, 0

    for poc in samples:
        for opt in opts:
            total += 1
            success, msg = compile_one(poc, opt)
            status = "OK" if success else "FAIL"
            print(f"  [{status}] {poc.parent.name}/{opt}: {msg}")
            if success:
                ok += 1

    print(f"\n  Compiled: {ok}/{total} ({100*ok//max(1,total)}%)")


if __name__ == "__main__":
    main()
