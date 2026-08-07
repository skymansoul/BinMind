# 样本编译模块 — 编译未构建的漏洞样本为PE可执行文件.
# 仅编译缺失 vuln.exe 的目录, 已存在的不重复编译.
# 创建: 2026-06-11

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def find_sample_dirs(base: str) -> list:
    """返回含 vuln.c 的样本目录列表."""
    dirs = []
    base_path = Path(base)
    if not base_path.is_dir():
        return dirs
    for d in sorted(base_path.iterdir()):
        if d.is_dir() and (d / "vuln.c").exists():
            dirs.append(d)
    return dirs


def compile_sample(sample_dir: Path, cc: str = "gcc",
                   extra_flags: tuple = ()) -> bool:
    """编译单个样本 vuln.c → vuln.exe."""
    exe = sample_dir / "vuln.exe"
    if exe.exists():
        return True
    cmd = [cc, "-O0", "-g", *extra_flags, "vuln.c", "-o", "vuln.exe"]
    try:
        r = subprocess.run(cmd, cwd=str(sample_dir), capture_output=True,
                           timeout=120)
        if r.returncode == 0 and exe.exists():
            return True
        print(f"  [compile] FAIL {sample_dir.name}: "
              f"{r.stderr.decode('utf-8', errors='replace')[-300:]}")
    except Exception as e:
        print(f"  [compile] ERROR {sample_dir.name}: {e}")
    return False


def compile_all(bases: list = None) -> list:
    """编译所有基线目录下的样本, 返回 (成功数, 样本路径列表)."""
    bases = bases or [
        str(ROOT / "samples_bwr"),
        str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\samples\heap_fp_reduction")),
        str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\samples\heap_overflow")),
    ]
    compiled = []
    ok = 0
    for base in bases:
        bwr_base = "samples_bwr" in base
        extra = ("-fno-builtin", "-fno-inline") if bwr_base else ()
        for d in find_sample_dirs(base):
            if compile_sample(d, extra_flags=extra):
                ok += 1
                compiled.append(str(d))
    print(f"[compile] done: {ok} samples ready")
    return compiled


if __name__ == "__main__":
    sys.exit(0 if compile_all() else 1)
