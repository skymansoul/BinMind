# coding: utf-8
#
"""
样本编译模块: 将 cve_heap 下每个样本的 vuln.c 编译为
vuln.exe (MinGW PE) 与 vuln.asm (objdump 反汇编)。

仅做编译与反汇编, 不含任何扫描逻辑 (职责单一)。

用法: python sample_compiler.py [--clean] [--samples id1 id2 ...]
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

SAMPLE_DIR = Path(__file__).resolve().parent
CC = os.environ.get("CC", "gcc")
OBJDUMP = os.environ.get("OBJDUMP", "objdump")
CFLAGS = ["-Wall", "-O0", "-g", "-fno-builtin", "-fno-stack-protector",
          "-no-pie"]


def compile_sample(sample_path: Path) -> Tuple[bool, str]:
    src = sample_path / "vuln.c"
    out = sample_path / "vuln.exe"
    asm = sample_path / "vuln.asm"
    if not src.exists():
        return False, f"{src.name} not found"
    cmd = [CC] + CFLAGS + ["-o", str(out), str(src)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"compile failed: {r.stderr[:200]}"
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"{type(e).__name__}: {e}"
    if not out.exists():
        return False, "binary not found after compile"
    try:
        r = subprocess.run([OBJDUMP, "-d", "-M", "intel", str(out)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"objdump failed: {r.stderr[:200]}"
        asm.write_text(r.stdout, encoding="utf-8", errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"{type(e).__name__}: {e}"
    return True, ""


def discover_samples() -> List[Path]:
    return sorted(
        d for d in SAMPLE_DIR.iterdir()
        if d.is_dir() and (d / "vuln.c").exists())


def main() -> int:
    ap = argparse.ArgumentParser(description="compile CVE heap samples")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--samples", nargs="*")
    args = ap.parse_args()

    dirs = discover_samples()
    if args.samples:
        dirs = [d for d in dirs if d.name in args.samples]

    if args.clean:
        for d in dirs:
            for f in ("vuln.exe", "vuln.asm", "vuln.o"):
                p = d / f
                if p.exists():
                    p.unlink()
        print(f"cleaned {len(dirs)} samples")
        return 0

    results = {}
    ok = fail = 0
    for d in dirs:
        success, err = compile_sample(d)
        results[d.name] = {"success": success, "error": err}
        print(f"  [{d.name}] {'OK' if success else 'FAIL: ' + err}")
        ok += success
        fail += (not success)

    (SAMPLE_DIR / "compile_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    print(f"\ncompile: {ok} ok, {fail} fail / {len(dirs)}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
