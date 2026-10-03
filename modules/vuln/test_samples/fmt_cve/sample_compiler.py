# coding: utf-8
#
"""编译格式串语料为 vuln.exe + vuln.asm."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

SAMPLE_DIR = Path(__file__).resolve().parent
CC = os.environ.get("CC", "gcc")
OBJDUMP = os.environ.get("OBJDUMP", "objdump")
CFLAGS = ["-Wall", "-O0", "-g", "-fno-builtin", "-fno-stack-protector",
          "-no-pie"]


def compile_sample(d: Path) -> Tuple[bool, str]:
    src = d / "vuln.c"
    out = d / "vuln.exe"
    asm = d / "vuln.asm"
    if not src.exists():
        return False, f"{src.name} not found"
    r = subprocess.run([CC] + CFLAGS + ["-o", str(out), str(src)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return False, f"compile failed: {r.stderr[:200]}"
    if not out.exists():
        return False, "binary not found"
    r = subprocess.run([OBJDUMP, "-d", "-M", "intel", str(out)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return False, f"objdump failed: {r.stderr[:200]}"
    asm.write_text(r.stdout, encoding="utf-8", errors="replace")
    return True, ""


def main() -> int:
    ap = argparse.ArgumentParser(description="compile fmt corpus")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--samples", nargs="*")
    args = ap.parse_args()

    dirs = sorted(d for d in SAMPLE_DIR.iterdir()
                  if d.is_dir() and (d / "vuln.c").exists())
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
        s, err = compile_sample(d)
        results[d.name] = {"success": s, "error": err}
        print(f"  [{d.name}] {'OK' if s else 'FAIL: ' + err}")
        ok += s
        fail += (not s)
    (SAMPLE_DIR / "compile_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    print(f"\ncompile: {ok} ok, {fail} fail / {len(dirs)}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
