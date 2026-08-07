# 创建: 2026-05-10 -- CVE样本编译模块
import subprocess, sys, os
from pathlib import Path

SAMPLES = Path(__file__).parent
BUILD_DIR = SAMPLES / "build"
SAMPLE_SRCS = {
    "cve_01": "uaf_sample.c", "cve_02": "heap_overflow.c",
    "cve_03": "fmtstr.c", "cve_04": "double_free.c",
    "cve_05": "int_overflow.c", "cve_06": "null_deref.c",
    "cve_07": "heap_overflow2.c", "cve_08": "oob_read.c",
    "cve_09": "uaf_realloc.c", "cve_10": "safe_printf.c",
}

def compile_samples(compiler="gcc", opt="O0"):
    BUILD_DIR.mkdir(exist_ok=True)
    results = {}
    for cve_id, src_name in SAMPLE_SRCS.items():
        src_path = SAMPLES / cve_id / src_name
        out_path = BUILD_DIR / f"{cve_id}_{compiler}_{opt}"
        if not src_path.exists():
            results[cve_id] = "missing_src"; continue
        cmd = [compiler, f"-{opt}", "-o", str(out_path), str(src_path), "-w"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results[cve_id] = "ok" if r.returncode == 0 else f"fail: {r.stderr[:80]}"
        except subprocess.TimeoutExpired:
            results[cve_id] = "timeout"
    return results

if __name__ == "__main__":
    compiler = sys.argv[1] if len(sys.argv) > 1 else "gcc"
    opt = sys.argv[2] if len(sys.argv) > 2 else "O0"
    r = compile_samples(compiler, opt)
    ok = sum(1 for v in r.values() if v == "ok")
    print(f"Compiled: {ok}/{len(r)} OK")
    for cve_id, status in r.items():
        print(f"  {cve_id}: {status}")
