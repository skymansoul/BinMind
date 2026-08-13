# UAF深度套件——样本编译模块
# 遍历uaf_deep_samples, gcc生成O0/O3到 build/
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

SAMPLES_ROOT = Path(__file__).parent.parent / "uaf_deep_samples"
BUILD_ROOT = Path(__file__).parent / "build"
GCC = shutil.which("gcc") or "gcc"


def main() -> int:
    samples = sorted(d for d in SAMPLES_ROOT.iterdir()
                     if d.is_dir() and (d / "vuln.c").exists())
    if not samples:
        print("[uaf compile] 无样本")
        return 1
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    results = []
    for sd in samples:
        for opt in ("O0", "O3"):
            out = BUILD_ROOT / f"{sd.name}_{opt}.exe"
            if out.exists():
                out.unlink()
            t0 = time.perf_counter()
            r = subprocess.run([GCC, f"-{opt}", "-w", "-o", str(out),
                                str(sd / "vuln.c")],
                               capture_output=True, text=True, timeout=120)
            ok = r.returncode == 0 and out.exists()
            results.append({"sample": sd.name, "opt": opt, "success": ok,
                            "time_ms": round((time.perf_counter() - t0) * 1000, 1)})
            print(f"  [{opt}] {sd.name}: {'OK' if ok else 'FAIL'}")
    (BUILD_ROOT / "compile_log.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    print(f"[uaf compile] {sum(1 for r in results if r['success'])}/{len(results)} 编译成功")
    return 0 if all(r["success"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
