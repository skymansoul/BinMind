# 深度样本编译模块——遍历heap_deep_samples调用gcc生成O0/O3二进制
# 依赖MinGW-w64 gcc(环境已具备), 输出到 tests/deep_suite/build/

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List

SAMPLES_ROOT = Path(__file__).parent.parent / "heap_deep_samples"
BUILD_ROOT = Path(__file__).parent / "build"
GCC = shutil.which("gcc") or "gcc"


@dataclass
class CompileOutcome:
    sample: str
    opt: str
    success: bool
    path: str = ""
    time_ms: float = 0.0
    error: str = ""


def discover_samples() -> List[Path]:
    return sorted(d for d in SAMPLES_ROOT.iterdir()
                  if d.is_dir() and (d / "vuln.c").exists())


def compile_one(sample_dir: Path, opt: str, out_path: Path) -> CompileOutcome:
    t0 = time.perf_counter()
    # TODO: O3下gcc会将部分TP样本的memcpy内联/整段消除(DCE), 需记录各样本在O0/O3的存活模式
    try:
        r = subprocess.run(
            [GCC, f"-{opt}", "-w", "-o", str(out_path),
             str(sample_dir / "vuln.c")],
            capture_output=True, text=True, timeout=120)
        ok = r.returncode == 0 and out_path.exists()
        return CompileOutcome(
            sample=sample_dir.name, opt=opt, success=ok,
            path=str(out_path), time_ms=(time.perf_counter() - t0) * 1000,
            error=r.stderr[:300] if not ok else "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return CompileOutcome(sample=sample_dir.name, opt=opt,
                              success=False, error=str(e)[:200])


def main() -> int:
    samples = discover_samples()
    if not samples:
        print("[compile_samples] 无样本目录")
        return 1
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    results: List[CompileOutcome] = []
    for sd in samples:
        for opt in ("O0", "O3"):
            out = BUILD_ROOT / f"{sd.name}_{opt}.exe"
            if out.exists():
                out.unlink()
            r = compile_one(sd, opt, out)
            st = "OK" if r.success else f"FAIL: {r.error[:60]}"
            print(f"  [{opt}] {sd.name}: {st}")
            results.append(r)
    ok = sum(1 for r in results if r.success)
    (BUILD_ROOT / "compile_log.json").write_text(
        json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\n[compile_samples] {ok}/{len(results)} 编译成功")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
