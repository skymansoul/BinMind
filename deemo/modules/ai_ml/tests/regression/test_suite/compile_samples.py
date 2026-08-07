# 样本编译模块——批量编译测试样本为ELF
# 支持多优化级别(O0/O3)编译，产出统一放在build/目录
# 错误处理: 编译失败时记录错误但不中断整个批次

import subprocess
import sys
import os
import json
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

ROOT = Path(__file__).parent.parent
SAMPLES_HEAP = ROOT / "samples_heap_overflow"
SAMPLES_LEGACY = ROOT / "samples"
BUILD_DIR = ROOT / "build"
RESULTS_FILE = Path(__file__).parent / "compile_results.json"

OPT_LEVELS = ['O0', 'O3']
CC = 'gcc'
BASE_CFLAGS = ['-g', '-fno-stack-protector', '-no-pie',
               '-Wno-implicit-function-declaration',
               '-Wno-incompatible-pointer-types',
               '-Wno-int-conversion']


@dataclass
class CompileResult:
    sample_name: str
    opt_level: str
    success: bool
    binary_path: str
    elapsed_ms: float
    error: str = ""


def find_samples(base_dir: Path) -> List[Path]:
    """递归查找所有包含vuln.c的样本目录"""
    samples = []
    for vuln_c in base_dir.rglob("vuln.c"):
        samples.append(vuln_c.parent)
    return sorted(samples)


def compile_sample(sample_dir: Path, opt_level: str) -> CompileResult:
    """编译单个样本到指定优化级别"""
    src = sample_dir / "vuln.c"
    if not src.exists():
        return CompileResult(
            sample_name=sample_dir.name, opt_level=opt_level,
            success=False, binary_path="",
            elapsed_ms=0, error=f"Source not found: {src}")

    out_dir = BUILD_DIR / sample_dir.name / opt_level
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / "target"

    cflags = BASE_CFLAGS + [f'-O{opt_level[1:]}']
    cmd = [CC] + cflags + ['-o', str(binary), str(src)]

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)
        elapsed = (time.perf_counter() - t0) * 1000
        if proc.returncode == 0:
            return CompileResult(
                sample_name=sample_dir.name, opt_level=opt_level,
                success=True, binary_path=str(binary),
                elapsed_ms=elapsed)
        else:
            return CompileResult(
                sample_name=sample_dir.name, opt_level=opt_level,
                success=False, binary_path=str(binary),
                elapsed_ms=elapsed, error=proc.stderr[:500])
    except subprocess.TimeoutExpired:
        return CompileResult(
            sample_name=sample_dir.name, opt_level=opt_level,
            success=False, binary_path="",
            elapsed_ms=30000, error="Compilation timeout")
    except Exception as e:
        return CompileResult(
            sample_name=sample_dir.name, opt_level=opt_level,
            success=False, binary_path="",
            elapsed_ms=0, error=str(e))


def compile_all(heap_only: bool = True) -> List[CompileResult]:
    """编译所有样本——heap_only=True时仅编译堆溢出样本"""
    results = []
    dirs = [SAMPLES_HEAP]
    if not heap_only:
        dirs.append(SAMPLES_LEGACY)

    for base in dirs:
        if not base.exists():
            continue
        for sample_dir in find_samples(base):
            for opt in OPT_LEVELS:
                result = compile_sample(sample_dir, opt)
                results.append(result)
                status = "OK" if result.success else f"FAIL: {result.error[:60]}"
                print(f"  [{result.opt_level}] {result.sample_name}: {status}")

    return results


def main():
    print(f"Compiling heap overflow samples ({len(list(find_samples(SAMPLES_HEAP)))} dirs)...")
    results = compile_all(heap_only=True)
    success = sum(1 for r in results if r.success)
    print(f"\nCompilation: {success}/{len(results)} succeeded")

    with open(RESULTS_FILE, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    return 0 if success == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
