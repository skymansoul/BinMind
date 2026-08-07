"""样本编译模块 — 批量编译所有 C 测试样本为 ELF 可执行文件.

使用: python compile_samples.py [--samples-dir PATH] [--jobs N]
输出: 每个样本目录下的 vuln ELF 文件
"""

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class CompileResult:
    name: str
    success: bool
    elapsed_ms: float
    binary_path: str = ""
    error_msg: str = ""


def find_samples(base_dir: str) -> List[str]:
    """扫描 base_dir 下所有含 src/vuln.c 的样本目录."""
    samples = []
    for entry in sorted(os.listdir(base_dir)):
        sample_dir = os.path.join(base_dir, entry)
        src_file = os.path.join(sample_dir, "src", "vuln.c")
        if os.path.isdir(sample_dir) and os.path.isfile(src_file):
            samples.append(sample_dir)
    return samples


def compile_one(sample_dir: str) -> CompileResult:
    """编译单个样本."""
    name = os.path.basename(sample_dir)
    src = os.path.join(sample_dir, "src", "vuln.c")
    # Windows gcc 自动追加 .exe
    binary = os.path.join(sample_dir, "vuln.exe" if sys.platform == "win32" else "vuln")

    start = time.perf_counter()
    try:
        result = subprocess.run(
            ["gcc", "-Wall", "-O0", "-g", "-no-pie",
             "-fno-stack-protector", "-o", binary, src],
            capture_output=True, text=True, timeout=30)
        elapsed = (time.perf_counter() - start) * 1000
        if result.returncode == 0:
            return CompileResult(name=name, success=True,
                                 elapsed_ms=elapsed, binary_path=binary)
        else:
            return CompileResult(name=name, success=False,
                                 elapsed_ms=elapsed,
                                 error_msg=result.stderr[:500])
    except subprocess.TimeoutExpired:
        elapsed = (time.perf_counter() - start) * 1000
        return CompileResult(name=name, success=False,
                             elapsed_ms=elapsed, error_msg="timeout")
    except FileNotFoundError:
        return CompileResult(name=name, success=False, elapsed_ms=0,
                             error_msg="gcc not found — install mingw-w64 or gcc")


def compile_all(samples_dir: str, jobs: int = 4) -> List[CompileResult]:
    """并行编译所有样本."""
    samples = find_samples(samples_dir)
    if not samples:
        print(f"[!] no samples found in {samples_dir}")
        return []

    results = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(compile_one, s): s for s in samples}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.name)
    return results


def print_summary(results: List[CompileResult]):
    """打印编译摘要."""
    ok = sum(1 for r in results if r.success)
    fail = len(results) - ok
    total_time = sum(r.elapsed_ms for r in results)
    print(f"\n{'='*60}")
    print(f"  Compile Summary: {ok}/{len(results)} succeeded, "
          f"{fail} failed, {total_time:.0f}ms total")
    print(f"{'='*60}")
    for r in results:
        status = "OK" if r.success else "FAIL"
        print(f"  [{status}] {r.name} ({r.elapsed_ms:.0f}ms)")
        if not r.success and r.error_msg:
            print(f"         {r.error_msg[:120]}")


def main():
    parser = argparse.ArgumentParser(description="Compile all C test samples")
    parser.add_argument("--samples-dir", default=None,
                        help="Path to heap_samples directory")
    parser.add_argument("--jobs", type=int, default=4,
                        help="Parallel compile jobs")
    args = parser.parse_args()

    if args.samples_dir:
        samples_dir = args.samples_dir
    else:
        samples_dir = os.path.join(os.path.dirname(__file__), "heap_samples")

    results = compile_all(samples_dir, args.jobs)
    print_summary(results)

    # 返回码: 任意失败 → 1
    return 0 if all(r.success for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
