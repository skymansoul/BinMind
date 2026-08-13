"""样本编译模块 — 自动化编译所有测试样本为ELF.

创建: 2025-06-09
用途: 遍历 sample_bins/ 目录, 对每个子目录执行 make,
      记录编译成功/失败状态, 输出编译报告。
"""
import os
import subprocess
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class CompileResult:
    sample_name: str
    source_file: str
    success: bool
    binary_path: str = ""
    error_msg: str = ""
    compiler: str = "gcc"


def find_samples(base_dir: str) -> List[str]:
    """扫描样本目录, 返回所有含 Makefile 的子目录路径."""
    samples = []
    base = Path(base_dir)
    for d in sorted(base.iterdir()):
        if d.is_dir() and (d / "Makefile").exists():
            samples.append(str(d))
    return samples


def compile_sample(sample_dir: str) -> CompileResult:
    """编译单个样本."""
    name = Path(sample_dir).name
    c_files = list(Path(sample_dir).glob("*.c"))
    src = str(c_files[0].name) if c_files else "unknown.c"
    result = CompileResult(sample_name=name, source_file=src, success=False)

    try:
        proc = subprocess.run(
            ["make", "-C", sample_dir, "clean"],
            capture_output=True, text=True, timeout=30)
        proc = subprocess.run(
            ["make", "-C", sample_dir],
            capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            result.success = True
            # 查找生成的二进制
            target_name = Path(src).stem
            binary = Path(sample_dir) / target_name
            if binary.exists():
                result.binary_path = str(binary)
        else:
            result.error_msg = proc.stderr[:500]
    except FileNotFoundError:
        result.error_msg = "gcc not found — install mingw-w64 or gcc"
    except subprocess.TimeoutExpired:
        result.error_msg = "compilation timeout (>60s)"
    except Exception as e:
        result.error_msg = str(e)[:500]

    return result


def compile_all(base_dir: str) -> List[CompileResult]:
    """编译所有样本, 返回结果列表."""
    samples = find_samples(base_dir)
    results = []
    for sd in samples:
        r = compile_sample(sd)
        results.append(r)
        status = "OK" if r.success else f"FAIL: {r.error_msg[:60]}"
        print(f"  [{r.sample_name}] {status}")
    return results


def summary(results: List[CompileResult]) -> dict:
    ok = [r for r in results if r.success]
    fail = [r for r in results if not r.success]
    return {
        "total": len(results),
        "success": len(ok),
        "failed": len(fail),
        "success_rate": len(ok) / max(1, len(results)),
        "binaries": [r.binary_path for r in ok],
        "failures": [{"sample": r.sample_name, "error": r.error_msg}
                     for r in fail],
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.join(base, "..", "sample_bins")
    if not os.path.isdir(samples_dir):
        print(f"ERROR: samples directory not found: {samples_dir}")
        sys.exit(1)

    print(f"Compiling samples in {samples_dir}...")
    results = compile_all(samples_dir)
    s = summary(results)

    print(f"\n{'='*50}")
    print(f"Compilation Summary: {s['success']}/{s['total']} succeeded")
    if s['failed']:
        print(f"Failures:")
        for f in s['failures']:
            print(f"  - {f['sample']}: {f['error'][:100]}")

    # 输出JSON供后续模块使用
    report_path = os.path.join(base, "compile_report.json")
    with open(report_path, "w") as fp:
        json.dump(s, fp, indent=2)
    print(f"Report written to {report_path}")

    sys.exit(0 if s['failed'] == 0 else 1)
