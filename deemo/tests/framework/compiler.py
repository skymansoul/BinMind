# tests/framework/compiler.py
# 自动编译CVE样本: 遍历样本目录, 执行build.sh或直接调用gcc
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CompileResult:
    sample_name: str
    success: bool = False
    binary_path: str = ''
    optimize_level: str = 'O0'
    error_msg: str = ''


def compile_sample(sample_dir: str, optimize: str = 'O0') -> CompileResult:
    """Compile a single CVE sample with specified optimization level."""
    name = os.path.basename(sample_dir)
    src = os.path.join(sample_dir, 'vuln.c')
    binary = os.path.join(sample_dir, f'vuln_{optimize}')

    if not os.path.isfile(src):
        return CompileResult(sample_name=name, success=False,
                            error_msg=f'Source not found: {src}')

    flag = {'O0': '-g -O0', 'O2': '-O2', 'O3': '-O3'}.get(optimize, '-O0')
    cmd = f'gcc {flag} -o {binary} {src}'

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True,
                            text=True, timeout=30)
        if proc.returncode == 0 and os.path.isfile(binary):
            return CompileResult(sample_name=name, success=True,
                                binary_path=binary,
                                optimize_level=optimize)
        return CompileResult(sample_name=name, success=False,
                            optimize_level=optimize,
                            error_msg=proc.stderr[:200])
    except Exception as e:
        return CompileResult(sample_name=name, success=False,
                            error_msg=str(e))


def compile_all(samples_root: str,
                optimize_levels: List[str] = None) -> List[CompileResult]:
    """Compile all samples in the root directory."""
    if optimize_levels is None:
        optimize_levels = ['O0', 'O2']
    results = []
    for entry in sorted(os.listdir(samples_root)):
        d = os.path.join(samples_root, entry)
        if not os.path.isdir(d):
            continue
        for opt in optimize_levels:
            results.append(compile_sample(d, opt))
    return results


if __name__ == '__main__':
    root = os.path.join(os.path.dirname(__file__), '..', 'cve_samples')
    for r in compile_all(root):
        status = 'OK' if r.success else 'FAIL'
        print(f'[{status}] {r.sample_name} {r.optimize_level}')
        if r.error_msg:
            print(f'  {r.error_msg[:100]}')
