"""
编译模块 — 自动编译CVE漏洞样本.

职责: 扫描样本目录, 调用编译器生成可执行文件.
不参与扫描逻辑, 不做结果解析.
"""

import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple


def find_c_sources(sample_dir: str) -> List[str]:
    """递归查找所有.c源文件."""
    sources = []
    for root, _, files in os.walk(sample_dir):
        for f in files:
            if f.endswith('.c'):
                sources.append(os.path.join(root, f))
    return sorted(sources)


def compile_sample(src_path: str, compiler: str = 'gcc',
                   extra_flags: str = '') -> Tuple[bool, str]:
    """编译单个C源文件.

    Returns: (success, output_path_or_error)
    """
    out_path = src_path.rsplit('.', 1)[0] + '.elf'
    flags = '-w -O0 -g -fno-stack-protector -z execstack -no-pie ' + extra_flags
    cmd = f'{compiler} {flags} -o {out_path} {src_path}'
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return True, out_path
        return False, result.stderr.strip()[:200]
    except subprocess.TimeoutExpired:
        return False, 'compilation timeout'
    except FileNotFoundError:
        return False, f'compiler {compiler} not found'


def build_all(sample_dir: str, compiler: str = 'gcc',
              extra_flags: str = '') -> List[dict]:
    """编译所有样本, 返回结果列表."""
    results = []
    sources = find_c_sources(sample_dir)
    for src in sources:
        ok, msg = compile_sample(src, compiler, extra_flags)
        results.append({
            'source': src,
            'success': ok,
            'output': msg if ok else None,
            'error': msg if not ok else None,
        })
    return results


if __name__ == '__main__':
    sample_dir = sys.argv[1] if len(sys.argv) > 1 else '../vuln_samples'
    compiler = sys.argv[2] if len(sys.argv) > 2 else 'gcc'
    results = build_all(sample_dir, compiler)
    ok = sum(1 for r in results if r['success'])
    print(f'Compiled {ok}/{len(results)} samples with {compiler}')
    for r in results:
        status = 'OK' if r['success'] else 'FAIL'
        print(f'  [{status}] {r["source"]}')
        if not r['success']:
            print(f'         {r["error"]}')
