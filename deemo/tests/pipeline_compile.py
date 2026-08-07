"""
回归测试管道 — 编译阶段。

封装 heap_overflow 基准样本的批量编译逻辑,
与 compile_samples.py 的差异: 专注 tests/samples/heap_overflow 目录,
输出结构化编译清单供扫描阶段消费。
"""
import os
import sys
import time
import subprocess
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(BASE, 'tests', 'samples', 'heap_overflow')


def compile_sample(src_path: str, out_path: str, timeout: int = 30) -> dict:
    """编译单个样本, 返回结构化结果。"""
    t0 = time.time()
    cc = _find_compiler()
    try:
        proc = subprocess.run(
            [cc, '-g', '-O0', '-fno-stack-protector', '-o', out_path, src_path],
            capture_output=True, text=True, timeout=timeout,
        )
        ok = proc.returncode == 0
        return {
            'compiled': ok,
            'binary': out_path,
            'error': proc.stderr[:200] if not ok else '',
            'compile_ms': int((time.time() - t0) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            'compiled': False, 'binary': out_path,
            'error': 'timeout', 'compile_ms': int((time.time() - t0) * 1000),
        }
    except Exception as e:
        return {
            'compiled': False, 'binary': out_path,
            'error': str(e)[:200], 'compile_ms': int((time.time() - t0) * 1000),
        }


def compile_all_samples(sample_dir: str = None) -> list:
    """编译 sample_dir 下所有含 vuln.c 的子目录, 返回编译结果列表。"""
    sdir = sample_dir or SAMPLE_DIR
    if not os.path.isdir(sdir):
        return []
    results = []
    for d in sorted(Path(sdir).iterdir()):
        if not d.is_dir():
            continue
        src = d / 'vuln.c'
        if not src.exists():
            continue
        out = d / 'vuln.exe'
        r = compile_sample(str(src), str(out))
        r['name'] = d.name
        results.append(r)
    return results


def _find_compiler() -> str:
    """优先使用 D:\\mingw64\\bin\\gcc.exe, 回退到 PATH 中的 gcc。"""
    mingw_gcc = r'D:\mingw64\bin\gcc.exe'
    if os.path.isfile(mingw_gcc):
        return mingw_gcc
    return 'gcc'


def print_compile_summary(results: list):
    """打印编译阶段汇总。"""
    ok = [r for r in results if r['compiled']]
    bad = [r for r in results if not r['compiled']]
    print(f'  编译成功: {len(ok)}, 失败: {len(bad)}')
    for b in bad:
        print(f'    FAIL {b["name"]}: {b["error"][:80]}')
    return ok, bad


if __name__ == '__main__':
    print('=' * 60)
    print('编译阶段 — tests/samples/heap_overflow')
    print('=' * 60)
    results = compile_all_samples()
    ok, bad = print_compile_summary(results)
    print(f'\n总计: {len(ok)} 成功, {len(bad)} 失败')
