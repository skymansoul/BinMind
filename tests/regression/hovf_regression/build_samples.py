"""
样本编译模块.

将每个样本目录内的 C 源码编译为 ELF/x86_64 可执行文件, 供
Angr/Ghidra/QEMU 等外部工具使用. 样本自带 Makefile 时优先调用 make;
否则直接调用 gcc. 编译产物命名 vuln 并写入样本目录, 已存在且更新的
产物跳过, 避免重复编译.

编译失败不中断批量流程, 记录失败列表供收集模块回退到源码级扫描.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from tests.regression.hovf_regression.ground_truth import load_all

_CC = os.environ.get('CC', 'gcc')
_CFLAGS = ['-O1', '-g', '-o']


def _candidate_binary(sdir: Path) -> Path:
    return sdir / ('vuln.exe' if sys.platform == 'win32' else 'vuln')


def _compile_one(sample: Dict) -> Dict:
    sdir = Path(sample['dir'])
    src = Path(sample['source'])
    binary = _candidate_binary(sdir)
    t0 = time.perf_counter()
    if binary.exists() and binary.stat().st_mtime >= src.stat().st_mtime:
        return {'name': sample['name'], 'ok': True, 'binary': str(binary),
                'cached': True, 'elapsed_s': 0.0, 'error': ''}
    makefile = sdir / 'Makefile'
    try:
        if makefile.exists():
            r = subprocess.run(['make', '-C', str(sdir)], capture_output=True,
                               text=True, timeout=120)
        else:
            r = subprocess.run([_CC, *_CFLAGS, str(binary), str(src)],
                               capture_output=True, text=True, timeout=120)
        ok = r.returncode == 0 and binary.exists()
        return {'name': sample['name'], 'ok': ok, 'binary': str(binary),
                'cached': False,
                'elapsed_s': round(time.perf_counter() - t0, 3),
                'error': r.stderr[:300] if not ok else ''}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {'name': sample['name'], 'ok': False, 'binary': str(binary),
                'cached': False,
                'elapsed_s': round(time.perf_counter() - t0, 3),
                'error': str(e)[:200]}


def build_samples() -> List[Dict]:
    """编译全部样本, 返回逐样本编译结果."""
    results = []
    for sample in load_all():
        results.append(_compile_one(sample))
    return results


if __name__ == '__main__':
    res = build_samples()
    ok = sum(1 for r in res if r['ok'])
    print(f'compiled {ok}/{len(res)} samples')
    for r in res:
        if not r['ok']:
            print(f"  FAIL {r['name']}: {r['error'][:120]}")
