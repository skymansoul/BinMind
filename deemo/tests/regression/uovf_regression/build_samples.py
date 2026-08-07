"""
UAF 样本编译模块.

将每个样本目录内的 C 源码编译为可执行文件. 复用堆套件的编译
策略: 有 Makefile 用 make, 否则直接 gcc. 编译失败不阻断, 由
调度模块回退到源码级分析.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from tests.regression.uovf_regression.ground_truth import load_all

_CC = os.environ.get('CC', 'gcc')


def _binary(sdir: Path) -> Path:
    return sdir / ('vuln.exe' if sys.platform == 'win32' else 'vuln')


def _compile_one(sample: Dict) -> Dict:
    sdir = Path(sample['dir'])
    src = Path(sample['source'])
    binary = _binary(sdir)
    t0 = time.perf_counter()
    if binary.exists() and binary.stat().st_mtime >= src.stat().st_mtime:
        return {'name': sample['name'], 'ok': True, 'binary': str(binary),
                'cached': True, 'elapsed_s': 0.0, 'error': ''}
    try:
        if (sdir / 'Makefile').exists():
            r = subprocess.run(['make', '-C', str(sdir)],
                               capture_output=True, text=True, timeout=120)
        else:
            r = subprocess.run([_CC, '-O1', '-g', '-o', str(binary), str(src)],
                               capture_output=True, text=True, timeout=120)
        ok = r.returncode == 0 and binary.exists()
        return {'name': sample['name'], 'ok': ok, 'binary': str(binary),
                'cached': False,
                'elapsed_s': round(time.perf_counter() - t0, 3),
                'error': r.stderr[:200] if not ok else ''}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {'name': sample['name'], 'ok': False, 'binary': str(binary),
                'cached': False,
                'elapsed_s': round(time.perf_counter() - t0, 3),
                'error': str(e)[:150]}


def build_samples() -> List[Dict]:
    return [_compile_one(s) for s in load_all()]


if __name__ == '__main__':
    res = build_samples()
    ok = sum(1 for r in res if r['ok'])
    print(f'compiled {ok}/{len(res)}')
    for r in res:
        if not r['ok']:
            print(f"  FAIL {r['name']}: {r['error'][:120]}")
