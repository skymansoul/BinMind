"""stripped 变体生成器 — 去符号表, 模拟加壳/去符号对分析的难度影响.

  - 加壳工具 (UPX 等) 不可用, 以 strip 去符号表作为难度代理:
    无符号辅助时, 基于名字的调用解析退化为基于地址.
  - 编译参数 -O1 -fno-builtin 保持 memcpy/malloc 库调用形式,
    避免优化内联导致比较口径漂移.
  - 产物: eval/acfpc_results/stripped/<sample>/vuln.exe
"""

import shutil
import subprocess
import sys
from pathlib import Path

VULN_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = VULN_ROOT / 'tests' / 'heap_fp_cve' / 'samples'
OUT = Path(__file__).resolve().parent / 'acfpc_results' / 'stripped'
OUT.mkdir(parents=True, exist_ok=True)

CFLAGS = ['-O1', '-fno-builtin', '-fno-stack-protector']


def main() -> int:
    cc = shutil.which('x86_64-w64-mingw32-gcc') or shutil.which('gcc')
    if not cc:
        print('no compiler')
        return 1
    n = 0
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        src = d / 'vuln.c'
        if not src.exists():
            continue
        out_dir = OUT / d.name
        out_dir.mkdir(parents=True, exist_ok=True)
        out_exe = out_dir / ('vuln.exe' if 'mingw' in cc else 'vuln')
        cmd = [cc] + CFLAGS + ['-o', str(out_exe), str(src)]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=60, cwd=str(d))
        if proc.returncode != 0:
            print(f'  FAIL {d.name}: {proc.stderr[-200:]}')
            continue
        strip = shutil.which('strip')
        if strip:
            subprocess.run([strip, '-s', str(out_exe)], capture_output=True,
                           timeout=30)
        n += 1
    print(f'stripped variants: {n}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
