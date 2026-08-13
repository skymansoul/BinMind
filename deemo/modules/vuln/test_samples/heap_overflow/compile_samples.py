"""编译所有堆溢出测试样本.

创建: 2025-01-13
用途: 编译 sample*/ 目录下的 C 源码为 x86-64 ELF, 生成 objdump 反汇编.

运行: python compile_samples.py [--clean] [--samples sample01 sample02 ...]
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SAMPLE_DIR = Path(__file__).resolve().parent
CC = os.environ.get('CC', 'gcc')
OBJDUMP = os.environ.get('OBJDUMP', 'objdump')
CFLAGS = ['-Wall', '-O0', '-g', '-fno-builtin', '-fno-stack-protector',
          '-no-pie']


def compile_sample(sample_path: Path) -> Tuple[bool, str]:
    """编译单个样本, 返回 (success, error_msg)."""
    src = sample_path / 'main.c'
    out = sample_path / 'main'
    out_exe = sample_path / 'main.exe'
    asm = sample_path / 'main.asm'

    if not src.exists():
        return False, f'{src} not found'

    # 编译 — Windows/MinGW 自动加 .exe 后缀
    cmd = [CC] + CFLAGS + ['-o', str(out), str(src)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, f'compile failed: {r.stderr[:200]}'
    except FileNotFoundError:
        return False, f'{CC} not found'
    except subprocess.TimeoutExpired:
        return False, 'compile timeout'

    # MinGW 可能产出 .exe 而非无后缀 ELF
    binary = out if out.exists() else out_exe
    if not binary.exists():
        return False, 'binary not found after compile'

    # 反汇编
    cmd = [OBJDUMP, '-d', '-M', 'intel', str(binary)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, f'objdump failed: {r.stderr[:200]}'
        asm.write_text(r.stdout, encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return True, f'{OBJDUMP} not found (ELF compiled)'

    return True, ''


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Compile heap overflow test samples')
    ap.add_argument('--clean', action='store_true', help='Remove compiled binaries')
    ap.add_argument('--samples', nargs='*', help='Specific samples to compile')
    args = ap.parse_args()

    # 发现所有 sample 目录
    all_samples = sorted([
        d for d in SAMPLE_DIR.iterdir()
        if d.is_dir() and d.name.startswith('sample') and (d / 'main.c').exists()
    ], key=lambda d: d.name)

    if args.samples:
        all_samples = [d for d in all_samples if d.name in args.samples]

    if not all_samples:
        print('No samples found.')
        return

    if args.clean:
        for d in all_samples:
            for f in ('main', 'main.asm', 'main.o'):
                fp = d / f
                if fp.exists():
                    fp.unlink()
                    print(f'  cleaned {d.name}/{f}')
        print(f'Cleaned {len(all_samples)} samples.')
        return

    results = {}
    ok = fail = 0
    for d in all_samples:
        print(f'  [{d.name}] ', end='', flush=True)
        success, err = compile_sample(d)
        results[d.name] = {'success': success, 'error': err}
        if success:
            print('OK')
            ok += 1
        else:
            print(f'FAIL: {err}')
            fail += 1

    print(f'\nResults: {ok} OK, {fail} FAIL out of {len(all_samples)}')

    # 保存编译结果
    res_file = SAMPLE_DIR / 'compile_results.json'
    res_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f'Saved: {res_file}')


if __name__ == '__main__':
    main()
