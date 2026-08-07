"""样本编译模块 — 编译 tests/heap_fp_cve/samples 下全部样本.

  - 每个样本目录独立编译, 产出 vuln.exe (MinGW) 或 vuln (ELF).
  - 探测编译器顺序: x86_64-w64-mingw32-gcc > gcc. 编译器不可用时
    尝试使用已有二进制 (--quick), 保证评估可离线复现.
  - 默认 -O0 便于指令级分析; -O1 变体经 --opt 生成, 用于对比
    优化对误报率的影响.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'
DEFAULT_CFLAGS = ['-O0', '-fno-stack-protector', '-fno-builtin']
OPT_CFLAGS = ['-O2', '-fno-stack-protector']


def find_compiler() -> str:
    for cc in ('x86_64-w64-mingw32-gcc', 'gcc', 'clang'):
        if shutil.which(cc):
            return cc
    return ''


def compile_one(sample_dir: Path, cc: str, extra_flags: list,
                timeout: int = 60) -> dict:
    src = sample_dir / 'vuln.c'
    if not src.exists():
        return {'sample': sample_dir.name, 'ok': False, 'error': 'no vuln.c'}
    out_name = 'vuln.exe' if 'mingw' in cc else 'vuln'
    out_path = sample_dir / out_name
    if sys.platform != 'win32' and 'mingw' not in cc:
        out_name = 'vuln'
        out_path = sample_dir / 'vuln'
    cmd = [cc] + extra_flags + ['-o', str(out_path), str(src)]
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(sample_dir))
        dt = round(time.time() - t0, 3)
        if proc.returncode != 0:
            return {'sample': sample_dir.name, 'ok': False,
                    'error': proc.stderr[-300:], 'time_s': dt}
        return {'sample': sample_dir.name, 'ok': True,
                'binary': out_path.name, 'time_s': dt}
    except Exception as e:
        return {'sample': sample_dir.name, 'ok': False, 'error': str(e)}


def compile_all(quick: bool = False, opt: bool = False) -> dict:
    cc = find_compiler()
    flags = OPT_CFLAGS if opt else DEFAULT_CFLAGS
    results = {'compiler': cc or 'NONE', 'samples': []}
    if not cc:
        results['error'] = 'no compiler found; using prebuilt binaries only'
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        exe = d / 'vuln.exe'
        elf = d / 'vuln'
        if quick and (exe.exists() or elf.exists()):
            results['samples'].append(
                {'sample': d.name, 'ok': True, 'binary': 'existing',
                 'time_s': 0.0})
            continue
        if not cc:
            results['samples'].append(
                {'sample': d.name, 'ok': False, 'error': 'no compiler'})
            continue
        results['samples'].append(compile_one(d, cc, flags))
    results['ok_count'] = sum(1 for s in results['samples'] if s['ok'])
    results['total'] = len(results['samples'])
    return results


def main():
    ap = argparse.ArgumentParser(description='ACFPC 样本编译')
    ap.add_argument('--quick', action='store_true', help='复用已有二进制')
    ap.add_argument('--opt', action='store_true', help='编译 -O2 变体')
    ap.add_argument('--json', type=str, default='', help='输出 JSON 路径')
    args = ap.parse_args()
    res = compile_all(quick=args.quick, opt=args.opt)
    print(f"compiler: {res['compiler']}  ok: {res['ok_count']}/{res['total']}")
    for s in res['samples']:
        mark = 'OK ' if s['ok'] else 'FAIL'
        print(f"  [{mark}] {s['sample']}" +
              (f" ({s['binary']})" if s['ok'] else f" {s.get('error','')}"))
    if args.json:
        import json
        jp = Path(args.json)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(res, ensure_ascii=False, indent=2),
                      encoding='utf-8')
    return 0 if res['ok_count'] == res['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
