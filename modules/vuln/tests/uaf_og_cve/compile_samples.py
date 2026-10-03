"""UAF-OG 样本编译模块 — 编译 tests/uaf_og_cve/samples 下全部样本.

  - 与 heap_fp_cve 编译模块同构: 独立目录独立产出, 编译器探测
    MinGW gcc 优先, 产出 vuln.exe/vuln.
  - -O0 -fno-builtin 保持 free/malloc 库调用形式, 供代际分析识别.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'
CFLAGS = ['-O0', '-fno-stack-protector', '-fno-builtin']


def find_compiler() -> str:
    for cc in ('x86_64-w64-mingw32-gcc', 'gcc', 'clang'):
        if shutil.which(cc):
            return cc
    return ''


def compile_one(d: Path, cc: str) -> dict:
    src = d / 'vuln.c'
    out_name = 'vuln.exe' if 'mingw' in cc else 'vuln'
    out = d / out_name
    t0 = time.time()
    try:
        proc = subprocess.run([cc] + CFLAGS + ['-o', str(out), str(src)],
                              capture_output=True, text=True, timeout=60,
                              cwd=str(d))
        return {'sample': d.name, 'ok': proc.returncode == 0,
                'binary': out_name,
                'time_s': round(time.time() - t0, 3),
                'error': proc.stderr[-200:] if proc.returncode else ''}
    except Exception as e:
        return {'sample': d.name, 'ok': False, 'error': str(e)}


def main():
    ap = argparse.ArgumentParser(description='UAF-OG 样本编译')
    ap.add_argument('--json', type=str, default='')
    args = ap.parse_args()
    cc = find_compiler()
    res = {'compiler': cc or 'NONE', 'samples': []}
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        exe = d / 'vuln.exe'
        elf = d / 'vuln'
        if exe.exists() or elf.exists():
            res['samples'].append({'sample': d.name, 'ok': True,
                                   'binary': 'existing', 'time_s': 0.0})
            continue
        res['samples'].append(compile_one(d, cc) if cc else
                              {'sample': d.name, 'ok': False,
                               'error': 'no compiler'})
    res['ok_count'] = sum(1 for s in res['samples'] if s['ok'])
    res['total'] = len(res['samples'])
    print(f"compiler: {res['compiler']}  ok: {res['ok_count']}/{res['total']}")
    for s in res['samples']:
        mark = 'OK ' if s['ok'] else 'FAIL'
        print(f"  [{mark}] {s['sample']}" +
              (f" ({s['binary']})" if s['ok'] else f" {s.get('error','')}"))
    if args.json:
        jp = Path(args.json)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(res, ensure_ascii=False, indent=2),
                      encoding='utf-8')
    return 0 if res['ok_count'] == res['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
