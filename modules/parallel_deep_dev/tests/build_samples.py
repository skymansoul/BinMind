"""样本编译模块 — 把全部样本编译为可执行文件。

使用 gcc (MinGW 或系统 cc)。仅记录编译结果, 不扫描。
输出: 每样本 (name, ok, binary, opt) 列表; 写 build_report_<class>.json。
用法: python tests/build_samples.py [--class heap|uaf]
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .backends import CLASS_ROOTS

OLEVELS = ['-O0', '-O2', '-Os']


def find_cc() -> str:
    for c in ('gcc', 'cc', 'clang'):
        try:
            r = subprocess.run([c, '--version'], capture_output=True,
                               timeout=10)
            if r.returncode == 0:
                return c
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return ''


def compile_one(src_dir: Path, cc: str, opt: str) -> tuple:
    """编译单样本到 vuln{tag}.exe。返回 (binary, ok)。"""
    src = src_dir / 'vuln.c'
    tag = opt.replace('-', '')  # O0/O2/Os
    binary = src_dir / f'vuln_{tag}.exe'
    cmd = [cc, opt, '-Wall', '-o', str(binary), str(src)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0 and binary.exists()
        if not ok:
            err = (r.stderr or r.stdout)[:300]
            print(f'  [FAIL] {src_dir.name} {opt}: {err}')
        return str(binary), ok
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return str(binary), False


def build_all(sample_class: str = 'heap') -> dict:
    cc = find_cc()
    if not cc:
        print('[build] no C compiler found')
        sys.exit(1)
    print(f'[build] compiler: {cc} class={sample_class}')
    cfg = CLASS_ROOTS[sample_class]
    report = {'compiler': cc, 'samples': {}}
    for base, vuln in ((cfg['vuln_dir'], True), (cfg['safe_dir'], False)):
        for d in sorted(p for p in base.iterdir() if p.is_dir()):
            entry = {'vuln': vuln, 'binaries': {}}
            for opt in OLEVELS:
                binary, ok = compile_one(d, cc, opt)
                entry['binaries'][opt] = {'ok': ok, 'binary': binary}
            report['samples'][d.name] = entry
            status = 'OK' if all(
                v['ok'] for v in entry['binaries'].values()) else 'FAIL'
            print(f'  [{status}] {d.name}')
    report_path = Path(__file__).resolve().parent / \
        f'build_report_{sample_class}.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    n_ok = sum(1 for e in report['samples'].values()
               if all(v['ok'] for v in e['binaries'].values()))
    print(f'[build] {n_ok}/{len(report["samples"])} samples fully compiled')
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    args = ap.parse_args()
    build_all(args.sample_class)
