#!/usr/bin/env python3
# coding: utf-8
"""
批量编译所有 CVE 样本 — 对每个子目录执行 gcc 编译.
输出编译状态报告, 统计成功/失败数.
"""

import os, sys, subprocess, json

ROOT = os.path.dirname(os.path.abspath(__file__))
CC = os.environ.get('CC', 'gcc')
CFLAGS = ['-std=c11', '-O0', '-g', '-Wall']


def find_samples() -> list:
    """发现所有含 vuln.c 的子目录."""
    samples = []
    for entry in sorted(os.listdir(ROOT)):
        subdir = os.path.join(ROOT, entry)
        if os.path.isdir(subdir):
            src = os.path.join(subdir, 'vuln.c')
            if os.path.isfile(src):
                samples.append((entry, subdir, src))
    return samples


def compile_one(name: str, subdir: str, src: str) -> dict:
    """编译单个样本."""
    out = os.path.join(subdir, f'{name}.exe')
    cmd = [CC] + CFLAGS + ['-o', out, src]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {'name': name, 'success': result.returncode == 0,
                'stderr': result.stderr[:200] if result.returncode != 0 else '',
                'output': out if result.returncode == 0 else None}
    except FileNotFoundError:
        return {'name': name, 'success': False,
                'stderr': f'编译器不可用: {CC}', 'output': None}
    except subprocess.TimeoutExpired:
        return {'name': name, 'success': False,
                'stderr': '编译超时(30s)', 'output': None}


def build_all():
    samples = find_samples()
    print(f'Found {len(samples)} samples, CC={CC}')
    results = []
    ok = fail = 0
    for name, subdir, src in samples:
        r = compile_one(name, subdir, src)
        results.append(r)
        status = 'OK' if r['success'] else 'FAIL'
        print(f'  [{status}] {name}')
        if r['success']: ok += 1
        else: fail += 1
        if r['stderr']:
            print(f'         {r["stderr"].strip()}')

    print(f'\nBuild: {ok} OK, {fail} FAIL, {len(samples)} total')

    # 保存编译报告
    report_path = os.path.join(ROOT, 'build_report.json')
    with open(report_path, 'w') as f:
        json.dump({'cc': CC, 'ok': ok, 'fail': fail, 'total': len(samples),
                   'results': results}, f, indent=2)
    print(f'Report: {report_path}')
    return results


if __name__ == '__main__':
    build_all()
