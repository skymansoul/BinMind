# coding: utf-8
"""堆 CVE 样本编译模块 — 直接调用 gcc, 不依赖 make.

遍历 cve_samples 下所有含 vuln.c 的目录, 编译为 {dirname}.exe / .elf
(按平台), 并检测附加的 packed 变体目录 (name_packed/). 输出编译摘要.
"""

import os, subprocess, sys, json
from typing import Any, Dict, List, Optional, Tuple

CC = os.environ.get('CC', 'gcc')
CFLAGS = ['-std=c11', '-O0', '-g', '-Wall', '-fno-stack-protector']
OUT_EXT = '.exe' if sys.platform == 'win32' else '.elf'


def find_samples(root: str) -> List[Tuple[str, str]]:
    """返回 [(样本名, vuln.c 路径)]."""
    samples = []
    for entry in sorted(os.listdir(root)):
        subdir = os.path.join(root, entry)
        if os.path.isdir(subdir):
            src = os.path.join(subdir, 'vuln.c')
            if os.path.isfile(src):
                samples.append((entry, src))
    return samples


def compile_one(name: str, src: str, out_dir: str) -> Dict[str, Any]:
    """编译单个样本, 输出二进制到 out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f'{name}{OUT_EXT}')
    cmd = [CC] + CFLAGS + ['-o', out, src]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {'name': name, 'success': r.returncode == 0,
                'output': out if r.returncode == 0 else '',
                'stderr': r.stderr[:300] if r.returncode != 0 else ''}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {'name': name, 'success': False, 'output': '',
                'stderr': f'{CC} 不可用或超时: {e}'}


def compile_all(root: str, out_dir: Optional[str] = None,
                output_json: Optional[str] = None) -> Dict[str, Any]:
    """批量编译, 返回 {total, success, failed, elf_paths, errors, results}."""
    if out_dir is None:
        out_dir = os.path.join(root, 'build')
    samples = find_samples(root)
    results = [compile_one(n, src, out_dir) for n, src in samples]
    ok = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    summary = {
        'cc': CC, 'total': len(results), 'success': len(ok),
        'failed': len(failed),
        'out_dir': out_dir,
        'elf_paths': [r['output'] for r in ok],
        'errors': [{'name': r['name'], 'error': r['stderr']} for r in failed],
        'results': results,
    }
    if output_json:
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)
    return summary


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=os.path.join(
        os.path.dirname(__file__), '..', 'cve_samples'))
    ap.add_argument('--out-dir')
    ap.add_argument('--output-json', default='build_report.json')
    args = ap.parse_args()
    summary = compile_all(args.root, args.out_dir, args.output_json)
    print(f'Build: {summary["success"]}/{summary["total"]} OK, '
          f'{summary["failed"]} FAIL')
    for e in summary['errors']:
        print(f'  FAIL {e["name"]}: {e["error"][:120]}')
    for p in summary['elf_paths']:
        print(f'  OK  {os.path.basename(p)}')
