"""编译 ALPR UAF 样本集 — MinGW gcc 双档 (O0/O2).

创建: 2024-09-27
用法:
  python compile_samples.py [样本根目录] [--gcc <path>]
"""

import argparse
import json
import shutil
import subprocess
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def find_gcc(preferred: str = "") -> str:
    if preferred and Path(preferred).exists():
        return preferred
    for cand in ('gcc', 'x86_64-w64-mingw32-gcc', 'cc'):
        p = shutil.which(cand)
        if p:
            return p
    return ''


def compile_one(gcc: str, src: Path, out: Path, opt: str) -> bool:
    out.parent.mkdir(parents=True, exist_ok=True)
    flags = [gcc, opt, '-fno-pic', '-fno-stack-protector']
    if opt == '-O2':
        flags += ['-fno-tree-dce', '-fno-tree-dse', '-fno-inline',
                  '-fno-builtin']
    flags += [str(src), '-o', str(out)]
    try:
        proc = subprocess.run(
            flags, capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace')
        return proc.returncode == 0
    except Exception:
        return False


def compile_all(root: Path, gcc: str) -> dict:
    report = {'gcc': gcc, 'samples': []}
    if not gcc:
        print('[compile] gcc not found — skipping')
        report['skipped'] = True
        return report
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        src = next(d.glob('*.c'), None)
        if src is None:
            continue
        name = src.stem
        entry = {'id': d.name, 'name': name}
        entry['plain'] = compile_one(gcc, src, d / 'bin' / 'plain' / f'{name}.exe', '-O0')
        entry['packed'] = compile_one(gcc, src, d / 'bin' / 'packed' / f'{name}.exe', '-O2')
        report['samples'].append(entry)
    (root / 'compile_report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default=None)
    ap.add_argument('--gcc', default='')
    args = ap.parse_args()
    root = Path(args.root) if args.root else _HERE / 'samples'
    compile_all(root, find_gcc(args.gcc))


if __name__ == '__main__':
    main()
