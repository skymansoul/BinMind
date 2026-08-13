"""一键编译全部50个回归测试样本 — HEAP(18) + UAF(18) + FMT(16) + INT(16).

创建: 2024-08-14
用途: 对所有回归样本执行 gcc 编译, 为后续回归测试准备二进制文件.
      支持 MinGW/MinGW-W64 on Windows + Linux gcc.

使用: python compile_all_samples.py [--clean]
"""

import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

SAMPLE_DIRS = [
    _HERE / 'test_samples' / 'heap_overflow',
    _HERE / 'detection' / 'src' / 'uaf' / 'uaf_samples',
    _HERE / 'detection' / 'src' / 'format' / 'fmt_samples',
    _HERE / 'detection' / 'src' / 'int_overflow' / 'int_samples',
]


def compile_sample(main_c: Path, out_exe: Path) -> bool:
    """编译单个 C 源文件."""
    r = subprocess.run(
        ['gcc', '-Wall', '-g', '-O0', '-o', str(out_exe), str(main_c)],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        err = r.stderr.split('\n')[0] if r.stderr else 'unknown'
        print(f'  FAIL: {main_c.parent.name} — {err[:100]}')
    return r.returncode == 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Compile all 50 regression samples')
    ap.add_argument('--clean', action='store_true', help='Remove all binaries')
    args = ap.parse_args()

    total_ok = 0
    total_fail = 0
    total_skip = 0

    for samples_dir in SAMPLE_DIRS:
        if not samples_dir.exists():
            print(f'SKIP: {samples_dir} (not found)')
            continue

        label = samples_dir.parent.name + '/' + samples_dir.name \
            if samples_dir.parent.name not in ('src', 'heap_overflow') \
            else samples_dir.name
        print(f'\n=== {label} ===')

        sample_dirs = sorted(
            [d for d in samples_dir.iterdir()
             if d.is_dir() and d.name.startswith('sample')],
            key=lambda d: d.name)

        if not sample_dirs:
            # 非标准目录结构 — 使用 compile_samples.py
            script = samples_dir / 'compile_samples.py'
            if script.exists():
                r = subprocess.run([sys.executable, str(script)],
                                 capture_output=True, text=True, timeout=120)
                print(r.stdout[-500:] if len(r.stdout) > 500 else r.stdout)
                if r.returncode == 0:
                    total_ok += 1
                else:
                    total_fail += 1
            continue

        for d in sample_dirs:
            main_c = d / 'main.c'
            if not main_c.exists():
                print(f'  SKIP: {d.name} (no main.c)')
                total_skip += 1
                continue

            out_exe = d / 'main.exe' if sys.platform == 'win32' else d / 'main'

            if args.clean:
                if out_exe.exists():
                    out_exe.unlink()
                    print(f'  CLEAN: {d.name}')
                total_ok += 1
                continue

            if out_exe.exists():
                print(f'  SKIP: {d.name} (binary exists)')
                total_skip += 1
                continue

            if compile_sample(main_c, out_exe):
                total_ok += 1
            else:
                total_fail += 1

    print(f'\n{"="*50}')
    print(f'TOTAL: {total_ok} ok, {total_fail} fail, {total_skip} skip')
    print(f'{"="*50}')


if __name__ == '__main__':
    main()
