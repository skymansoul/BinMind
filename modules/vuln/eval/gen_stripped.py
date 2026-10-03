"""stripped 变体生成器 — 去符号表, 模拟加壳/去符号对分析的难度影响.

  - 加壳工具 (UPX 等) 不可用, 以 strip 去符号表作为难度代理:
    无符号辅助时, 基于名字的调用解析退化为基于地址.
  - 编译参数 -O1 -fno-builtin 保持库调用形式, 避免优化内联导致
    比较口径漂移.
  - 产物: eval/<results>/stripped/<sample>/vuln.exe
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

VULN_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = VULN_ROOT / 'tests' / 'heap_fp_cve' / 'samples'
OUT = Path(__file__).resolve().parent / 'acfpc_results' / 'stripped'
OUT.mkdir(parents=True, exist_ok=True)

CFLAGS = ['-O1', '-fno-builtin', '-fno-stack-protector']


def _find_main_addr(exe: Path) -> str:
    import re as _re
    import subprocess as _sp
    try:
        proc = _sp.run(['objdump', '-d', '-M', 'intel', str(exe)],
                       capture_output=True, text=True, timeout=30)
        m = _re.search(r'^\s*([0-9a-f]+)\s+<main>:', proc.stdout, _re.M)
        return m.group(1) if m else ''
    except Exception:
        return ''

_RESULTS = {
    'heap': ('tests/heap_fp_cve/samples', 'acfpc_results'),
    'uaf': ('tests/uaf_og_cve/samples', 'og_results'),
    'fmt': ('tests/fmt_fp_cve/samples', 'fmt_results'),
}


def main() -> int:
    ap = argparse.ArgumentParser(description='stripped 变体生成')
    ap.add_argument('--type', choices=list(_RESULTS), default='heap')
    args = ap.parse_args()
    rel_samples, rel_results = _RESULTS[args.type]
    samples_dir = VULN_ROOT / rel_samples
    out = Path(__file__).resolve().parent / rel_results / 'stripped'
    out.mkdir(parents=True, exist_ok=True)
    cc = shutil.which('x86_64-w64-mingw32-gcc') or shutil.which('gcc')
    if not cc:
        print('no compiler')
        return 1
    n = 0
    for d in sorted(samples_dir.iterdir()):
        if not d.is_dir():
            continue
        src = d / 'vuln.c'
        if not src.exists():
            continue
        out_dir = out / d.name
        out_dir.mkdir(parents=True, exist_ok=True)
        out_exe = out_dir / ('vuln.exe' if 'mingw' in cc else 'vuln')
        cmd = [cc] + CFLAGS + ['-o', str(out_exe), str(src)]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=60, cwd=str(d))
        if proc.returncode != 0:
            print(f'  FAIL {d.name}: {proc.stderr[-200:]}')
            continue
        # strip 前记录 main 地址: strip 不重排布局, 地址保持有效,
        # 供无符号实验按地址构造用户代码区间
        main_addr = _find_main_addr(out_exe)
        (out_dir / 'main_addr.txt').write_text(
            main_addr or '', encoding='utf-8')
        strip = shutil.which('strip')
        if strip:
            subprocess.run([strip, '-s', str(out_exe)], capture_output=True,
                           timeout=30)
        n += 1
    print(f'stripped variants ({args.type}): {n}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
