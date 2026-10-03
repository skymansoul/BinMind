"""加壳/混淆变体生成 — 评估工具对变形二进制的鲁棒性。

优先 UPX 真加壳; 无 UPX 时用 strip 去符号(仍显著扰动
符号依赖型分析)。变体输出到 samples/.../packed/ 目录,
二进制工具对 plain 与 packed 各跑一次, 供分组对比。
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ..tests.backends import CLASS_ROOTS  # noqa: E402


def _method() -> str:
    if shutil.which('upx'):
        return 'upx'
    if shutil.which('strip'):
        return 'strip'
    return ''


def pack_binary(binary: Path) -> tuple:
    """生成 packed 变体。返回 (packed_path, method)。"""
    method = _method()
    if not method:
        return None, ''
    out_dir = binary.parent / 'packed'
    out_dir.mkdir(exist_ok=True)
    out = out_dir / binary.name
    if out.exists():
        return str(out), method
    if method == 'upx':
        r = subprocess.run(['upx', '-9', '-o', str(out), str(binary)],
                           capture_output=True, timeout=60)
        if r.returncode == 0:
            return str(out), method
        return None, 'upx-failed'
    # strip 去符号
    shutil.copy2(binary, out)
    r = subprocess.run(['strip', '--strip-all', str(out)],
                       capture_output=True, timeout=60)
    if r.returncode == 0:
        return str(out), method
    return None, 'strip-failed'


def pack_all(sample_class: str = 'heap') -> dict:
    method = _method()
    if not method:
        print('[pack] neither upx nor strip available')
        return {}
    print(f'[pack] method: {method} class={sample_class}')
    cfg = CLASS_ROOTS[sample_class]
    report = {}
    for base in (cfg['vuln_dir'], cfg['safe_dir']):
        for d in sorted(p for p in base.iterdir() if p.is_dir()):
            binary = d / 'vuln_O2.exe'
            if not binary.exists():
                continue
            packed, used = pack_binary(binary)
            report[d.name] = {'method': used, 'packed': packed}
            print(f'  [{used}] {d.name}')
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    args = ap.parse_args()
    sys.exit(0 if pack_all(args.sample_class) else 1)
