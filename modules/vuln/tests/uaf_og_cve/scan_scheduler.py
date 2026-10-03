"""UAF-OG 扫描调度 — 反汇编 → 基线候选 → 代际压缩.

  - 每样本两步: UafBaseScanner 得朴素候选 (BASE), OgFilter 压缩
    得保留集 (UAF-OG). 两套指标对比量化误报压缩.
  - 反汇编解析复用 tests/_common/disasm, 与基准脚本共享.
  - 并行线程池 + 超时保护, 单样本失败不影响整体.
"""

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

VULN_ROOT = Path(__file__).resolve().parents[2]
OG_DIR = VULN_ROOT / 'src' / 'uaf' / 'og'
for _p in (str(OG_DIR), str(VULN_ROOT / 'src'), str(VULN_ROOT / 'tests')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'
MAX_WORKERS = 4


def _binary_of(d: Path) -> Path:
    for name in ('vuln.exe', 'vuln'):
        p = d / name
        if p.exists():
            return p
    return Path('')


def scan_one(d: Path) -> dict:
    from uaf_base_scanner import UafBaseScanner
    from og_filter import OgFilter
    binary = _binary_of(d)
    result = {'sample': d.name}
    if not binary.exists():
        result['error'] = 'no binary'
        return result
    t0 = time.time()
    from _common.disasm import (disassemble, parse_asm, main_range,
                                   range_from_addr)
    from heap.acfpc.pe_imports import build_import_map
    asm = disassemble(str(binary))
    lines, addrs, labels = parse_asm(asm)
    if not lines:
        result['error'] = 'empty disasm'
        result['base'] = result['kept'] = 0
        return result
    urange = main_range(labels, len(lines))
    if urange is None:
        addr_file = binary.parent / 'main_addr.txt'
        if addr_file.exists():
            urange = range_from_addr(addrs, int(addr_file.read_text(
                encoding='utf-8').strip(), 16))
    import_map = build_import_map(str(binary), asm)
    base = UafBaseScanner().scan(lines, addrs, user_range=urange,
                                 import_map=import_map)
    og = OgFilter().compress(lines, base, addrs, import_map=import_map)
    result.update({
        'base': len(base),
        'kept': len(og.kept),
        'suppressed': len(og.suppressed),
        'same_gen': og.stats.same_gen,
        'diff_gen': og.stats.diff_gen,
        'unknown': og.stats.unknown,
        'elapsed_ms': round((time.time() - t0) * 1000, 1),
    })
    return result


def scan_all() -> dict:
    dirs = sorted(d for d in SAMPLES_DIR.iterdir() if d.is_dir())
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {pool.submit(scan_one, d): d for d in dirs}
        for fut in as_completed(futs):
            results.append(fut.result())
    results.sort(key=lambda r: r['sample'])
    return {
        'samples': results,
        'n_samples': len(results),
        'total_base': sum(r.get('base', 0) for r in results),
        'total_kept': sum(r.get('kept', 0) for r in results),
        'total_suppressed': sum(r.get('suppressed', 0) for r in results),
        'avg_ms': round(sum(r.get('elapsed_ms', 0) for r in results)
                        / max(1, len(results)), 1),
    }


def main():
    ap = argparse.ArgumentParser(description='UAF-OG 扫描调度')
    ap.add_argument('--json', type=str, default='scan_results.json')
    args = ap.parse_args()
    res = scan_all()
    print(f"samples={res['n_samples']} base={res['total_base']} "
          f"kept={res['total_kept']} suppressed={res['total_suppressed']} "
          f"avg={res['avg_ms']}ms")
    for r in res['samples']:
        status = 'ERR' if 'error' in r else 'ok'
        print(f"  [{status}] {r['sample']}: base={r.get('base')} "
              f"kept={r.get('kept')} sup={r.get('suppressed')} "
              f"{r.get('elapsed_ms')}ms"
              + (f" {r.get('error','')}" if 'error' in r else ''))
    jp = Path(args.json)
    jp.parent.mkdir(parents=True, exist_ok=True)
    jp.write_text(json.dumps(res, ensure_ascii=False, indent=2),
                  encoding='utf-8')
    print(f'saved: {args.json}')


if __name__ == '__main__':
    main()
