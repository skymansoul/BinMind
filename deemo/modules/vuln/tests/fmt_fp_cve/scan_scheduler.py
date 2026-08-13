"""Fmt-OG 扫描调度 — 反汇编 → printf 调用提取 → 三态压缩.

基线 (BASE) 口径: 所有非 .rdata 常量格式串的 printf 调用均报为
疑似 (用户可控格式串). Fmt-OG 口径: 证据链压缩后的保留集.
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

VULN_ROOT = Path(__file__).resolve().parents[2]
SRC = VULN_ROOT / 'src'
for _p in (str(SRC), str(VULN_ROOT / 'tests'), str(SRC / 'format' / 'fmtog')):
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
    from _common.disasm import (disassemble, parse_asm, main_range,
                                   range_from_addr)
    from heap.acfpc.pe_imports import build_import_map
    from rdata_strings import extract_rdata_strings
    from fmt_compressor import FmtCompressor
    binary = _binary_of(d)
    result = {'sample': d.name}
    if not binary.exists():
        result['error'] = 'no binary'
        result['base'] = result['kept'] = 0
        return result
    t0 = time.time()
    asm = disassemble(str(binary))
    lines, addrs, labels = parse_asm(asm)
    if not lines:
        result['error'] = 'empty disasm'
        result['base'] = result['kept'] = 0
        return result
    rdata = extract_rdata_strings(str(binary))
    urange = main_range(labels, len(lines))
    if urange is None:
        addr_file = binary.parent / 'main_addr.txt'
        if addr_file.exists():
            urange = range_from_addr(addrs, int(addr_file.read_text(
                encoding='utf-8').strip(), 16))
    import_map = build_import_map(str(binary), asm)
    comp = FmtCompressor().compress(lines, addrs, labels, rdata,
                                    user_range=urange,
                                    import_map=import_map)
    # 基线: 用户区间内调用点为疑似 (base 检出面)
    base = comp.stats.in_range
    kept = len(comp.kept)
    result.update({
        'base': base,
        'kept': kept,
        'suppressed': comp.stats.suppressed,
        'confirmed': comp.stats.confirmed,
        'unchanged': comp.stats.unchanged,
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
    ap = argparse.ArgumentParser(description='Fmt-OG 扫描调度')
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
              f"cfm={r.get('confirmed')} {r.get('elapsed_ms')}ms"
              + (f" {r.get('error','')}" if 'error' in r else ''))
    jp = Path(args.json)
    jp.parent.mkdir(parents=True, exist_ok=True)
    jp.write_text(json.dumps(res, ensure_ascii=False, indent=2),
                  encoding='utf-8')
    print(f'saved: {args.json}')


if __name__ == '__main__':
    main()
