"""扫描调度模块 — 对样本批量执行分配契约流保持管线.

  - 每个样本: analyze_heap 得基线 findings → 分配契约流保持压缩得 kept.
    基线 vs 压缩后的指标差即误报压缩效果.
  - 线程池并发, 单样本超时保护, 单线程失败不影响整体.
  - 产物: 每样本 {base, kept, suppressed, confirmed, contracts,
    writes, elapsed_ms, binary} + 汇总统计.
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

VULN_ROOT = Path(__file__).resolve().parents[2]      # modules/vuln
HEAP_DIR = VULN_ROOT / 'src' / 'heap'
for _p in (str(HEAP_DIR), str(VULN_ROOT / 'src')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'
MAX_WORKERS = 4


def _binary_of(sample_dir: Path) -> Path:
    for name in ('vuln.exe', 'vuln'):
        p = sample_dir / name
        if p.exists():
            return p
    return Path('')


def scan_one(sample_dir: Path, timeout_s: int = 60) -> dict:
    from acfpc.alloc_contract_pipeline import run_acfpc_pipeline
    binary = _binary_of(sample_dir)
    result = {'sample': sample_dir.name}
    if not binary.exists():
        result['error'] = 'no binary; run compile_samples.py first'
        result['base'] = result['kept'] = 0
        return result
    t0 = time.time()
    try:
        rep = run_acfpc_pipeline(str(binary), timeout_s=timeout_s)
        result.update({
            'base': rep.base_findings,
            'kept': rep.kept_findings,
            'suppressed': rep.suppressed,
            'confirmed': rep.confirmed,
            'contracts': rep.n_contracts,
            'writes': rep.n_writes,
            'suppress_rate': rep.suppress_rate,
            'elapsed_ms': round(rep.elapsed_sec * 1000, 1),
            'findings': rep.findings[:8],
            'suppressed_sites': rep.suppressed_sites[:8],
        })
    except Exception as e:
        result['error'] = str(e)[:200]
        result['base'] = result['kept'] = 0
    result['elapsed_ms'] = round((time.time() - t0) * 1000, 1)
    return result


def scan_all(timeout_s: int = 60, workers: int = MAX_WORKERS) -> dict:
    dirs = sorted(d for d in SAMPLES_DIR.iterdir() if d.is_dir())
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(scan_one, d, timeout_s): d for d in dirs}
        for fut in as_completed(futs):
            results.append(fut.result())
    results.sort(key=lambda r: r['sample'])
    n_ok = sum(1 for r in results if 'error' not in r)
    return {
        'samples': results,
        'n_samples': len(results),
        'n_ok': n_ok,
        'total_base': sum(r.get('base', 0) for r in results),
        'total_kept': sum(r.get('kept', 0) for r in results),
        'total_suppressed': sum(r.get('suppressed', 0) for r in results),
        'total_confirmed': sum(r.get('confirmed', 0) for r in results),
        'avg_ms': round(sum(r.get('elapsed_ms', 0) for r in results)
                        / max(1, len(results)), 1),
    }


def main():
    ap = argparse.ArgumentParser(description='ACFPC 样本扫描调度')
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--json', type=str, default='scan_results.json')
    args = ap.parse_args()
    res = scan_all(timeout_s=args.timeout)
    print(f"samples={res['n_samples']} ok={res['n_ok']} "
          f"base={res['total_base']} kept={res['total_kept']} "
          f"suppressed={res['total_suppressed']} "
          f"confirmed={res['total_confirmed']} avg={res['avg_ms']}ms")
    for r in res['samples']:
        status = 'ERR' if 'error' in r else 'ok'
        print(f"  [{status}] {r['sample']}: base={r.get('base')} "
              f"kept={r.get('kept')} sup={r.get('suppressed')} "
              f"cfm={r.get('confirmed')} {r.get('elapsed_ms')}ms"
              + (f" {r.get('error','')}" if 'error' in r else ''))
    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(
        json.dumps(res, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'saved: {args.json}')


if __name__ == '__main__':
    main()
