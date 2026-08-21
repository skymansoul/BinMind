"""扫描调度模块 — 并行调度检测器扫描全部样本。

每任务: 读 vuln.c → 运行 LCV/CACBV 与朴素基线 → 记录判定/耗时。
结果写入 results_<class>/<name>.json, 供 collect_results 汇总。
用法: python tests/scan_scheduler.py [--class heap|uaf]
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .backends import CLASS_ROOTS, load_detectors


def load_truth(sample_dir: Path) -> dict:
    t = sample_dir / 'truth.json'
    if t.exists():
        return json.loads(t.read_text(encoding='utf-8'))
    return {'is_vuln': True, 'pattern': '', 'cwe': ''}


def scan_sample(sample_dir: Path, detect, base, tool: str) -> dict:
    src = (sample_dir / 'vuln.c').read_text(encoding='utf-8')
    truth = load_truth(sample_dir)

    t0 = time.perf_counter()
    det_findings = detect(src)[0] if tool != 'LCV' else detect(src)[0]
    det_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    base_findings = base(src)
    base_ms = (time.perf_counter() - t0) * 1000

    return {
        'name': sample_dir.name,
        'is_vuln': truth.get('is_vuln', True),
        'pattern': truth.get('pattern', ''),
        'cve': truth.get('cve', ''),
        'tools': {
            tool: {'detected': bool(det_findings), 'findings': det_findings,
                   'ms': round(det_ms, 3)},
            'Baseline': {'detected': bool(base_findings),
                         'findings': base_findings, 'ms': round(base_ms, 3)},
        },
    }


def scan_all(sample_class: str = 'heap', max_workers: int = 4) -> list:
    detect, base, tool = load_detectors(sample_class)
    cfg = CLASS_ROOTS[sample_class]
    dirs = ([d for d in cfg['vuln_dir'].iterdir() if d.is_dir()]
            + [d for d in cfg['safe_dir'].iterdir() if d.is_dir()])
    res_dir = cfg['results']
    res_dir.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(lambda d: scan_sample(d, detect, base, tool),
                        sorted(dirs)):
            results.append(r)
            (res_dir / f'{r["name"]}.json').write_text(
                json.dumps(r, ensure_ascii=False, indent=2), encoding='utf-8')
            print(f'  [scan] {r["name"]:44s} '
                  f'{tool}={"HIT" if r["tools"][tool]["detected"] else "-"} '
                  f'BASE={"HIT" if r["tools"]["Baseline"]["detected"] else "-"}')
    return results


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()
    scan_all(args.sample_class, args.workers)
