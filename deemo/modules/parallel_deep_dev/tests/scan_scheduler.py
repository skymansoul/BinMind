"""扫描调度模块 — 并行调度检测器扫描全部样本。

每任务: 读 vuln.c → 运行 CACBV 与朴素基线 → 记录判定/耗时。
结果写入 results/<name>.json, 供 collect_results 汇总。
"""

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from heapov import analyze_source, analyze_baseline  # noqa: E402

VULN_DIR = ROOT / 'samples' / 'heap_overflow_cve'
SAFE_DIR = ROOT / 'samples' / 'heap_safe_fp'
RESULT_DIR = Path(__file__).resolve().parent / 'results'


def load_truth(sample_dir: Path) -> dict:
    t = sample_dir / 'truth.json'
    if t.exists():
        return json.loads(t.read_text(encoding='utf-8'))
    return {'is_vuln': True, 'pattern': '', 'cwe': ''}


def scan_sample(sample_dir: Path) -> dict:
    src = (sample_dir / 'vuln.c').read_text(encoding='utf-8')
    truth = load_truth(sample_dir)

    t0 = time.perf_counter()
    cacbv = analyze_source(src)[0]
    cacbv_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    base = analyze_baseline(src)
    base_ms = (time.perf_counter() - t0) * 1000

    return {
        'name': sample_dir.name,
        'is_vuln': truth.get('is_vuln', True),
        'pattern': truth.get('pattern', ''),
        'cve': truth.get('cve', ''),
        'tools': {
            'CACBV': {
                'detected': bool(cacbv),
                'findings': cacbv,
                'ms': round(cacbv_ms, 3),
            },
            'Baseline': {
                'detected': bool(base),
                'findings': base,
                'ms': round(base_ms, 3),
            },
        },
    }


def scan_all(max_workers: int = 4) -> list:
    dirs = ([d for d in VULN_DIR.iterdir() if d.is_dir()]
            + [d for d in SAFE_DIR.iterdir() if d.is_dir()])
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(scan_sample, sorted(dirs)):
            results.append(r)
            (RESULT_DIR / f'{r["name"]}.json').write_text(
                json.dumps(r, ensure_ascii=False, indent=2), encoding='utf-8')
            print(f'  [scan] {r["name"]:42s} '
                  f'CACBV={"HIT" if r["tools"]["CACBV"]["detected"] else "-"} '
                  f'BASE={"HIT" if r["tools"]["Baseline"]["detected"] else "-"}')
    return results


if __name__ == '__main__':
    scan_all()
