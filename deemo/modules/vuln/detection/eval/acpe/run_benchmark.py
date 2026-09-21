"""多工具对比主实验 — 分配容量溯源 vs 基线 vs angr vs qemu vs ghidra.

对所有样本(plain/packed 两档)调用全部工具, 输出统一 CSV:
  tool, sample_id, detected, fp, fn, elapsed_sec, peak_mem_mb

指标口径:
  detected  样本级检出 (存在 ≥1 告警/运行时越界)
  fp        该工具在 clean 样本上误报 = 1
  fn        该工具在 vuln 样本上漏检 = 1
峰值内存: 各工具在进程内以 tracemalloc 度量 (Python 进程估算)。

用法:
  python run_benchmark.py [--samples <root>] [--out <dir>]
"""

import argparse
import csv
import json
import sys
import time
import tracemalloc
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _anchor in _HERE.parents:
    if (_anchor / 'modules').exists():
        sys.path.insert(0, str(_anchor))
        break

from modules.vuln.detection.eval.acpe.angr_explorer import explore as _angr
from modules.vuln.detection.eval.acpe.qemu_tracer import trace as _qemu
from modules.vuln.detection.eval.acpe.ghidra_headless import audit as _ghidra
from modules.vuln.detection.tests.heap_acpe_cve.scan_runner import (
    acpe_detect, baseline_detect)

_HEADER = ["tool", "sample_id", "detected", "fp", "fn",
           "elapsed_sec", "peak_mem_mb"]


def _run_tool(name, fn, binary) -> dict:
    tracemalloc.start()
    t0 = time.time()
    try:
        r = fn(binary)
    except Exception as exc:
        r = {'detected': False, 'error': f'{type(exc).__name__}: {exc}'}
    elapsed = round(time.time() - t0, 3)
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        'tool': name,
        'detected': bool(r.get('detected', False)),
        'elapsed_sec': elapsed,
        'peak_mem_mb': round(peak / (1024 * 1024), 3),
        'error': r.get('error', ''),
        'raw': r,
    }


def discover_samples(root: Path) -> list:
    """返回 [(sample_id, expected, {plain: bin, packed: bin})]."""
    manifest = root / 'manifest.json'
    exp = {}
    if manifest.exists():
        exp = {d['id']: d['expected']
               for d in json.loads(manifest.read_text(encoding='utf-8'))}
    samples = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        src = next(d.glob('*.c'), None)
        if src is None:
            continue
        stem = src.stem
        bins = {}
        for tier in ('plain', 'packed'):
            b = d / 'bin' / tier / f'{stem}.exe'
            if b.exists():
                bins[tier] = str(b)
        samples.append({'id': d.name, 'expected': exp.get(d.name, 'vuln'),
                        'bins': bins})
    return samples


def run_all(root: Path, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    tools = {
        'acpe': acpe_detect,
        'baseline': baseline_detect,
        'angr': _angr,
        'qemu': _qemu,
        'ghidra': _ghidra,
    }
    samples = discover_samples(root)
    rows = []
    by_tool = {t: {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'time': 0.0}
               for t in tools}

    for s in samples:
        for tier, binary in s['bins'].items():
            for tname, tfunc in tools.items():
                r = _run_tool(tname, tfunc, binary)
                detected = r['detected']
                is_vuln = s['expected'] == 'vuln'
                fp = 1 if (not is_vuln and detected) else 0
                fn = 1 if (is_vuln and not detected) else 0
                tp = 1 if (is_vuln and detected) else 0
                tn = 1 if (not is_vuln and not detected) else 0
                st = by_tool[tname]
                st['tp'] += tp
                st['fp'] += fp
                st['tn'] += tn
                st['fn'] += fn
                st['time'] += r['elapsed_sec']
                rows.append([
                    tname, f"{s['id']}:{tier}", int(detected), fp, fn,
                    r['elapsed_sec'], r['peak_mem_mb'],
                ])

    with open(out / 'benchmark_results.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(_HEADER)
        w.writerows(rows)

    summary = {}
    for t, st in by_tool.items():
        recall = st['tp'] / (st['tp'] + st['fn']) if (st['tp'] + st['fn']) else 0
        precision = (st['tp'] / (st['tp'] + st['fp'])
                     if (st['tp'] + st['fp']) else 0)
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0)
        summary[t] = {
            'tp': st['tp'], 'fp': st['fp'], 'tn': st['tn'], 'fn': st['fn'],
            'recall': round(recall, 4), 'precision': round(precision, 4),
            'f1': round(f1, 4),
            'fp_rate': round(st['fp'] / (st['fp'] + st['tn']), 4)
            if (st['fp'] + st['tn']) else 0.0,
            'total_sec': round(st['time'], 3),
        }
    (out / 'benchmark_summary.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=None)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    root = Path(args.samples) if args.samples else (
        _HERE.parent.parent / 'tests' / 'heap_acpe_cve' / 'samples')
    out = Path(args.out) if args.out else _HERE / 'results'
    run_all(root, out)


if __name__ == '__main__':
    main()
