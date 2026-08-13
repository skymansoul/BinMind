"""PCFV 可扩展性基准 — 四工具在合成大二进制上的耗时/峰值内存.

创建: 2023-07-13
用法: python eval/fp_cve_experiment/run_scalability.py [--out results/scalability.csv]
输出: CSV (tool, scale, insns, time_ms, peak_mem_mb)
"""
import argparse
import csv
import glob
import os
import subprocess
import sys
import time

from _common import HERE as _HERE, DEEMO as _DEEMO, setup_paths
setup_paths(with_format=False)
from pcfv import analyze_heap_pcfv
from orchestrator import analyze_heap as analyze_heap_baseline
from ghidra_headless import ghidra_scan
from angr_explorer import angr_scan

SCAL_DIR = os.path.join(_HERE, 'scalability')
RESULTS = os.path.join(_HERE, 'results')
TIMEOUTS = {'pcfv': 300, 'baseline': 300, 'ghidra': 120, 'angr': 90}


def count_insns(exe: str) -> int:
    proc = subprocess.run(['objdump', '-d', '-M', 'intel', exe],
                          capture_output=True, text=True, timeout=60)
    n = 0
    for line in proc.stdout.splitlines():
        s = line.strip()
        # 指令行格式: 140001511: e8 ... (hex 地址 + 冒号)
        if len(s) > 3 and ':' in s[:12] and s[0] in '0123456789abcdef':
            n += 1
    return n


def peak_mem_mb() -> float:
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        pass
    try:
        import psutil
        return psutil.Process().memory_info().peak_wset / (1024 * 1024)
    except Exception:
        return 0.0


def run_one(tool: str, exe: str) -> dict:
    t0 = time.time()
    if tool == 'pcfv':
        r = analyze_heap_pcfv(exe, timeout_s=120)
        return {'time_ms': round((time.time() - t0) * 1000, 1),
                'error': r.error}
    if tool == 'baseline':
        r = analyze_heap_baseline(exe, timeout_s=120)
        return {'time_ms': round((time.time() - t0) * 1000, 1), 'error': ''}
    if tool == 'ghidra':
        r = ghidra_scan(exe, timeout_sec=90)
        return {'time_ms': r['time_ms'], 'error': r['error']}
    if tool == 'angr':
        r = angr_scan(exe, timeout_sec=60)
        return {'time_ms': r['time_ms'], 'error': r['error']}
    return {'time_ms': 0.0, 'error': 'unknown'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='')
    ap.add_argument('--tools', default='pcfv,baseline,ghidra,angr')
    args = ap.parse_args()

    tools = [t.strip() for t in args.tools.split(',') if t.strip()]
    rows = []
    for exe in sorted(glob.glob(os.path.join(SCAL_DIR, 'scal_*.exe'))):
        scale = int(os.path.basename(exe).split('_')[1].split('.')[0])
        insns = count_insns(exe)
        print('scale=%d insns=%d' % (scale, insns))
        for tool in tools:
            mem_before = peak_mem_mb()
            res = run_one(tool, exe)
            mem_after = peak_mem_mb()
            rows.append({
                'tool': tool, 'scale': scale, 'insns': insns,
                'time_ms': res['time_ms'],
                'peak_mem_mb': round(max(mem_before, mem_after), 1),
                'error': res['error'][:60],
            })
            print('  %-9s %10.1f ms  mem=%7.1f MB  %s' % (
                tool, res['time_ms'], rows[-1]['peak_mem_mb'],
                res['error'][:40]))

    os.makedirs(RESULTS, exist_ok=True)
    out = args.out or os.path.join(RESULTS, 'scalability.csv')
    with open(out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print('saved ->', out)


if __name__ == '__main__':
    main()
