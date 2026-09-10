"""多工具对比主实验 — PCFV/基线/angr/qemu-asan/ghidra 统一基准.

用法: python eval/fp_cve_experiment/run_benchmark.py [--exe vuln.exe]
[--out results/benchmark.csv]
输出: CSV 列:
  tool, sample_id, expected_vuln, detected_count, fp_count, fn_count,
  time_ms, peak_mem_mb, variant, error
指标口径 (逐样本):
- detected_count: 工具报告的危险写入/溢出候选数 (>0 视为检出)
- fp_count: 安全样本上的误报 (expected_vuln=false 且检出)
- fn_count: 漏洞样本上的漏报 (expected_vuln=true 且未检出)
"""
import argparse
import csv
import glob
import json
import os
import sys
import time
from _common import HERE as _HERE, list_samples, setup_paths
setup_paths(with_format=False)
from orchestrator import analyze_heap as analyze_heap_baseline
from angr_explorer import angr_scan
from qemu_tracer import run as qemu_run
from ghidra_headless import ghidra_scan
from pcfv import analyze_heap_pcfv
CORPUS = os.path.join(_HERE, 'corpus')
RESULTS = os.path.join(_HERE, 'results')

def peak_mem_mb() -> float:
    """当前进程峰值内存 (MB), 跨平台尽力而为.
    FIXME: resource 仅在 POSIX 可用, psutil 缺失时返回 0."""
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


def run_tool(tool: str, exe: str, sample_dir: str) -> dict:
    """执行单个工具, 返回统一结果."""
    t0 = time.time()
    if tool == 'pcfv':
        r = analyze_heap_pcfv(exe)
        return {'detected_count': r.confirmed + r.likely + r.uncertain,
                'time_ms': round((time.time() - t0) * 1000, 1),
                'error': r.error}
    if tool == 'baseline':
        r = analyze_heap_baseline(exe, timeout_s=60)
        return {'detected_count': r.confirmed + r.likely + r.uncertain,
                'time_ms': round((time.time() - t0) * 1000, 1),
                'error': ''}
    if tool == 'angr':
        r = angr_scan(exe)
        return {'detected_count': r['findings'], 'time_ms': r['time_ms'],
                'error': r['error']}
    if tool == 'asan':
        r = qemu_run(exe, sample_dir, mode='asan')
        return {'detected_count': r['findings'], 'time_ms': r['time_ms'],
                'error': r['error']}
    if tool == 'ghidra':
        r = ghidra_scan(exe)
        return {'detected_count': r['findings'], 'time_ms': r['time_ms'],
                'error': r['error']}
    return {'detected_count': 0, 'time_ms': 0.0, 'error': 'unknown tool'}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', default='vuln.exe')
    ap.add_argument('--out', default='')
    ap.add_argument('--tools', default='pcfv,baseline,angr,asan,ghidra')
    args = ap.parse_args()

    tools = [t.strip() for t in args.tools.split(',') if t.strip()]
    rows = []
    samples = list_samples(CORPUS)
    for d, truth in samples:
        sid = os.path.basename(d)
        with open(os.path.join(d, 'truth.json'), encoding='utf-8') as f:
            truth = json.load(f)
        exe = os.path.join(d, args.exe)
        if not os.path.exists(exe):
            continue
        for tool in tools:
            res = run_tool(tool, exe, d)
            expected = truth['expected_vuln']
            detected = res['detected_count'] > 0
            fp = 1 if (not expected and detected) else 0
            fn = 1 if (expected and not detected) else 0
            rows.append({
                'tool': tool,
                'sample_id': sid,
                'expected_vuln': expected,
                'detected_count': res['detected_count'],
                'fp_count': fp,
                'fn_count': fn,
                'time_ms': res['time_ms'],
                'peak_mem_mb': round(peak_mem_mb(), 1),
                'variant': args.exe,
                'error': res['error'][:80],
            })
            print('%-8s %-30s det=%2d fp=%d fn=%d %8.1fms %s' % (
                tool, sid, res['detected_count'], fp, fn,
                res['time_ms'], res['error'][:40]))

    os.makedirs(RESULTS, exist_ok=True)
    out_path = args.out or os.path.join(
        RESULTS, 'benchmark_%s.csv' % args.exe.replace('.', '_'))
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print('saved ->', out_path)

    # 汇总
    print('\n===== SUMMARY (%s) =====' % args.exe)
    for tool in tools:
        tr = [r for r in rows if r['tool'] == tool]
        if not tr:
            continue
        tp = sum(1 for r in tr if r['expected_vuln'] and r['fn_count'] == 0)
        fn = sum(r['fn_count'] for r in tr)
        fp = sum(r['fp_count'] for r in tr)
        tn = sum(1 for r in tr
                 if not r['expected_vuln'] and r['fp_count'] == 0)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        t = sum(r['time_ms'] for r in tr)
        print('%-9s TP=%2d FN=%2d FP=%2d TN=%2d | P=%.3f R=%.3f F1=%.3f '
              '| time=%6.0fms' % (tool, tp, fn, fp, tn, prec, rec, f1, t))

if __name__ == '__main__':
    main()
