#!/usr/bin/env python3
"""堆溢出检测回归测试 — 编译→扫描→评估完整管线."""
import json, os, subprocess, sys, time
from pathlib import Path

BASE = Path(__file__).parent
SAMPLES = BASE / 'heap_samples'
OUTPUT = BASE / 'heap_results'

def compile_samples(compiler='gcc'):
    """编译所有样本, 返回 (success_count, total)."""
    results = []
    for d in sorted(SAMPLES.iterdir()):
        if not d.is_dir() or not d.name.startswith('CVE-'):
            continue
        src = d / 'cve.c'
        out = d / 'cve.elf'
        if not src.exists():
            continue
        try:
            r = subprocess.run(
                [compiler, '-w', '-O0', '-g', '-o', str(out), str(src)],
                capture_output=True, text=True, timeout=30)
            results.append({'sample': d.name, 'ok': r.returncode == 0,
                           'error': r.stderr.strip()[:100] if r.returncode else ''})
        except Exception as e:
            results.append({'sample': d.name, 'ok': False, 'error': str(e)[:100]})
    return results

def scan_samples(detector='heap'):
    """扫描所有编译好的样本, 收集检测结果."""
    results = []
    for d in sorted(SAMPLES.iterdir()):
        if not d.is_dir():
            continue
        elf = d / 'cve.elf'
        if not elf.exists():
            continue
        t0 = time.time()
        try:
            from core.heap_analyzer import analyze_heap_operations
            findings = analyze_heap_operations(str(elf))
            elapsed = time.time() - t0
            detected = bool(findings)
            types = [f.get('type', '?') for f in findings]
            results.append({
                'sample': d.name, 'binary': str(elf),
                'detected': detected, 'n_findings': len(findings),
                'types': types, 'elapsed': round(elapsed, 3),
            })
        except Exception as e:
            results.append({
                'sample': d.name, 'binary': str(elf),
                'detected': False, 'n_findings': 0,
                'elapsed': round(time.time()-t0, 3), 'error': str(e)[:100],
            })
    return results

def evaluate(scans, ground_truth=None):
    """评估检测结果: 检出率, 误报率."""
    if ground_truth is None:
        ground_truth = {d.name: True for d in SAMPLES.iterdir()
                       if d.is_dir() and d.name.startswith('CVE-')}
    total = len(scans)
    tp = sum(1 for s in scans if s['detected'])
    fn = total - tp
    detection_rate = tp / max(total, 1)
    return {
        'total': total, 'detected': tp, 'missed': fn,
        'detection_rate': round(detection_rate, 4),
        'avg_elapsed': round(sum(s['elapsed'] for s in scans) / max(total, 1), 4),
    }

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    compiler = sys.argv[1] if len(sys.argv) > 1 else 'gcc'

    print('='*50)
    print(f'Phase 1/3: Compiling {compiler}...')
    compile_results = compile_samples(compiler)
    ok = sum(1 for r in compile_results if r['ok'])
    print(f'  Compiled {ok}/{len(compile_results)}')
    for r in compile_results:
        if not r['ok']:
            print(f'    FAIL: {r["sample"]} — {r["error"]}')

    print(f'\nPhase 2/3: Scanning with heap analyzer...')
    scan_results = scan_samples()
    with open(OUTPUT / 'scan_results.json', 'w') as f:
        json.dump(scan_results, f, indent=2)
    print(f'  Scanned {len(scan_results)} binaries')

    print(f'\nPhase 3/3: Evaluating...')
    eval_result = evaluate(scan_results)
    print(f'  Detection Rate: {eval_result["detection_rate"]:.2%}')
    print(f'  Avg Time: {eval_result["avg_elapsed"]}s')
    with open(OUTPUT / 'evaluation.json', 'w') as f:
        json.dump(eval_result, f, indent=2)
    print(f'\nResults saved to {OUTPUT}')

if __name__ == '__main__':
    main()
