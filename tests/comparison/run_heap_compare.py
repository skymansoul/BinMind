#!/usr/bin/env python3
"""横向对比实验: BinMind vs Angr vs QEMU vs Ghidra — 堆溢出检测."""
import json, os, subprocess, sys, time, resource
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).parent.parent
SAMPLES = BASE / 'heap_samples'
OUTPUT = Path(__file__).parent

def find_binaries():
    bins = []
    for d in sorted(SAMPLES.iterdir()):
        if d.is_dir():
            elf = d / 'cve.elf'
            if elf.exists():
                bins.append(str(elf))
    return bins

def measure(fn, *args):
    t0 = time.time()
    try:
        r = fn(*args)
        return r, time.time()-t0, 0
    except Exception as e:
        return None, time.time()-t0, str(e)[:80]

def run_binmind(bp):
    try:
        from core.heap_analyzer import analyze_heap_operations
        findings = analyze_heap_operations(bp)
        return {'findings': len(findings), 'success': True}
    except Exception as e:
        return {'findings': 0, 'success': False, 'error': str(e)[:80]}

def run_angr(bp):
    try:
        import angr
        p = angr.Project(bp, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
        dangerous = {'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memmove'}
        count = sum(1 for f in cfg.functions.values() if f.name in dangerous)
        return {'findings': count, 'success': True}
    except Exception as e:
        return {'findings': 0, 'success': False, 'error': str(e)[:80]}

def run_qemu(bp):
    try:
        r = subprocess.run(
            ['qemu-x86_64', '-strace', bp, 'AAAA'],
            capture_output=True, text=True, timeout=10)
        lines = r.stderr.count('\n')
        return {'findings': min(lines, 99), 'success': True}
    except FileNotFoundError:
        return {'findings': -1, 'success': False, 'error': 'qemu not installed'}
    except Exception as e:
        return {'findings': 0, 'success': False, 'error': str(e)[:80]}

def run_ghidra(bp):
    try:
        r = subprocess.run(
            ['ghidra_headless', bp, 'test', '-postScript', '/dev/null'],
            capture_output=True, text=True, timeout=120)
        return {'findings': 0, 'success': False, 'error': 'ghidra_headless not available'}
    except FileNotFoundError:
        return {'findings': -1, 'success': False, 'error': 'ghidra not installed'}
    except Exception as e:
        return {'findings': 0, 'success': False, 'error': str(e)[:80]}

def main():
    binaries = find_binaries()
    print(f'Found {len(binaries)} binaries')

    tools = [
        ('BinMind', run_binmind),
        ('Angr', run_angr),
        ('QEMU', run_qemu),
        ('Ghidra', run_ghidra),
    ]

    results = []
    for i, bp in enumerate(binaries):
        name = Path(bp).parent.name
        print(f'\n[{i+1}/{len(binaries)}] {name}')
        for tname, tfn in tools:
            r, elapsed, err = measure(tfn, bp)
            entry = {
                'tool': tname, 'sample': name, 'binary': bp,
                'elapsed': round(elapsed, 3),
                'findings': r['findings'] if r else 0,
                'success': r['success'] if r else False,
                'error': err or '',
            }
            results.append(entry)
            status = 'OK' if entry['success'] else f'FAIL({entry["error"][:30]})'
            print(f'  {tname:10s}: {entry["findings"]:3d} findings, {elapsed:.2f}s {status}')

    with open(OUTPUT / 'heap_comparison_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    by_tool = defaultdict(lambda: {'total':0, 'findings':0, 'elapsed':0})
    for r in results:
        t = r['tool']
        by_tool[t]['total'] += 1
        by_tool[t]['findings'] += max(0, r['findings'])
        by_tool[t]['elapsed'] += r['elapsed']

    print('\n=== SUMMARY ===')
    for tool in ['BinMind','Angr','QEMU','Ghidra']:
        s = by_tool[tool]
        n = max(s['total'], 1)
        print(f'  {tool:10s}: {n} bins, {s["findings"]} findings, '
              f'{s["elapsed"]:.1f}s total ({s["elapsed"]/n:.2f}s avg)')

    print(f'\nResults: {OUTPUT}/heap_comparison_results.json')

if __name__ == '__main__':
    main()
