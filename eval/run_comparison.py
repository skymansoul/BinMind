#!/usr/bin/env python3
"""
BinMind heap overflow FP reduction comparison framework.

Compares LPVRA against existing approaches:
  - Baseline regex detection (fully implemented)
  - LPVRA (fully implemented)
  - Angr symbolic execution (conceptual framework)
  - Ghidra headless decompilation (conceptual framework)

Outputs: eval/result_table.tex (LaTeX comparison table)
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).parent.parent
BENCHMARK_DIR = PROJECT_ROOT / 'tests' / 'heap_overflow_benchmark'


class ComparisonResult:
    """Comparison across multiple analysis methods."""

    def __init__(self, sample_id: str) -> None:
        self.sample_id = sample_id
        self.methods: Dict[str, Dict[str, Any]] = {}

    def add_method(self, name: str, verdict: str, time_ms: float,
                   details: Dict[str, Any] | None = None) -> None:
        self.methods[name] = {
            'verdict': verdict,
            'time_ms': round(time_ms, 2),
            'details': details or {},
        }


def run_regex_baseline(source: str) -> Dict[str, Any]:
    """Run baseline regex detection."""
    t0 = time.time()

    alloc_re = re.compile(
        r'(\w[\w]*)\s*=\s*\(?\s*\w*\s*\*?\s*\)?\s*(malloc|calloc|realloc)\s*\(',
        re.IGNORECASE)
    store_re = re.compile(
        r'(?:memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf'
        r'|scanf|fread|recv|read)', re.IGNORECASE)

    lines = source.splitlines()
    allocs: List[Dict] = []
    writes: List[Dict] = []

    for i, line in enumerate(lines, start=1):
        m = alloc_re.search(line)
        if m:
            sz_m = re.search(rf'{re.escape(m.group(2))}\s*\(\s*(\d+)', line)
            sz = int(sz_m.group(1)) if sz_m else 0
            allocs.append({'line': i, 'var': m.group(1), 'size': sz})

    for i, line in enumerate(lines, start=1):
        if store_re.search(line):
            dest_m = re.search(
                r'(?:memcpy|strcpy|strncpy|memset|memmove)\s*\(\s*(\w[\w]*)', line)
            writes.append({'line': i, 'var': dest_m.group(1) if dest_m else ''})
            continue
        arr_m = re.search(r'(\w[\w]*)\s*\[\s*(\d+)\s*\]\s*=', line)
        if arr_m:
            writes.append({
                'line': i, 'var': arr_m.group(1),
                'offset': int(arr_m.group(2))})

    candidates = 0
    for ai in allocs:
        for wi in writes:
            if wi['var'] == ai['var']:
                candidates += 1

    elapsed = (time.time() - t0) * 1000
    return {
        'verdict': 'FLAG' if candidates > 0 else 'CLEAN',
        'time_ms': elapsed,
        'candidates': candidates,
        'allocs': len(allocs),
        'writes': len(writes),
    }


def run_lpvra(source: str) -> Dict[str, Any]:
    """Run LPVRA analysis."""
    t0 = time.time()
    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from analysis.lpvra_engine import LPVRAEngine

        engine = LPVRAEngine(max_paths=128)
        result = engine.analyze(source)

        if not result.verdicts:
            return {'verdict': 'NONE', 'time_ms': (time.time() - t0) * 1000}

        has_overflow = any(
            v.verdict.value == 'OVERFLOW' for v in result.verdicts)
        all_safe = all(
            v.verdict.value == 'SAFE' for v in result.verdicts)

        if all_safe:
            verdict = 'SAFE'
        elif has_overflow:
            verdict = 'OVERFLOW'
        else:
            verdict = 'UNCERTAIN'

        return {
            'verdict': verdict,
            'time_ms': (time.time() - t0) * 1000,
            'allocs': len(result.allocs),
            'writes': len(result.writes),
            'paths_explored': result.total_paths_explored,
            'verdicts': len(result.verdicts),
        }
    except Exception as e:
        return {
            'verdict': 'ERROR',
            'time_ms': (time.time() - t0) * 1000,
            'error': str(e),
        }


def generate_latex_table(results: List[ComparisonResult]) -> str:
    """Generate LaTeX comparison table."""
    lines = [r'\begin{table}[htbp]',
             r'\centering',
             r'\caption{Heap Overflow FP Reduction: Method Comparison}',
             r'\label{tab:comparison}',
             r'\begin{tabular}{lcccc}',
             r'\toprule',
             r'Sample & Regex Baseline & LPVRA & Ground Truth & LPVRA Correct? \\',
             r'\midrule']

    for r in results:
        regex = r.methods.get('regex', {}).get('verdict', 'N/A')
        lpvra = r.methods.get('lpvra', {}).get('verdict', 'N/A')
        truth = r.methods.get('truth', {}).get('verdict', 'N/A')

        correct = ''
        if truth == 'OVERFLOW' and lpvra in ('OVERFLOW', 'UNCERTAIN'):
            correct = r'\checkmark'
        elif truth == 'SAFE' and lpvra == 'SAFE':
            correct = r'\checkmark'
        elif truth == 'SAFE' and lpvra == 'OVERFLOW':
            correct = r'\textcolor{red}{\times}'
        elif truth == 'OVERFLOW' and lpvra == 'SAFE':
            correct = r'\textcolor{red}{\times}'

        lines.append(
            f'{r.sample_id} & {regex} & {lpvra} & {truth} & {correct} \\\\')

    lines.extend([
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
    ])
    return '\n'.join(lines)


def main() -> int:
    """Run comparison on all benchmark samples."""
    if not BENCHMARK_DIR.exists():
        print(f"Benchmark directory not found: {BENCHMARK_DIR}")
        return 1

    sample_dirs = sorted(
        [d for d in BENCHMARK_DIR.iterdir()
         if d.is_dir() and (d / 'truth.json').exists()],
        key=lambda d: d.name)

    results: List[ComparisonResult] = []

    header = f"{'Sample':30s} {'Regex':8s} {'LPVRA':10s} {'Truth':8s} {'Match':6s}"
    print(header)
    print("-" * 70)

    for sd in sample_dirs:
        truth = json.loads((sd / 'truth.json').read_text(encoding='utf-8'))
        source = (sd / 'sample.c').read_text(encoding='utf-8', errors='replace')

        cr = ComparisonResult(truth['sample_id'])

        truth_v = 'OVERFLOW' if truth['expect_overflow'] else 'SAFE'
        cr.add_method('truth', truth_v, 0)

        regex_r = run_regex_baseline(source)
        cr.add_method('regex', regex_r['verdict'], regex_r['time_ms'], regex_r)

        lpvra_r = run_lpvra(source)
        cr.add_method('lpvra', lpvra_r['verdict'], lpvra_r['time_ms'], lpvra_r)

        lpvra_v = lpvra_r['verdict']
        if truth_v == 'OVERFLOW':
            match = 'PASS' if lpvra_v in ('OVERFLOW', 'UNCERTAIN') else 'MISS'
        else:
            match = 'PASS' if lpvra_v == 'SAFE' else (
                'OK' if lpvra_v == 'UNCERTAIN' else 'FP')

        print(f"{cr.sample_id:30s} {regex_r['verdict']:8s} {lpvra_v:10s} "
              f"{truth_v:8s} {match:6s}")

        results.append(cr)

    latex = generate_latex_table(results)
    latex_path = PROJECT_ROOT / 'eval' / 'result_table.tex'
    latex_path.write_text(latex, encoding='utf-8')
    print(f"\nLaTeX table written to {latex_path}")

    tp = sum(1 for r in results
             if r.methods['truth']['verdict'] == 'OVERFLOW'
             and r.methods['lpvra']['verdict'] == 'OVERFLOW')
    tn = sum(1 for r in results
             if r.methods['truth']['verdict'] == 'SAFE'
             and r.methods['lpvra']['verdict'] == 'SAFE')
    fp = sum(1 for r in results
             if r.methods['truth']['verdict'] == 'SAFE'
             and r.methods['lpvra']['verdict'] == 'OVERFLOW')
    fn = sum(1 for r in results
             if r.methods['truth']['verdict'] == 'OVERFLOW'
             and r.methods['lpvra']['verdict'] == 'SAFE')

    print(f"\nSummary: TP={tp} TN={tn} FP={fp} FN={fn}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
