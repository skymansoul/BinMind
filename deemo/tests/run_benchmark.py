#!/usr/bin/env python3
"""
堆溢出误报削减benchmark自动化测试脚本.

功能:
  1. 采样编译模块 — 编译每个样本的C源码
  2. 扫描调度模块 — 对每个样本执行：regex基线检测 + LPVRA过滤分析
  3. 结果收集与对比模块 — 计算TP/TN/FP/FN/Precision/Recall/F1/耗时

一键运行: python -m tests.run_benchmark

输出: tests/heap_overflow_benchmark/BENCHMARK_REPORT.md
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from tests.run_benchmark_data import SampleResult, BenchmarkReport, generate_markdown_report


BENCHMARK_DIR = Path(__file__).parent / 'heap_overflow_benchmark'
PROJECT_ROOT = Path(__file__).parent.parent


class HeapOverflowScanner:
    """堆溢出扫描器 — 包装regex基线检测 + LPVRA分析."""

    _HEAP_ALLOC_RE = None
    _STORE_RE = None

    @classmethod
    def _init_regex(cls):
        if cls._HEAP_ALLOC_RE is None:
            import re
            cls._HEAP_ALLOC_RE = re.compile(
                r'(\w[\w]*)\s*=\s*\(?\s*\w*\s*\*?\s*\)?\s*(malloc|calloc|realloc)\s*\(',
                re.IGNORECASE)
            cls._STORE_RE = re.compile(
                r'(?:memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf|scanf|fread|recv|read)',
                re.IGNORECASE)

    def baseline_scan(self, source: str):
        """regex基线检测. Returns: (detected, candidate_count, reason)"""
        self._init_regex()
        import re
        lines = source.splitlines()
        allocs, writes = [], []

        for i, line in enumerate(lines, start=1):
            m = self._HEAP_ALLOC_RE.search(line)
            if m:
                alloc_var = m.group(1)
                sz_m = re.search(rf'{re.escape(m.group(2))}\s*\(\s*(\d+|\w[\w]*)', line)
                sz = int(sz_m.group(1)) if sz_m and sz_m.group(1).isdigit() else 0
                allocs.append({'line': i, 'var': alloc_var, 'func': m.group(2), 'size': sz})

        for i, line in enumerate(lines, start=1):
            if self._STORE_RE.search(line):
                dest_m = re.search(
                    r'(?:memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf'
                    r'|scanf|fread|recv|read)\s*\(\s*(\w[\w]*)', line)
                dest_var = dest_m.group(1) if dest_m else ""
                writes.append({'line': i, 'var': dest_var, 'op': 'copy'})
                continue
            arr_m = re.search(r'(\w[\w]*)\s*\[\s*(\d+)\s*\]\s*=', line)
            if arr_m:
                writes.append({
                    'line': i, 'var': arr_m.group(1),
                    'offset': int(arr_m.group(2)), 'op': 'store'})

        candidates = 0
        for ai in allocs:
            for wi in writes:
                if wi['var'] == ai['var']:
                    if ai['size'] > 0 and 'offset' in wi:
                        if wi['offset'] + (wi.get('size', 1) or 1) > ai['size']:
                            candidates += 1
                    else:
                        candidates += 1

        return candidates > 0, candidates, f"regex: {len(allocs)} allocs, {len(writes)} writes, {candidates} candidates"

    def lpvra_scan(self, source: str):
        """LPVRA + Guard分析."""
        try:
            sys.path.insert(0, str(PROJECT_ROOT))
            from analysis.lpvra_engine import LPVRAEngine, Verdict as LVerdict
            from analysis.guard_relation_analyzer import analyze_guard, GuardVerdict

            engine = LPVRAEngine(max_paths=128)
            result = engine.analyze(source)
            alloc_count = len(result.allocs)
            write_count = len(result.writes)
            safe_paths, total_paths = 0, 0

            if not result.verdicts:
                lpvra_verdict = 'NONE'
            else:
                safe_paths = sum(v.safe_paths for v in result.verdicts)
                total_paths = sum(v.total_paths for v in result.verdicts)
                has_overflow = any(v.verdict == LVerdict.OVERFLOW for v in result.verdicts)
                all_safe = all(v.verdict == LVerdict.SAFE for v in result.verdicts)
                if all_safe:
                    lpvra_verdict = 'SAFE'
                elif has_overflow:
                    lpvra_verdict = 'OVERFLOW'
                else:
                    lpvra_verdict = 'UNCERTAIN'

            verdict = lpvra_verdict
            if lpvra_verdict in ('UNCERTAIN', 'OVERFLOW', 'NONE'):
                guard_results = analyze_guard(source)
                if guard_results:
                    safe_guards = [g for g in guard_results if g.verdict == GuardVerdict.SAFE]
                    if safe_guards:
                        verdict = 'SAFE'

            return (verdict, safe_paths, total_paths, alloc_count, write_count, '')

        except Exception as e:
            return ('ERROR', 0, 0, 0, 0, str(e))


def compile_sample(sample_dir: Path):
    """编译单个样本. Returns (success, error_message)."""
    sample_c = sample_dir / 'sample.c'
    if not sample_c.exists():
        return False, f"sample.c not found in {sample_dir}"

    makefile = sample_dir / 'Makefile'
    if makefile.exists():
        try:
            subprocess.run(['make', '-C', str(sample_dir), 'clean'],
                           capture_output=True, text=True, timeout=10)
            result = subprocess.run(['make', '-C', str(sample_dir)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return True, ""
            return False, result.stderr.strip()[:200]
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            return False, "compilation timeout"

    try:
        result = subprocess.run(
            ['gcc', '-Wall', '-O0', '-g', '-o',
             str(sample_dir / 'sample'), str(sample_c)],
            capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()[:200]
    except FileNotFoundError:
        return False, "gcc not found"
    except subprocess.TimeoutExpired:
        return False, "compilation timeout"


def evaluate_sample(sample_dir: Path, scanner: HeapOverflowScanner) -> SampleResult:
    """对单个样本执行完整的检测评估."""
    sample_c = sample_dir / 'sample.c'
    truth_json = sample_dir / 'truth.json'

    if not sample_c.exists():
        return SampleResult(sample_id=sample_dir.name, label='error')

    source = sample_c.read_text(encoding='utf-8', errors='replace')
    truth = {}
    if truth_json.exists():
        truth = json.loads(truth_json.read_text(encoding='utf-8'))

    result = SampleResult(
        sample_id=truth.get('sample_id', sample_dir.name),
        label=truth.get('label', 'unknown'),
        truth_overflow=truth.get('expect_overflow', False),
    )

    # regex基线检测
    t0 = time.time()
    try:
        detected, n_candidates, reason = scanner.baseline_scan(source)
        result.regex_detected = detected
        result.regex_candidates = n_candidates
    except Exception as e:
        result.regex_error = str(e)
    result.regex_time_ms = (time.time() - t0) * 1000

    # LPVRA分析
    t0 = time.time()
    verdict, safe_p, total_p, allocs, writes, error = scanner.lpvra_scan(source)
    result.lpvra_verdict = verdict
    result.lpvra_safe_paths = safe_p
    result.lpvra_total_paths = total_p
    result.lpvra_allocs = allocs
    result.lpvra_writes = writes
    result.lpvra_error = error
    result.lpvra_time_ms = (time.time() - t0) * 1000

    # 判定
    if result.truth_overflow:
        if result.lpvra_verdict == 'SAFE':
            result.is_fn = True
        elif result.lpvra_verdict == 'OVERFLOW':
            result.is_tp = True
    else:
        if result.lpvra_verdict == 'SAFE':
            result.is_tn = True
        elif result.lpvra_verdict == 'OVERFLOW':
            result.is_fp = True

    return result


def run_all_benchmarks() -> BenchmarkReport:
    """执行所有样本的benchmark评估."""
    scanner = HeapOverflowScanner()
    report = BenchmarkReport()

    if not BENCHMARK_DIR.exists():
        print(f"Benchmark directory not found: {BENCHMARK_DIR}")
        return report

    sample_dirs = sorted(
        [d for d in BENCHMARK_DIR.iterdir()
         if d.is_dir() and (d / 'truth.json').exists()],
        key=lambda d: d.name)

    if not sample_dirs:
        print(f"No samples found in {BENCHMARK_DIR}")
        return report

    t_total_start = time.time()

    print(f"{'Sample':30s} {'Truth':6s} {'LPVRA':10s} {'Result':8s} {'Time':8s} {'Details'}")
    print("-" * 100)

    for sd in sample_dirs:
        sr = evaluate_sample(sd, scanner)
        report.samples.append(sr)
        result_str = sr.lpvra_verdict
        truth_str = 'OVERFLOW' if sr.truth_overflow else 'SAFE'
        status = 'PASS' if (sr.is_tp or sr.is_tn) else ('MISS' if sr.is_fn else 'FLAG')
        details = f"a={sr.lpvra_allocs} w={sr.lpvra_writes} p={sr.lpvra_safe_paths}/{sr.lpvra_total_paths}"
        if sr.lpvra_error:
            details += f" err={sr.lpvra_error[:40]}"
        print(f"{sr.sample_id:30s} {truth_str:6s} {result_str:10s} {status:8s} "
              f"{sr.lpvra_time_ms:6.1f}ms {details}")

    report.total_time_ms = (time.time() - t_total_start) * 1000
    return report


def main():
    """主入口."""
    print("=" * 60)
    print("  Heap Overflow FP Reduction Benchmark — LPVRA Pipeline")
    print("=" * 60)
    print()

    report = run_all_benchmarks()
    metrics = report.compute_metrics()
    report_path = BENCHMARK_DIR / 'BENCHMARK_REPORT.md'
    generate_markdown_report(report, report_path)

    print()
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Samples:    {metrics['total_samples']}")
    print(f"  TP: {metrics['tp']}  |  TN: {metrics['tn']}")
    print(f"  FP: {metrics['fp']}  |  FN: {metrics['fn']}")
    print(f"  Precision:  {metrics['precision']:.2%}")
    print(f"  Recall:     {metrics['recall']:.2%}")
    print(f"  F1 Score:   {metrics['f1']:.2%}")
    print(f"  FP Rate:    {metrics['fp_rate']:.2%}")
    print(f"  Total Time: {metrics['total_time_ms']:.0f}ms")
    print()

    return 1 if metrics['fn'] > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
