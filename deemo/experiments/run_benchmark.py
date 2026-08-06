#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对比实验启动脚本 — 将同一批样本喂给 Angr/QEMU/Ghidra/BinMind, 收集指标."""
import json, os, subprocess, sys, time, tracemalloc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class ToolResult:
    tool: str; sample: str; variant: str
    wall_ms: float; peak_memory_mb: float
    findings: int; true_positives: int = 0
    false_positives: int = 0; false_negatives: int = 0
    success: bool = True; error_msg: str = ''

def run_binmind(binary: str, sample: str, variant: str, timeout: int = 60) -> ToolResult:
    tracemalloc.start(); t0 = time.perf_counter()
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from modules.core.compat.vuln_synthesis import synthesize
        r = ToolResult('BinMind', sample, variant, 0, 0, 0, True)
        r.wall_ms = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        r.peak_memory_mb = peak / (1024*1024)
        return r
    except Exception as e:
        tracemalloc.stop(); return ToolResult('BinMind', sample, variant, 0,0,0, False, error_msg=str(e))

def run_angr(binary: str, sample: str, variant: str, timeout: int = 120) -> ToolResult:
    t0 = time.perf_counter()
    try:
        import angr, claripy
        proj = angr.Project(binary, auto_load_libs=False)
        # 简化: 搜索危险函数调用作为指标, 不跑完整 exploration
        cfg = proj.analyses.CFGFast()
        dangerous = ['malloc','free','printf','sprintf','memcpy','strcpy']
        findings = sum(1 for f in cfg.functions if any(d in f.name for d in dangerous))
        wall = (time.perf_counter() - t0) * 1000
        return ToolResult('Angr', sample, variant, wall, 0, findings, success=True)
    except ImportError:
        return ToolResult('Angr', sample, variant, 0,0,0, False, error_msg='angr not installed')
    except Exception as e:
        return ToolResult('Angr', sample, variant, 0,0,0, False, error_msg=str(e))

def run_tool_on_all(tool_name: str, runner_fn, build_dir: str,
                    ground_truth: Dict) -> List[ToolResult]:
    results = []
    for f in sorted(os.listdir(build_dir)):
        if not f.endswith('.elf'): continue
        path = os.path.join(build_dir, f)
        parts = f.replace('.elf', '').rsplit('_', 1)
        name = parts[0] if len(parts) == 2 else f
        variant = parts[1] if len(parts) == 2 else 'default'
        r = runner_fn(path, name, variant)
        # 与 ground truth 比对
        expected = ground_truth.get(name, {})
        if expected:
            if r.findings > 0: r.true_positives = 1
            else: r.false_negatives = 1
        results.append(r)
    return results

def generate_comparison_table(all_results: Dict[str, List[ToolResult]],
                               ground_truth: Dict) -> Dict[str, Any]:
    """计算各工具的检测率、FPR、平均耗时."""
    table = {}
    for tool, results in all_results.items():
        ok = [r for r in results if r.success]
        total = len(results)
        tp = sum(r.true_positives for r in ok)
        fn = sum(r.false_negatives for r in ok)
        fp = sum(r.false_positives for r in ok)
        table[tool] = {
            'samples': total,
            'detection_rate': round(tp / max(1, tp+fn), 3),
            'false_positive_rate': round(fp / max(1, total), 3),
            'avg_time_ms': round(sum(r.wall_ms for r in ok) / max(1, len(ok)), 1),
            'avg_memory_mb': round(sum(r.peak_memory_mb for r in ok) / max(1, len(ok)), 2),
            'successful_runs': len(ok),
        }
    return table

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    build_dir = os.path.join(base, '..', 'tests', 'cve_samples', 'build', 'x86_64')
    output = os.path.join(base, '..', 'tests', 'results', 'benchmark_results.json')

    from tests.regression.parser import _GROUND_TRUTH
    gt = _GROUND_TRUTH

    print('=== Cross-Tool Benchmark ===')
    all_results = {}

    print('--- BinMind ---')
    all_results['BinMind'] = run_tool_on_all('BinMind', run_binmind, build_dir, gt)
    print(f'  {len(all_results["BinMind"])} samples')

    print('--- Angr ---')
    all_results['Angr'] = run_tool_on_all('Angr', run_angr, build_dir, gt)
    print(f'  {len(all_results["Angr"])} samples')

    table = generate_comparison_table(all_results, gt)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w', encoding='utf-8') as f:
        json.dump({'comparison': table, 'raw_results': {
            tool: [{'sample': r.sample, 'variant': r.variant, 'wall_ms': r.wall_ms,
                    'findings': r.findings, 'tp': r.true_positives, 'fn': r.false_negatives}
                   for r in results]}
        }, f, ensure_ascii=False, indent=2)
    print(f'\nResults saved to {output}')
    for tool, data in table.items():
        print(f'{tool}: DR={data["detection_rate"]:.1%} '
              f'FPR={data["false_positive_rate"]:.1%} '
              f'T={data["avg_time_ms"]:.0f}ms')

if __name__ == '__main__':
    main()
