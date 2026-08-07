#!/usr/bin/env python3
# coding: utf-8
"""
扫描调度模块 — 对编译好的 ELF 调用检测管线并收集原始结果.
支持两种模式:
  1. 基础模式: 仅使用 L0-L3 (值区间+污点+分配器约束)
  2. 深度模式: 启用全部六层过滤 (L0-L5)
"""

import os, json, time, sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ScanResult:
    sample_id: str
    elf_path: str
    success: bool = False
    candidates: List[Dict] = field(default_factory=list)
    wall_time_ms: float = 0.0
    error: str = ''
    # 各层统计
    layer_stats: List[Dict] = field(default_factory=list)


def scan_elf_minimal(elf_path: str) -> ScanResult:
    """最小化扫描 — 只依赖二进制固有特征."""
    sample_id = os.path.basename(elf_path).replace('.elf', '')
    result = ScanResult(sample_id=sample_id, elf_path=elf_path)
    try:
        from modules.core.compat.scan_pipeline import run_pipeline_minimal
        t0 = time.perf_counter()
        pipe_result = run_pipeline_minimal(elf_path)
        result.wall_time_ms = (time.perf_counter() - t0) * 1000
        result.candidates = [
            {'overflow_site': v.primary_addr,
             'vuln_type': v.vuln_type,
             'confidence': v.confidence,
             'exploitable': v.exploitable,
             'description': v.description}
            for v in pipe_result.findings.vulns
        ]
        result.success = True
    except Exception as e:
        result.success = False
        result.error = str(e)
    return result


def scan_elf_deep(elf_path: str,
                  instructions: Optional[List[Dict]] = None,
                  ir_ops: Optional[Dict[int, Dict]] = None,
                  callee_names: Optional[Dict[int, str]] = None,
                  def_use_chains: Optional[Dict[int, List[int]]] = None,
                  ) -> ScanResult:
    """深度扫描 — 多层过滤管线 (未提供 IR 时自动用二进制前端提取)."""
    sample_id = os.path.basename(elf_path).replace('.elf', '').replace('.exe', '')
    result = ScanResult(sample_id=sample_id, elf_path=elf_path)
    try:
        from modules.core.compat.deep_heap_orchestrator import (
            DeepHeapOrchestrator, DeepHeapReport)
        t0 = time.perf_counter()
        orch = DeepHeapOrchestrator(
            enable_l4=True, enable_l5=True, enable_interproc=True)
        report = orch.run(
            elf_path,
            instructions=instructions,
            ir_ops=ir_ops,
            callee_names=callee_names,
            def_use_chains=def_use_chains,
        )
        result.wall_time_ms = (time.perf_counter() - t0) * 1000
        result.candidates = report.candidates
        result.layer_stats = [
            {'name': s.name, 'input': s.input_count,
             'filtered': s.filtered, 'retained': s.retained,
             'duration_ms': s.duration_ms}
            for s in report.layer_stats
        ]
        result.success = True
    except Exception as e:
        result.success = False
        result.error = str(e)
    return result


def scan_all(elf_paths: List[str],
             mode: str = 'minimal',
             **kwargs) -> List[ScanResult]:
    """批量扫描所有 ELF."""
    results = []
    for i, path in enumerate(elf_paths):
        print(f'[{i+1}/{len(elf_paths)}] scanning {os.path.basename(path)} ...',
              end=' ', flush=True)
        if mode == 'deep':
            r = scan_elf_deep(path, **kwargs)
        else:
            r = scan_elf_minimal(path)
        status = f'OK ({len(r.candidates)} candidates, {r.wall_time_ms:.0f}ms)' if r.success else f'FAIL: {r.error}'
        print(status)
        results.append(r)
    return results


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('elf_paths', nargs='+', help='ELF files to scan')
    ap.add_argument('--mode', default='minimal', choices=['minimal', 'deep'])
    ap.add_argument('--output', help='JSON output path')
    args = ap.parse_args()

    results = scan_all(args.elf_paths, mode=args.mode)
    output = {
        'mode': args.mode,
        'total': len(results),
        'results': [
            {
                'sample_id': r.sample_id,
                'success': r.success,
                'candidates': len(r.candidates),
                'exploitable': sum(1 for c in r.candidates if c.get('exploitable')),
                'wall_time_ms': r.wall_time_ms,
                'error': r.error,
            }
            for r in results
        ],
    }
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2, default=str)
    else:
        print(json.dumps(output, indent=2, default=str))
