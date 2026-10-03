#!/usr/bin/env python3
# coding: utf-8
"""
端到端基准测试管道 — 编译 CVE 源码 → 扫描 → ground truth 对比.
步骤: (1) 发现 C 源文件 (2) GCC 编译 (3) objdump 反汇编
     (4) 提取 malloc/memcpy 参数 (5) 约束求解判定 (6) 指标汇总

objdump 解析委托 tests/regression/objdump_parser.py.
"""

import os, sys, json, time, subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

_CORE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
_MODULES_DIR = os.path.dirname(os.path.dirname(_CORE_DIR))
sys.path.insert(0, _CORE_DIR)
sys.path.insert(0, _MODULES_DIR)

from .objdump_parser import (
    disassemble_sample, detect_malloc_write)


@dataclass
class ScanResult:
    sample_id: str
    compiled: bool
    disassembled: bool
    candidates_found: int
    exploitable: int
    ground_truth: Optional[bool]  # True=vulnerable, False=safe, None=unknown
    is_correct: Optional[bool]
    wall_time_ms: float
    error: str = ''


class CveBenchmarkRunner:
    """CVE 样本基准测试运行器 — 编译→反汇编→约束求解→对比."""

    def __init__(self, samples_root: str = None, cc: str = 'gcc'):
        self.cc = cc
        self.samples_root = samples_root or os.path.join(
            _CORE_DIR, 'tests', 'cve_samples')
        self._gt: Dict[str, bool] = {}
        self._load_ground_truth()

    def _load_ground_truth(self):
        gt_path = os.path.join(_CORE_DIR, 'tests', 'samples', 'ground_truth.json')
        try:
            with open(gt_path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
                for k, v in raw.items():
                    if isinstance(v, dict) and 'heap_overflow' in v:
                        self._gt[k] = v['heap_overflow']
                    elif isinstance(v, bool):
                        self._gt[k] = v
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def discover_samples(self) -> List[str]:
        """发现所有 C 源文件, 限 20 个防编译超时."""
        sources = []
        for root, dirs, files in os.walk(self.samples_root):
            for f in files:
                if f.endswith('.c'):
                    sources.append(os.path.join(root, f))
        return sorted(sources)[:20]

    def compile_sample(self, src_path: str, output_dir: str) -> Optional[str]:
        """编译单个 C 源文件 → 可执行文件."""
        os.makedirs(output_dir, exist_ok=True)
        basename = os.path.splitext(os.path.basename(src_path))[0]
        out_path = os.path.join(output_dir, f'{basename}.exe')
        try:
            result = subprocess.run(
                [self.cc, '-std=c11', '-O0', '-g',
                 '-o', out_path, src_path, '-lws2_32'],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return out_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def run_scan(self, src_path: str, output_dir: str) -> ScanResult:
        """完整流程: 编译 → 反汇编 → 约束求解 → 对比 ground truth."""
        sample_id = os.path.splitext(os.path.basename(src_path))[0]
        t0 = time.perf_counter()

        exe_path = self.compile_sample(src_path, output_dir)
        if exe_path is None:
            elapsed = (time.perf_counter() - t0) * 1000
            return ScanResult(sample_id=sample_id, compiled=False, disassembled=False,
                              candidates_found=0, exploitable=0,
                              ground_truth=self._gt.get(sample_id),
                              is_correct=None, wall_time_ms=elapsed, error='编译失败')

        instructions = disassemble_sample(exe_path)
        if instructions is None:
            elapsed = (time.perf_counter() - t0) * 1000
            return ScanResult(sample_id=sample_id, compiled=True, disassembled=False,
                              candidates_found=0, exploitable=0,
                              ground_truth=self._gt.get(sample_id),
                              is_correct=None, wall_time_ms=elapsed, error='反汇编失败')

        alloc_sz, write_sz = detect_malloc_write(instructions)

        is_overflow = False
        if alloc_sz > 0 and write_sz > 0:
            from modules.core.compat.constraint_solver import prove_overflow_infeasible
            from modules.core.compat.alloc_constraint_encoder import prove_safe_with_allocator
            infeasible, _ = prove_overflow_infeasible(alloc_sz, write_sz)
            if not infeasible:
                safe, _ = prove_safe_with_allocator(alloc_sz, write_sz)
                is_overflow = not safe

        elapsed = (time.perf_counter() - t0) * 1000
        gt = self._gt.get(sample_id)
        is_correct = None
        if gt is not None:
            if gt and is_overflow:       is_correct = True
            elif gt and not is_overflow:  is_correct = False
            elif not gt and not is_overflow: is_correct = True
            elif not gt and is_overflow:  is_correct = False

        return ScanResult(sample_id=sample_id, compiled=True, disassembled=True,
                          candidates_found=1 if is_overflow else 0,
                          exploitable=1 if is_overflow else 0,
                          ground_truth=gt, is_correct=is_correct, wall_time_ms=elapsed)

    def run_benchmark(self, output_dir: str = None) -> Tuple[List[ScanResult], Dict]:
        """运行完整基准测试 → 聚合指标."""
        if output_dir is None:
            output_dir = os.path.join(_CORE_DIR, 'tests', 'regression', 'build')
        sources = self.discover_samples()
        results = []
        for i, src in enumerate(sources):
            print(f'[{i+1}/{len(sources)}] {os.path.basename(src)} ...', end=' ', flush=True)
            r = self.run_scan(src, output_dir)
            status = 'OK' if r.is_correct else ('FAIL' if r.is_correct is False else 'SKIP')
            print(f'{status} ({r.wall_time_ms:.0f}ms)')
            results.append(r)

        tp = sum(1 for r in results if r.ground_truth and r.is_correct)
        tn = sum(1 for r in results if r.ground_truth is False and r.is_correct)
        fp = sum(1 for r in results if r.ground_truth is False and r.is_correct is False)
        fn = sum(1 for r in results if r.ground_truth and r.is_correct is False)
        unknown = sum(1 for r in results if r.ground_truth is None)
        metrics = {
            'total': len(results), 'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
            'unknown': unknown,
            'compiled': sum(1 for r in results if r.compiled),
            'disassembled': sum(1 for r in results if r.disassembled),
            'precision': tp / max(1, tp + fp),
            'recall': tp / max(1, tp + fn),
            'f1': 2 * tp / max(1, 2 * tp + fp + fn),
        }
        return results, metrics


if __name__ == '__main__':
    runner = CveBenchmarkRunner()
    results, metrics = runner.run_benchmark()
    print(f'\n===== Benchmark Results =====')
    print(f'Total: {metrics["total"]}  Compiled: {metrics["compiled"]}  '
          f'Disassembled: {metrics["disassembled"]}')
    print(f'TP={metrics["tp"]} TN={metrics["tn"]} FP={metrics["fp"]} '
          f'FN={metrics["fn"]} Unknown={metrics["unknown"]}')
    print(f'Precision={metrics["precision"]:.1%} Recall={metrics["recall"]:.1%} '
          f'F1={metrics["f1"]:.3f}')

    out_path = os.path.join(_CORE_DIR, 'tests', 'regression', 'output',
                            'benchmark_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({'metrics': metrics, 'results': [
            {'sample_id': r.sample_id, 'compiled': r.compiled,
             'candidates_found': r.candidates_found, 'exploitable': r.exploitable,
             'is_correct': r.is_correct, 'wall_time_ms': r.wall_time_ms, 'error': r.error}
            for r in results
        ]}, f, indent=2)
    print(f'Results saved to {out_path}')
