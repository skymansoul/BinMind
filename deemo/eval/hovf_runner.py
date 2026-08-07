"""
HOVF 多工具对比实验 — 工具运行器.

统一封装五条检测通道的单样本扫描:
  BinMind-Baseline  既有管线 (不含 HOVF 阶段)
  BinMind-HOVF      既有管线 + HOVF 追加通道与宽松核验
  Angr              angr_explorer 符号执行探索
  Ghidra            ghidra_headless 无头脚本
  QEMU-Tracer       qemu_tracer 动态追踪 + LD_PRELOAD hook

外部工具缺失时优雅降级 (success=False, error 记录原因), 不中断
整批实验. 峰值内存用 psutil 采样, 不可用时记 0.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Dict, List

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EVAL_DIR)


def _ensure_paths() -> None:
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    if EVAL_DIR not in sys.path:
        sys.path.insert(0, EVAL_DIR)


def _peak_mem_mb() -> float:
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / 1048576.0, 1)
    except Exception:
        return 0.0


def run_binmind(source_path: str, enable_hovf: bool) -> Dict:
    """运行 BinMind 管线 (enable_hovf 控制 HOVF 阶段)."""
    _ensure_paths()
    t0 = time.perf_counter()
    try:
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        with open(source_path, encoding='utf-8', errors='replace') as f:
            code = f.read()
        candidates, _stats = detect_heap_overflows_full(
            code.splitlines(), code, enable_hovf=enable_hovf)
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            'tool': 'BinMind-HOVF' if enable_hovf else 'BinMind-Baseline',
            'detections': len(candidates),
            'elapsed_ms': round(elapsed, 1),
            'success': True,
            'verdict': 'OVERFLOW' if candidates else 'SAFE',
            'peak_mb': _peak_mem_mb(),
        }
    except Exception as e:
        return {'tool': 'BinMind-HOVF' if enable_hovf else 'BinMind-Baseline',
                'detections': 0, 'elapsed_ms': 0, 'success': False,
                'error': str(e)[:160], 'verdict': 'ERROR', 'peak_mb': 0.0}


def run_angr(binary_path: str) -> Dict:
    """Angr 符号执行探索危险函数调用点."""
    _ensure_paths()
    t0 = time.perf_counter()
    try:
        import logging
        logging.getLogger('angr').setLevel(logging.ERROR)
        from angr_explorer import angr_scan
        r = angr_scan(binary_path)
        if not r.get('success'):
            return {'tool': 'Angr', 'detections': 0, 'elapsed_ms': 0,
                    'success': False, 'error': r.get('error', '')[:160],
                    'verdict': 'ERROR', 'peak_mb': 0.0}
        return {'tool': 'Angr', 'detections': r.get('findings', 0),
                'elapsed_ms': round(r.get('duration_sec', 0) * 1000, 1),
                'success': True, 'error': '',
                'verdict': 'OVERFLOW' if r.get('findings') else 'SAFE',
                'peak_mb': 0.0}
    except Exception as e:
        return {'tool': 'Angr', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:160], 'verdict': 'ERROR',
                'peak_mb': 0.0}


def run_ghidra(binary_path: str) -> Dict:
    """Ghidra 无头脚本模拟自动化静态审计."""
    _ensure_paths()
    t0 = time.perf_counter()
    try:
        from ghidra_headless import analyze_auto
        r = analyze_auto(binary_path, os.path.basename(binary_path))
        if r.get('error'):
            return {'tool': 'Ghidra', 'detections': 0, 'elapsed_ms': 0,
                    'success': False, 'error': r['error'][:160],
                    'verdict': 'ERROR', 'peak_mb': 0.0}
        return {'tool': 'Ghidra', 'detections': r.get('sites', 0),
                'elapsed_ms': round(r.get('duration_s', 0) * 1000, 1),
                'success': True, 'error': '',
                'verdict': 'OVERFLOW' if r.get('sites') else 'SAFE',
                'peak_mb': 0.0}
    except Exception as e:
        return {'tool': 'Ghidra', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:160], 'verdict': 'ERROR',
                'peak_mb': 0.0}


def run_qemu(binary_path: str) -> Dict:
    """QEMU user-mode 动态追踪 (alloc/free 事件作为 ground truth 线索)."""
    _ensure_paths()
    t0 = time.perf_counter()
    try:
        from qemu_tracer import trace_auto
        r = trace_auto(binary_path, os.path.basename(binary_path))
        calls = r.get('calls', 0) or r.get('allocs', 0)
        return {'tool': 'QEMU-Tracer', 'detections': calls,
                'elapsed_ms': round(r.get('duration_s', 0) * 1000, 1),
                'success': not r.get('error'),
                'error': r.get('error', '')[:160],
                'verdict': 'OVERFLOW' if calls else 'SAFE', 'peak_mb': 0.0}
    except Exception as e:
        return {'tool': 'QEMU-Tracer', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:160], 'verdict': 'ERROR',
                'peak_mb': 0.0}


def run_all(source_path: str, binary_path: str) -> List[Dict]:
    """单样本运行全部工具, 返回结果列表."""
    results = [run_binmind(source_path, False),
               run_binmind(source_path, True)]
    if binary_path and os.path.isfile(binary_path):
        results.append(run_angr(binary_path))
        results.append(run_ghidra(binary_path))
        results.append(run_qemu(binary_path))
    else:
        for tool in ('Angr', 'Ghidra', 'QEMU-Tracer'):
            results.append({'tool': tool, 'detections': 0, 'elapsed_ms': 0,
                            'success': False, 'error': 'binary missing',
                            'verdict': 'ERROR', 'peak_mb': 0.0})
    return results
