"""
UOVF 多工具对比实验 — 工具运行器.

统一封装 UAF 检测通道的单样本扫描:
  Existing  既有 UAF 检测器 (uaf_enhanced)
  UOVF      UAF 值流复核通道 (本创新)
  Angr      angr_explorer 危险调用点探索
  Ghidra    ghidra_headless 无头审计
  QEMU-Tracer 动态追踪

外部工具缺失时优雅降级, 不中断批量实验.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Dict, List

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EVAL_DIR)


def _ensure() -> None:
    for p in (PROJECT_ROOT, EVAL_DIR):
        if p not in sys.path:
            sys.path.insert(0, p)


def run_existing(source_path: str) -> Dict:
    _ensure()
    t0 = time.perf_counter()
    try:
        from core.uaf_enhanced import detect_uaf_enhanced
        with open(source_path, encoding='utf-8', errors='replace') as f:
            src = f.read()
        result = detect_uaf_enhanced(src.splitlines())
        candidates = result[0] if isinstance(result, tuple) else result
        kept = [c for c in candidates
                if getattr(c, 'verdict', None) in ('CONFIRMED', 'UNCERTAIN')
                or getattr(c, 'confidence', 0.5) >= 0.30]
        return {'tool': 'UAF-Existing', 'detections': len(kept),
                'elapsed_ms': round((time.perf_counter() - t0) * 1000, 1),
                'success': True,
                'verdict': 'OVERFLOW' if kept else 'SAFE'}
    except Exception as e:
        return {'tool': 'UAF-Existing', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:150], 'verdict': 'ERROR'}


def run_uovf(source_path: str) -> Dict:
    _ensure()
    t0 = time.perf_counter()
    try:
        from core.uovf_engine import detect_uaf_uovf
        with open(source_path, encoding='utf-8', errors='replace') as f:
            src = f.read()
        kept, stats = detect_uaf_uovf(src.splitlines())
        return {'tool': 'UOVF', 'detections': len(kept),
                'elapsed_ms': round((time.perf_counter() - t0) * 1000, 1),
                'success': True, 'verdict': 'OVERFLOW' if kept else 'SAFE',
                'uovf_stats': stats.to_dict()}
    except Exception as e:
        return {'tool': 'UOVF', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:150], 'verdict': 'ERROR'}


def run_angr(binary_path: str) -> Dict:
    _ensure()
    t0 = time.perf_counter()
    try:
        import logging
        logging.getLogger('angr').setLevel(logging.ERROR)
        from angr_explorer import angr_scan
        r = angr_scan(binary_path)
        if not r.get('success'):
            return {'tool': 'Angr', 'detections': 0, 'elapsed_ms': 0,
                    'success': False, 'error': r.get('error', '')[:150],
                    'verdict': 'ERROR'}
        return {'tool': 'Angr', 'detections': r.get('findings', 0),
                'elapsed_ms': round(r.get('duration_sec', 0) * 1000, 1),
                'success': True, 'verdict': 'OVERFLOW' if r.get('findings')
                else 'SAFE'}
    except Exception as e:
        return {'tool': 'Angr', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:150], 'verdict': 'ERROR'}


def run_ghidra(binary_path: str) -> Dict:
    _ensure()
    try:
        from ghidra_headless import analyze_auto
        r = analyze_auto(binary_path, os.path.basename(binary_path))
        if r.get('error'):
            return {'tool': 'Ghidra', 'detections': 0, 'elapsed_ms': 0,
                    'success': False, 'error': r['error'][:150],
                    'verdict': 'ERROR'}
        return {'tool': 'Ghidra', 'detections': r.get('sites', 0),
                'elapsed_ms': round(r.get('duration_s', 0) * 1000, 1),
                'success': True, 'verdict': 'OVERFLOW' if r.get('sites')
                else 'SAFE'}
    except Exception as e:
        return {'tool': 'Ghidra', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:150], 'verdict': 'ERROR'}


def run_qemu(binary_path: str) -> Dict:
    _ensure()
    try:
        from qemu_tracer import trace_auto
        r = trace_auto(binary_path, os.path.basename(binary_path))
        calls = r.get('calls', 0) or r.get('allocs', 0)
        return {'tool': 'QEMU-Tracer', 'detections': calls,
                'elapsed_ms': round(r.get('duration_s', 0) * 1000, 1),
                'success': not r.get('error'),
                'error': r.get('error', '')[:150],
                'verdict': 'OVERFLOW' if calls else 'SAFE'}
    except Exception as e:
        return {'tool': 'QEMU-Tracer', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:150], 'verdict': 'ERROR'}


def run_all(source_path: str, binary_path: str) -> List[Dict]:
    results = [run_existing(source_path), run_uovf(source_path)]
    if binary_path and os.path.isfile(binary_path):
        results.append(run_angr(binary_path))
        results.append(run_ghidra(binary_path))
        results.append(run_qemu(binary_path))
    else:
        for tool in ('Angr', 'Ghidra', 'QEMU-Tracer'):
            results.append({'tool': tool, 'detections': 0, 'elapsed_ms': 0,
                            'success': False, 'error': 'binary missing',
                            'verdict': 'ERROR'})
    return results
