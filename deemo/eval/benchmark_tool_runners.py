"""
多工具对比实验 — 工具运行器模块.
"""
from __future__ import annotations
import os, sys, time
from typing import Dict

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EVAL_DIR)


def run_binmind_full(source_path: str, binary_path: str) -> Dict:
    """BinMind完整管线: 仿射边界验证-约束求解 + 后向值流 + 路径条件后向值流."""
    t0 = time.perf_counter()
    try:
        sys.path.insert(0, PROJECT_ROOT)
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        with open(source_path, encoding='utf-8', errors='ignore') as f:
            code = f.read()
        ir_lines = code.splitlines()
        candidates, _ = detect_heap_overflows_full(ir_lines, code)
        elapsed = (time.perf_counter() - t0) * 1000
        overflow_count = sum(1 for c in candidates if c.confidence >= 0.25)
        return {
            'tool': 'BinMind-Full', 'detections': overflow_count,
            'elapsed_ms': round(elapsed, 1), 'success': True,
            'verdict': 'OVERFLOW' if overflow_count > 0 else 'SAFE',
        }
    except Exception as e:
        return {'tool': 'BinMind-Full', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:120], 'verdict': 'ERROR'}


def run_binmind_hosv(source_path: str) -> Dict:
    """BinMind 堆写模式验证: 源码级验证器."""
    t0 = time.perf_counter()
    try:
        sys.path.insert(0, PROJECT_ROOT)
        from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
        with open(source_path, encoding='utf-8', errors='ignore') as f:
            code = f.read()
        v = HeapOverflowSrcVerifier()
        results = v.verify(code)
        elapsed = (time.perf_counter() - t0) * 1000
        has_vuln = any(r.verdict.name == 'VULN' for r in results)
        det = sum(1 for r in results if r.verdict.name == 'VULN')
        return {'tool': 'BinMind-HOSV', 'detections': det,
                'elapsed_ms': round(elapsed, 1), 'success': True,
                'verdict': 'OVERFLOW' if has_vuln else 'SAFE'}
    except Exception as e:
        return {'tool': 'BinMind-HOSV', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:120], 'verdict': 'ERROR'}


def run_binmind_baseline(source_path: str) -> Dict:
    """BinMind基线: 仅基础边界检测, 无仿射边界验证/后向值流过滤."""
    t0 = time.perf_counter()
    try:
        sys.path.insert(0, PROJECT_ROOT)
        from core.heap_overflow_detector import detect_heap_overflow
        with open(source_path, encoding='utf-8', errors='ignore') as f:
            code = f.read()
        ir_lines = code.splitlines()
        candidates = detect_heap_overflow(ir_lines, code)
        elapsed = (time.perf_counter() - t0) * 1000
        return {'tool': 'BinMind-Baseline', 'detections': len(candidates),
                'elapsed_ms': round(elapsed, 1), 'success': True,
                'verdict': 'OVERFLOW' if candidates else 'SAFE'}
    except Exception as e:
        return {'tool': 'BinMind-Baseline', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:120], 'verdict': 'ERROR'}


def run_angr_cf(binary_path: str) -> Dict:
    """Angr CFG快速分析 + 危险函数调用检测."""
    t0 = time.perf_counter()
    try:
        sys.path.insert(0, EVAL_DIR)
        from angr_explorer import angr_scan
        result = angr_scan(binary_path)
        elapsed = (time.perf_counter() - t0) * 1000
        if not result.get('success'):
            return {'tool': 'Angr-CFG', 'detections': 0,
                    'elapsed_ms': round(elapsed, 1), 'success': False,
                    'verdict': 'ERROR', 'error': result.get('error', '')[:120]}
        findings = result.get('findings', 0)
        return {'tool': 'Angr-CFG', 'detections': findings,
                'elapsed_ms': round(max(result.get('duration_sec', 0) * 1000, elapsed), 1),
                'success': True, 'verdict': 'OVERFLOW' if findings > 0 else 'SAFE',
                'error': ''}
    except Exception as e:
        return {'tool': 'Angr-CFG', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:120], 'verdict': 'ERROR'}


def run_ghidra(binary_path: str) -> Dict:
    """Ghidra headless分析."""
    t0 = time.perf_counter()
    try:
        sys.path.insert(0, EVAL_DIR)
        from ghidra_headless import analyze
        sample_name = os.path.basename(binary_path)
        result = analyze(binary_path, sample_name)
        sites = result.get('sites', 0)
        err = result.get('error', '')
        return {'tool': 'Ghidra', 'detections': sites,
                'elapsed_ms': round(result.get('duration_s', 0) * 1000, 1),
                'success': not err,
                'verdict': 'OVERFLOW' if sites > 0 else 'SAFE',
                'error': err[:120] if err else ''}
    except Exception as e:
        return {'tool': 'Ghidra', 'detections': 0, 'elapsed_ms': 0,
                'success': False, 'error': str(e)[:120], 'verdict': 'ERROR'}
