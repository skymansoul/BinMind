"""
UAF 扫描调度模块.

对单样本同时运行 既有 UAF 检测器 (uaf_enhanced) 与 UAF 使用点验证复核通道,
记录逐样本检出数与判定. 既有检测器接口不稳定时降级为安全失败.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))


def _ensure() -> None:
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)


def _run_existing(src: str) -> Dict:
    """既有 UAF 检测器: uaf_enhanced 五阶段管线."""
    _ensure()
    t0 = time.perf_counter()
    try:
        from core.uaf_enhanced import detect_uaf_enhanced
        lines = src.splitlines()
        result = detect_uaf_enhanced(lines)
        candidates = result[0] if isinstance(result, tuple) else result
        kept = [c for c in candidates
                if getattr(c, 'verdict', None) in ('CONFIRMED', 'UNCERTAIN')
                or getattr(c, 'confidence', 0.5) >= 0.30]
        return {'detections': len(kept),
                'elapsed_ms': round((time.perf_counter() - t0) * 1000, 1),
                'verdict': 'OVERFLOW' if kept else 'SAFE', 'success': True}
    except Exception as e:
        return {'detections': 0, 'elapsed_ms': 0, 'verdict': 'ERROR',
                'success': False, 'error': str(e)[:150]}


def _run_uovf(src: str) -> Dict:
    """UAF 使用点验证复核通道."""
    _ensure()
    t0 = time.perf_counter()
    try:
        from core.uaf_use_engine import detect_uaf_uovf
        kept, stats = detect_uaf_uovf(src.splitlines())
        return {'detections': len(kept),
                'elapsed_ms': round((time.perf_counter() - t0) * 1000, 1),
                'verdict': 'OVERFLOW' if kept else 'SAFE', 'success': True,
                'uovf_stats': stats.to_dict()}
    except Exception as e:
        return {'detections': 0, 'elapsed_ms': 0, 'verdict': 'ERROR',
                'success': False, 'error': str(e)[:150]}


def scan_sample(source_path: str) -> Dict:
    with open(source_path, encoding='utf-8', errors='replace') as f:
        src = f.read()
    return {'existing': _run_existing(src), 'uovf': _run_uovf(src)}


def scan_all(samples: List[Dict]) -> List[Dict]:
    results = []
    for s in samples:
        r = scan_sample(s['source'])
        r.update({'name': s['name'], 'cve_id': s.get('cve_id', ''),
                  'is_vuln': s['is_vuln']})
        results.append(r)
    return results
