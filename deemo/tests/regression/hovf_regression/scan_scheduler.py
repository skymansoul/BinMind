"""
扫描调度模块.

对全部堆溢出样本依次执行基线管线与 HOVF 管线, 记录逐样本
检出数/耗时/判定. 判定阈值按置信度 0.40, 与管线输出语义一致.
逐样本并行调度由外层 run_regression 控制, 本模块仅负责单样本扫描.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))


def _ensure_imports() -> None:
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)


def _run_pipeline(src_text: str, enable_hovf: bool) -> Dict:
    _ensure_imports()
    from core.heap_overflow_pipeline import detect_heap_overflows_full
    t0 = time.perf_counter()
    try:
        candidates, stats = detect_heap_overflows_full(
            src_text.splitlines(), src_text, enable_hovf=enable_hovf)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        detections = len(candidates)
        verdict = 'OVERFLOW' if detections > 0 else 'SAFE'
        hovf = stats.get('hovf_stats')
        return {
            'detections': detections,
            'elapsed_ms': round(elapsed_ms, 1),
            'verdict': verdict,
            'success': True,
            'hovf_stats': hovf.to_dict() if hovf else None,
        }
    except Exception as e:
        return {'detections': 0, 'elapsed_ms': 0, 'verdict': 'ERROR',
                'success': False, 'error': str(e)[:200]}


def scan_sample(source_path: str) -> Dict:
    """对单样本同时运行基线与 HOVF 两档, 返回合并结果."""
    with open(source_path, encoding='utf-8', errors='replace') as f:
        src = f.read()
    base = _run_pipeline(src, enable_hovf=False)
    full = _run_pipeline(src, enable_hovf=True)
    return {
        'baseline': base,
        'hovf': full,
    }


def scan_all(samples: List[Dict]) -> List[Dict]:
    """批量扫描全部样本, 并入 ground truth 标签."""
    results = []
    for s in samples:
        r = scan_sample(s['source'])
        r.update({
            'name': s['name'],
            'cve_id': s.get('cve_id', ''),
            'is_vuln': s['is_vuln'],
        })
        results.append(r)
    return results
