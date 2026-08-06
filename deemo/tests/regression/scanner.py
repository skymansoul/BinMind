# -*- coding: utf-8 -*-
"""扫描调度模块 — 调用 scan_pipeline 执行真实检测, 收集指标."""
import json, os, sys, time, tracemalloc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class ScanResult:
    sample_name: str; binary_path: str; variant: str
    success: bool; wall_ms: float = 0.0
    peak_memory_mb: float = 0.0
    findings: Dict[str, Any] = field(default_factory=dict)
    error_msg: str = ''

def scan_binary(binary_path: str, sample_name: str, variant: str = 'default') -> ScanResult:
    tracemalloc.start(); t0 = time.perf_counter()
    result = ScanResult(sample_name, binary_path, variant, False)
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
        from modules.core.compat.scan_pipeline import run_pipeline_minimal
        pr = run_pipeline_minimal(binary_path)
        result.success = True
        result.findings = pr.to_dict()
    except ImportError as e:
        result.error_msg = f'模块加载失败: {e}'
    except Exception as e:
        result.error_msg = f'{type(e).__name__}: {e}'
    result.wall_ms = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    result.peak_memory_mb = peak / (1024 * 1024)
    return result

def scan_all_binaries(build_dir: str) -> List[ScanResult]:
    results = []
    for f in sorted(os.listdir(build_dir)):
        if not f.endswith('.elf'): continue
        path = os.path.join(build_dir, f)
        parts = f.replace('.elf', '').rsplit('_', 1)
        name = parts[0] if len(parts) == 2 else f
        variant = parts[1] if len(parts) == 2 else 'default'
        results.append(scan_binary(path, name, variant))
    return results

def scan_summary(results: List[ScanResult]) -> dict:
    ok = [r for r in results if r.success]
    return {
        'total_binaries': len(results), 'successful_scans': len(ok),
        'avg_wall_ms': round(sum(r.wall_ms for r in ok)/max(1,len(ok)), 1),
        'avg_memory_mb': round(sum(r.peak_memory_mb for r in ok)/max(1,len(ok)), 2),
    }
