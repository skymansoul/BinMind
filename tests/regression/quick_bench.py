"""
一键基准测试 —— 编译单个样本并运行所有检测器, 输出结构化结果。

用法: python quick_bench.py <sample_dir>
输出: JSON 格式的检测结果, 包含每个检测器的输出和耗时。
"""

import os, sys, json, time

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)


def run_all_detectors(vuln_c_path: str) -> dict:
    """对单个 vuln.c 运行所有可用检测器。"""
    if not os.path.isfile(vuln_c_path):
        return {'error': f'file not found: {vuln_c_path}'}

    with open(vuln_c_path, encoding='utf-8', errors='replace') as f:
        code = f.read()

    results = {'file': vuln_c_path, 'size_bytes': len(code), 'detectors': {}}

    # Heap flow tracker
    t0 = time.perf_counter()
    try:
        from core.heap_flow_tracker import HeapFlowTracker
        tracker = HeapFlowTracker()
        traces = tracker.trace(code)
        results['detectors']['heap_flow'] = {
            'traces': len(traces), 'elapsed_ms': (time.perf_counter()-t0)*1000,
            'details': [{'alloc': t.alloc_func, 'source': t.source_type.value,
                         'constrained': t.is_constrained} for t in traces[:5]],
        }
    except Exception as e:
        results['detectors']['heap_flow'] = {'error': str(e)[:100]}

    # UAF detector
    t0 = time.perf_counter()
    try:
        from core.uaf_detector import UAFDetector
        uaf = UAFDetector()
        findings = uaf.detect(code, os.path.basename(vuln_c_path))
        results['detectors']['uaf'] = {
            'findings': len(findings), 'elapsed_ms': (time.perf_counter()-t0)*1000,
            'details': [{'ptr': f.pointer_name, 'conf': f.confidence} for f in findings[:5]],
        }
    except Exception as e:
        results['detectors']['uaf'] = {'error': str(e)[:100]}

    # INT overflow detector
    t0 = time.perf_counter()
    try:
        from core.int_overflow_detector import IntOverflowDetector
        iod = IntOverflowDetector()
        int_candidates = iod.detect(code, os.path.basename(vuln_c_path))
        results['detectors']['int_overflow'] = {
            'candidates': len(int_candidates), 'elapsed_ms': (time.perf_counter()-t0)*1000,
        }
    except Exception as e:
        results['detectors']['int_overflow'] = {'error': str(e)[:100]}

    # INT range propagator
    t0 = time.perf_counter()
    try:
        from core.int_range_propagator import propagate_ranges
        ranges = propagate_ranges(code)
        results['detectors']['int_range'] = {
            'vars_tracked': len(ranges), 'elapsed_ms': (time.perf_counter()-t0)*1000,
        }
    except Exception as e:
        results['detectors']['int_range'] = {'error': str(e)[:100]}

    results['total_elapsed_ms'] = sum(
        d.get('elapsed_ms', 0) for d in results['detectors'].values()
    )
    return results


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('sample_dir', help='Path to sample directory containing vuln.c')
    ap.add_argument('--json', action='store_true', help='Output JSON only')
    args = ap.parse_args()

    vuln_c = os.path.join(args.sample_dir, 'vuln.c')
    result = run_all_detectors(vuln_c)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"File: {result['file']} ({result['size_bytes']} bytes)")
        for name, det in result['detectors'].items():
            if 'error' in det:
                print(f"  {name}: ERROR - {det['error']}")
            else:
                count = det.get('traces') or det.get('findings') or det.get('candidates') or det.get('vars_tracked') or 0
                elapsed = det.get('elapsed_ms', 0)
                print(f"  {name}: {count} results ({elapsed:.1f}ms)")
        print(f"Total: {result['total_elapsed_ms']:.1f}ms")
