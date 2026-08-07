"""统一工具执行器 — 把各工具输出规范为统一结果字典。

每个 runner 返回: {tool, detected, detections, elapsed_ms, success,
error, detail}。run_all 对单样本执行全部可用工具,
二进制工具按顺序降级(skip 不抛错)。
"""

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from heapov import analyze_source, analyze_baseline  # noqa: E402

EXTERNAL_OK = {}


def _check_external() -> None:
    global EXTERNAL_OK
    try:
        import angr  # noqa: F401
        EXTERNAL_OK['angr'] = True
    except ImportError:
        EXTERNAL_OK['angr'] = False
    EXTERNAL_OK['ghidra'] = bool(os.environ.get('GHIDRA_HOME', ''))
    from shutil import which
    EXTERNAL_OK['qemu'] = which('qemu-x86_64') is not None


_check_external()


def _mk(tool, sample, detected, detections, ms, success, error='', detail=None):
    return {'tool': tool, 'sample': sample, 'detected': bool(detected),
            'detections': detections, 'elapsed_ms': round(ms, 3),
            'success': success, 'error': error, 'detail': detail or {}}


def run_cacbv(sample: dict) -> dict:
    t0 = time.perf_counter()
    src = Path(sample['src']).read_text(encoding='utf-8', errors='replace')
    findings = analyze_source(src)[0]
    ms = (time.perf_counter() - t0) * 1000
    return _mk('CACBV', sample['name'], bool(findings), len(findings),
               ms, True, detail={
                   'verdicts': sorted({f['verdict'] for f in findings}),
                   'reasons': sorted({r for f in findings for r in f['fp_reasons']}),
               })


def run_baseline(sample: dict) -> dict:
    t0 = time.perf_counter()
    src = Path(sample['src']).read_text(encoding='utf-8', errors='replace')
    findings = analyze_baseline(src)
    ms = (time.perf_counter() - t0) * 1000
    return _mk('Baseline', sample['name'], bool(findings), len(findings),
               ms, True, detail={'verdicts': sorted({f['verdict'] for f in findings})})


def run_angr(sample: dict) -> dict:
    if not EXTERNAL_OK['angr']:
        return _mk('Angr', sample['name'], False, 0, 0, False,
                   'angr not installed')
    from angr_explorer import angr_explore
    r = angr_explore(sample['binary'])
    return _mk('Angr', sample['name'], r['reached_sites'] > 0,
               r['reached_sites'], r['duration_sec'] * 1000, r['success'],
               r.get('error', ''))


def run_ghidra(sample: dict) -> dict:
    if not EXTERNAL_OK['ghidra']:
        return _mk('Ghidra', sample['name'], False, 0, 0, False,
                   'GHIDRA_HOME not set')
    from ghidra_headless import ghidra_audit
    r = ghidra_audit(sample['binary'])
    return _mk('Ghidra', sample['name'], r['writes'] > 0, r['writes'],
               r['duration_sec'] * 1000, r['success'], r.get('error', ''))


def run_qemu_gt(sample: dict) -> dict:
    if not EXTERNAL_OK['qemu']:
        return _mk('QEMU-GT', sample['name'], False, 0, 0, False,
                   'qemu-x86_64 not found')
    from qemu_tracer import trace_gt
    r = trace_gt(sample['binary'])
    return _mk('QEMU-GT', sample['name'], r['overflow_events'] > 0,
               r['overflow_events'], r['duration_sec'] * 1000, r['success'],
               r.get('error', ''))


_SOURCE_TOOLS = [run_cacbv, run_baseline]
_BINARY_TOOLS = [run_angr, run_ghidra, run_qemu_gt]


def run_all(sample: dict) -> list:
    results = []
    for fn in _SOURCE_TOOLS:
        results.append(fn(sample))
    for fn in _BINARY_TOOLS:
        results.append(fn(sample))
    return results
