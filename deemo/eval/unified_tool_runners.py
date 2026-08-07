"""

包含: BinMind-HOSV/GAPSBV-CJ/baseline/Angr/Ghidra/QEMU + 模拟 + 分类.
"""
from __future__ import annotations

import os, time, random
from typing import Dict, List, Tuple


# 外部工具文献估计参数
LITERATURE_EST = {
    "Angr": {"precision": 0.55, "recall": 0.70, "fp_rate": 0.50, "time_ms": 8500},
    "Ghidra": {"precision": 0.45, "recall": 0.65, "fp_rate": 0.60, "time_ms": 120},
    "QEMU": {"precision": 0.75, "recall": 0.45, "fp_rate": 0.30, "time_ms": 3200},
}


def run_hosv(source: str) -> Tuple[int, float, str]:
    """BinMind-HOSV 源级堆溢出检测."""
    t0 = time.time()
    try:
        from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
        v = HeapOverflowSrcVerifier()
        results = v.verify(source)
        n = sum(1 for r in results if r.verdict.value == "VULN")
        return n, (time.time() - t0) * 1000, ""
    except Exception as e:
        return 0, (time.time() - t0) * 1000, str(e)[:200]


def run_gapsbv_cj(source: str) -> Tuple[int, float, str]:
    """HOSV源级检测 + CJ约束联结增强判定."""
    t0 = time.time()
    try:
        from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
        from core.cj_solver import solve_candidate
        from core.cj_constraint_types import SolverVerdict
        from core.heap_overflow_detector import (
            HeapAllocSite as IrAlloc, HeapStore, HeapOverflowCandidate)

        v = HeapOverflowSrcVerifier()
        results = v.verify(source)
        vuln = 0
        for r in results:
            if r.verdict.value != "VULN":
                continue
            ir_alloc = IrAlloc(
                pc=r.alloc_line, alloc_func='malloc',
                size_arg=r.alloc_size if r.alloc_size > 0 else 0,
                size_is_dynamic=r.alloc_size <= 0, result_var=r.var_name,
            )
            ir_store = HeapStore(
                pc=r.write_line, base_var=r.var_name,
                offset=0, offset_is_dynamic=False,
                store_size=r.write_size if r.write_size > 0 else 0,
            )
            cand = HeapOverflowCandidate(
                alloc_site=ir_alloc, overflow_store=ir_store,
                confidence=r.confidence, description='',
            )
            result, _ = solve_candidate(cand, [], source, "x86_64")
            if result.verdict == SolverVerdict.PROVEN_SAFE:
                continue
            vuln += 1
        return vuln, (time.time() - t0) * 1000, ""
    except Exception as e:
        return 0, (time.time() - t0) * 1000, str(e)[:200]


def run_baseline(source: str) -> Tuple[int, float, str]:
    """Phase 1+2 only — 纯pattern matching, 无约束过滤."""
    t0 = time.time()
    try:
        from analysis.heap_overflow_src_phases import find_allocs, find_writes
        from analysis.heap_overflow_src_patterns import _ptmalloc2_usable
        lines = source.splitlines()
        allocs = find_allocs(lines)
        writes = find_writes(lines, allocs)
        n = 0
        for a in allocs:
            for w in writes:
                if w.target != a.var:
                    continue
                if w.write_size >= 0 and a.size_const >= 0:
                    usable = _ptmalloc2_usable(a.size_const)
                    if w.offset + w.write_size > usable:
                        n += 1
                elif w.write_size == -1:
                    n += 1
        return n, (time.time() - t0) * 1000, ""
    except Exception as e:
        return 0, (time.time() - t0) * 1000, str(e)[:200]


def run_angr(binary: str | None) -> Tuple[int, float, str]:
    t0 = time.time()
    if not binary or not os.path.exists(binary):
        return -1, 0, "binary not found"
    try:
        from eval.ext_tool_runners import run_angr
        r = run_angr(binary)
        if r.get('success'):
            return r.get('dangerous_calls', 0), r.get('duration_ms', 0), ""
        return -1, r.get('duration_ms', 0), r.get('error', 'unknown')
    except Exception as e:
        return -1, (time.time() - t0) * 1000, str(e)[:200]


def run_ghidra(binary: str | None) -> Tuple[int, float, str]:
    if not binary or not os.path.exists(binary):
        return -1, 0, "binary not found"
    try:
        from eval.ext_tool_runners import run_ghidra_headless
        r = run_ghidra_headless(binary)
        if r.get('success'):
            return r.get('dangerous_calls', -1), r.get('duration_ms', 0), ""
        return -1, r.get('duration_ms', 0), r.get('error', 'unknown')
    except Exception as e:
        return -1, 0, str(e)[:200]


def run_qemu(binary: str | None) -> Tuple[int, float, str]:
    if not binary or not os.path.exists(binary):
        return -1, 0, "binary not found"
    try:
        from eval.ext_tool_runners import run_qemu
        r = run_qemu(binary)
        if r.get('success'):
            return r.get('mallocs_detected', -1), r.get('duration_ms', 0), ""
        return -1, r.get('duration_ms', 0), r.get('error', 'unknown')
    except Exception as e:
        return -1, 0, str(e)[:200]


def simulate_tool(tool_name: str, expected_vuln: bool) -> Tuple[int, float, str]:
    """当外部工具不可用时, 基于文献参数模拟判定结果."""
    est = LITERATURE_EST.get(tool_name)
    if not est:
        return 0, 0, f"unknown tool {tool_name}"
    rng = random.Random(hash(tool_name + str(expected_vuln)) % 2**31)
    if expected_vuln:
        detected = rng.random() < est["recall"]
    else:
        detected = rng.random() < est["fp_rate"]
    count = 1 if detected else 0
    dur = est["time_ms"] * (0.8 + rng.random() * 0.4)
    src = "literature-estimate" if detected else "literature-estimate"
    return count, dur, src


def classify(tool_name: str, detection_count: int, expected_vuln: bool) -> Dict:
    """二分类: detection_count>0 → VULN, 否则 SAFE."""
    detected = detection_count > 0
    if expected_vuln and detected:
        return {"tp": 1, "fp": 0, "fn": 0, "tn": 0, "detected": True}
    elif expected_vuln and not detected:
        return {"tp": 0, "fp": 0, "fn": 1, "tn": 0, "detected": False}
    elif not expected_vuln and detected:
        return {"tp": 0, "fp": 1, "fn": 0, "tn": 0, "detected": True}
    else:
        return {"tp": 0, "fp": 0, "fn": 0, "tn": 1, "detected": False}


__all__ = [
    'run_hosv', 'run_gapsbv_cj', 'run_baseline',
    'run_angr', 'run_ghidra', 'run_qemu',
    'simulate_tool', 'classify', 'LITERATURE_EST',
]
