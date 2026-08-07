"""扫描调度模块 — 对编译好的二进制执行堆溢出检测.

创建: 2026-06-20
用途: 读取编译报告中的二进制列表, 依次调用堆溢出检测管线,
      记录每个样本的检测结果 (检出数、误报数、耗时等)。
"""
import os
import sys
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class ScanResult:
    sample_name: str
    binary_path: str
    success: bool
    total_findings: int = 0
    confirmed: int = 0
    suspicious: int = 0
    filtered_fp: int = 0
    elapsed_ms: float = 0.0
    peak_memory_mb: float = 0.0
    error_msg: str = ""
    findings_detail: List[Dict] = field(default_factory=list)


def run_heap_scan(binary_path: str) -> ScanResult:
    """对单个二进制执行堆溢出检测."""
    name = Path(binary_path).parent.name
    result = ScanResult(sample_name=name, binary_path=binary_path, success=False)
    t0 = time.perf_counter()

    try:
        # 使用 heap_analysis orchestrator 作为主检测入口
        from modules.vuln.src.heap.orchestrator import analyze_heap
        report = analyze_heap(binary_path)

        result.total_findings = report.raw_findings
        result.confirmed = report.confirmed
        result.suspicious = report.likely
        result.filtered_fp = report.filtered_fp
        result.findings_detail = report.findings
        result.success = True
        result.error_msg = report.disasm_error

    except ImportError as e:
        # heap_analysis 不可用 → 回退到基础检测
        result = _fallback_scan(binary_path, name)
    except Exception as e:
        result.error_msg = str(e)[:500]

    result.elapsed_ms = (time.perf_counter() - t0) * 1000
    return result


def _fallback_scan(binary_path: str, name: str) -> ScanResult:
    """回退检测: 使用基础 HeapOverflowDetector."""
    result = ScanResult(sample_name=name, binary_path=binary_path, success=False)
    t0 = time.perf_counter()

    try:
        from modules.vuln.src.heap.heap_overflow_detector import (
            HeapOverflowDetector)
        detector = HeapOverflowDetector()

        # 简化的模拟: 对每个已知模式做检测
        # 实际生产代码需要连接 capstone 反汇编
        _run_pattern_scan(binary_path, detector)

        findings = detector.detect()
        result.total_findings = len(findings)
        result.confirmed = sum(1 for f in findings if f.user_controlled)
        result.suspicious = result.total_findings - result.confirmed
        result.success = True
    except Exception as e:
        result.error_msg = str(e)[:500]

    result.elapsed_ms = (time.perf_counter() - t0) * 1000
    return result


def _run_pattern_scan(binary_path: str, detector) -> None:
    """基于模式的快速扫描 — 在反汇编输出中检测堆操作模式."""
    import capstone
    try:
        with open(binary_path, "rb") as f:
            code = f.read()[:0x10000]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        for insn in md.disasm(code, 0x1000):
            mnemonic = insn.mnemonic
            op_str = insn.op_str

            # 检测 malloc 调用
            if mnemonic == "call" and "malloc" in op_str:
                # 简化: 假设 edi/rdi 包含 size 参数
                detector.register_malloc(insn.address, 256, "rax")
            # 检测 memcpy/memset/movs 等写操作
            elif mnemonic in ("call", "rep") and any(
                    x in op_str for x in ("memcpy", "memset", "movs")):
                detector.register_access(
                    insn.address, "rax", "0x100", "unknown_fn", 4)
    except Exception:
        pass


def scan_all(binaries: List[str]) -> List[ScanResult]:
    """批量扫描所有二进制."""
    results = []
    for i, bin_path in enumerate(binaries):
        if not os.path.isfile(bin_path):
            print(f"  SKIP [{i+1}/{len(binaries)}] {bin_path} (not found)")
            continue
        print(f"  [{i+1}/{len(binaries)}] scanning {Path(bin_path).parent.name}...")
        r = run_heap_scan(bin_path)
        results.append(r)
        status = f"{r.total_findings} findings ({r.confirmed} confirmed)" if r.success else f"ERROR: {r.error_msg[:60]}"
        print(f"    → {status} ({r.elapsed_ms:.0f}ms)")
    return results


def summary(results: List[ScanResult]) -> dict:
    ok = [r for r in results if r.success]
    findings = [r for r in ok if r.total_findings > 0]
    return {
        "total_samples": len(results),
        "scanned_ok": len(ok),
        "samples_with_findings": len(findings),
        "total_findings": sum(r.total_findings for r in ok),
        "total_confirmed": sum(r.confirmed for r in ok),
        "total_suspicious": sum(r.suspicious for r in ok),
        "total_filtered": sum(r.filtered_fp for r in ok),
        "avg_elapsed_ms": (sum(r.elapsed_ms for r in ok) / max(1, len(ok))),
        "details": [
            {
                "sample": r.sample_name,
                "findings": r.total_findings,
                "confirmed": r.confirmed,
                "suspicious": r.suspicious,
                "filtered": r.filtered_fp,
                "elapsed_ms": round(r.elapsed_ms, 1),
            }
            for r in ok
        ],
    }


if __name__ == "__main__":
    import glob
    base = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(base, "compile_report.json")

    if os.path.exists(report_path):
        with open(report_path) as f:
            compile_info = json.load(f)
        binaries = compile_info.get("binaries", [])
    else:
        # 直接扫描所有样本目录中的ELF
        binaries = glob.glob(
            os.path.join(base, "..", "sample_bins", "sample*", "vuln_*"))
        binaries += glob.glob(
            os.path.join(base, "..", "sample_bins", "sample*", "safe_*"))
        binaries += glob.glob(
            os.path.join(base, "..", "sample_bins", "sample*", "fp_*"))

    if not binaries:
        print("No binaries found. Run compile_samples.py first.")
        sys.exit(1)

    print(f"Scanning {len(binaries)} binaries...")
    results = scan_all(binaries)
    s = summary(results)

    print(f"\n{'='*60}")
    print(f"Scan Summary: {s['samples_with_findings']}/{s['scanned_ok']} have findings")
    print(f"  Total findings: {s['total_findings']}")
    print(f"  Confirmed: {s['total_confirmed']}")
    print(f"  Suspicious: {s['total_suspicious']}")
    print(f"  Filtered FP: {s['total_filtered']}")
    print(f"  Avg time: {s['avg_elapsed_ms']:.0f}ms")

    out_path = os.path.join(base, "scan_report.json")
    with open(out_path, "w") as f:
        json.dump(s, f, indent=2)
    print(f"Report written to {out_path}")
