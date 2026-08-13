"""
扫描调度模块 — 调用检测器对每个样本执行堆溢出检测.

用objdump反汇编二进制, 提取指令后调用HeapOverflowDetector,
收集检测结果(检出/漏报/误报)及耗时.

创建: 2025-05-12
"""

import os
import subprocess
import time
from typing import Dict, List, Optional

from sample_compiler import SAMPLE_ROOT

try:
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.heap_overflow_detect import (
        HeapOverflowDetector)
    from modules.analysis.static.heap_alloc_model import AllocatorFamily
    from modules.analysis.static.import_resolver import resolve_call_targets
    _HAS_DETECTOR = True
except ImportError:
    _HAS_DETECTOR = False


def scan_binary(binary_path: str) -> Dict:
    """扫描单个二进制, 返回检测结果.

    返回: {binary, findings, stats, time_ms, error}
    """
    if not _HAS_DETECTOR:
        return {"binary": binary_path, "findings": [], "stats": {},
                "time_ms": 0, "error": "detector not available"}

    if not os.path.isfile(binary_path):
        return {"binary": binary_path, "findings": [], "stats": {},
                "time_ms": 0, "error": "binary not found"}

    try:
        instructions, file_format, main_addr, user_ranges = \
            disassemble_binary(binary_path)
    except Exception as e:
        return {"binary": binary_path, "findings": [], "stats": {},
                "time_ms": 0, "error": f"disasm failed: {e}"}

    if not instructions:
        return {"binary": binary_path, "findings": [], "stats": {},
                "time_ms": 0, "error": "no instructions"}

    # 解析导入函数调用 (PE的IAT / ELF的PLT)
    instructions = resolve_call_targets(
        binary_path, instructions, file_format)

    start = time.perf_counter()
    detector = HeapOverflowDetector(
        allocator=AllocatorFamily.GLIBC,
        use_win64_abi="pei" in file_format.lower())
    detector.set_user_func_ranges(user_ranges)
    detector.pre_analyze(instructions)
    for ins in instructions:
        detector.analyze_instruction(ins)
    findings = detector.finalize(instructions)
    elapsed = (time.perf_counter() - start) * 1000

    return {
        "binary": binary_path,
        "findings": findings,
        "stats": detector.stats,
        "time_ms": round(elapsed, 2),
        "error": "",
    }


def scan_all() -> List[Dict]:
    """扫描所有已编译样本."""
    results = []
    if not os.path.isdir(SAMPLE_ROOT):
        return results

    for entry in sorted(os.listdir(SAMPLE_ROOT)):
        sample_dir = os.path.join(SAMPLE_ROOT, entry)
        if not os.path.isdir(sample_dir):
            continue
        binary_name = f"vuln_{entry}"
        binary_path = os.path.join(sample_dir, binary_name)
        if not os.path.isfile(binary_path):
            binary_path = os.path.join(sample_dir, binary_name + ".exe")
        if not os.path.isfile(binary_path):
            continue
        result = scan_binary(binary_path)
        result["sample_id"] = entry
        results.append(result)

    return results


if __name__ == "__main__":
    results = scan_all()
    print(f"Scanned {len(results)} samples")
    for r in results:
        n = len(r["findings"])
        t = r["time_ms"]
        print(f"  {r['sample_id']}: {n} findings, {t}ms")

__all__ = ["scan_binary", "scan_all"]
