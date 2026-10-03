# 扫描调度模块 - 单样本扫描执行器.
# 对单个二进制执行反汇编 + 调用目标解析 + 堆溢出检测(finalize),
# 支持 有界写恢复 (Bounded Write Recovery)/路径条件敏感污点 (Path-Condition Sensitive Taint) 开/关的消融, 返回结构化结果与统计.

import sys
import time
from pathlib import Path

_BINMIND = Path(r"C:\Users\Administrator\Desktop\BinMind")
for p in (str(_BINMIND), str(_BINMIND / "deemo")):
    if p not in sys.path:
        sys.path.insert(0, p)


def scan_sample(binary_path, enable_bwr: bool = True,
                enable_pcst: bool = True,
                allocator_family=None) -> dict:
    """扫描单个二进制, 返回 {findings, counts, time_ms, stats}.

    enable_bwr=False 且 enable_pcst=False 时等效基线(旧参数索引+跳过无界写).
    """
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.heap_overflow_detect import (
        HeapOverflowDetector)
    from modules.analysis.static.heap_alloc_model import AllocatorFamily
    from modules.analysis.static.import_resolver import resolve_call_targets

    t0 = time.perf_counter()
    instructions, fmt, main, ranges = disassemble_binary(binary_path)
    instructions = resolve_call_targets(binary_path, instructions, fmt)
    family = allocator_family or AllocatorFamily.GLIBC
    detector = HeapOverflowDetector(allocator=family, use_win64_abi=True,
                                    enable_bwr=enable_bwr,
                                    enable_pcst=enable_pcst)
    if enable_bwr:
        from modules.analysis.static.rodata_extract import extract_rodata_bytes
        detector.set_rodata_bytes(extract_rodata_bytes(binary_path))
    detector.set_user_func_ranges(ranges)
    detector.pre_analyze(instructions)
    for ins in instructions:
        detector.analyze_instruction(ins)
    findings = detector.finalize(instructions)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    stats = detector.stats
    return {
        "findings": [dict(f) for f in findings],
        "count": len(findings),
        "time_ms": round(elapsed_ms, 2),
        "raw_count": len(detector.raw_findings),
        "bwr": stats.get("bwr", {}),
        "detection_methods": sorted({f.get("detection_method", "call")
                                     for f in findings}),
    }


def scan_dir(sample_dir, enable_bwr: bool = True,
             enable_pcst: bool = True) -> dict:
    """扫描样本目录(取首个 vuln.exe), 返回 {sample, result}."""
    d = Path(sample_dir)
    exe = d / "vuln.exe"
    if not exe.exists():
        return {"sample": d.name, "error": "no vuln.exe"}
    return {"sample": d.name, "result": scan_sample(str(exe), enable_bwr,
                                                     enable_pcst)}


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else ""
    if not p:
        print("usage: scan_dispatch.py <binary_or_sample_dir>")
        sys.exit(1)
    import os
    if os.path.isdir(p):
        print(scan_dir(p))
    else:
        r = scan_sample(p)
        print({k: v for k, v in r.items() if k != "findings"})
        for f in r["findings"]:
            print("  ", f.get("type"), f.get("write_size"),
                  (f.get("note") or "")[:70])
