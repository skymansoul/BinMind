#!/usr/bin/env python3
"""调试堆溢出检测器的指令分析过程."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

binary = "modules/vuln/sample_bins/heap_overflow_cve/CVE_02/vuln_CVE_02.exe"
ins, fmt, main, ranges = disassemble_binary(binary)
ins = resolve_call_targets(binary, ins, fmt)

# 找到malloc调用点附近的指令
malloc_addrs = []
for i, instruction in enumerate(ins):
    if instruction["mnemonic"].lower() == "call":
        ops = " ".join(instruction["operands"])
        if "malloc" in ops.lower():
            malloc_addrs.append(i)

print(f"Found {len(malloc_addrs)} malloc calls")
for idx in malloc_addrs:
    print(f"\n--- Around malloc at index {idx} ---")
    start = max(0, idx - 10)
    end = min(len(ins), idx + 10)
    for j in range(start, end):
        i = ins[j]
        marker = " >>>" if j == idx else "    "
        addr = hex(i["address"])
        mnem = i["mnemonic"]
        ops = i["operands"]
        print(f"{marker} {addr} {mnem} {ops}")

# 模拟检测器分析
print("\n\n=== Running detector ===")
detector = HeapOverflowDetector(
    allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(ranges)
detector.pre_analyze(ins)
for instruction in ins:
    detector.analyze_instruction(instruction)
findings = detector.finalize(ins)
print(f"Raw findings: {len(detector.raw_findings)}")
print(f"Filtered findings: {len(findings)}")
print(f"Stats: {detector.stats}")
