#!/usr/bin/env python3
"""CVE_09 调试 — 查看loop_overflow的反汇编和检测状态."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_09\vuln_CVE_09.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

# 找malloc和loop_overflow函数
for i, ins in enumerate(instructions):
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    addr = ins.get("address", 0)
    if 0x140001750 <= addr <= 0x140001800:
        print(f"[{i:4d}] 0x{addr:x} {mnem} {', '.join(ops)}")

print("\n--- Full analysis ---")
detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)
findings = detector.finalize(instructions)

print(f"Raw findings: {len(detector._raw_findings)}")
for rf in detector._raw_findings:
    print(f"  alloc_addr=0x{rf.get('alloc_addr',0):x}")
    print(f"  write_addr=0x{rf.get('write_addr',0):x}")
    print(f"  alloc_size_range={rf.get('alloc_size_range')}")
    print(f"  write_size_range={rf.get('write_size_range')}")

print(f"\nFinal findings: {len(findings)}")
print(f"\nStats: {detector.stats}")
