#!/usr/bin/env python3
"""CVE_09 LoopWriteAccumulator 状态检查."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.loop_write_accumulator import LoopWriteAccumulator

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_09\vuln_CVE_09.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)

# 直接测试LoopWriteAccumulator
loop_acc = LoopWriteAccumulator(use_win64_abi=True)
loop_findings = loop_acc.analyze(instructions, detector._alloc_tracker, use_win64_abi=True)
stats = loop_acc.stats
print(f"loops_detected: {stats['loops_detected']}")
print(f"accumulations_tracked: {stats['accumulations_tracked']}")
print(f"overflow_findings: {stats['overflow_findings']}")
for lf in loop_findings:
    print(f"  finding: alloc=0x{lf.get('alloc_addr',0):x}, write=0x{lf.get('write_addr',0):x}")
    print(f"  note: {lf.get('note','')}")
