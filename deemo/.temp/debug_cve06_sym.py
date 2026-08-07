#!/usr/bin/env python3
"""CVE_06 符号表达式调试 — 查看alloc_sym和write_sym的关系."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_06\vuln_CVE_06.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

# 打印所有指令
for i, ins in enumerate(instructions):
    print(f"[{i:3d}] 0x{ins.get('address',0):x} {ins.get('mnemonic','')} {', '.join(ins.get('operands',[]))}")

print("\n--- Analysis ---")
detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)
findings = detector.finalize(instructions)

print(f"Raw findings: {len(detector._raw_findings)}")
for rf in detector._raw_findings:
    print(f"  Raw: {rf}")
print(f"Filtered findings: {len(findings)}")
for f in findings:
    print(f"  Final: {f}")

# 检查符号快照
print(f"\nSym snapshots:")
for addr, snap in detector._sym_snapshots.items():
    print(f"  addr=0x{addr:x}: {snap}")

# 检查符号传播器的状态
print(f"\nSym tracker state:")
st = detector._sym_propagator._tracker
print(f"  alloc_exprs: {dict(st._alloc_syms)}")
print(f"  exprs:")
for k, v in st._exprs.items():
    print(f"    {k} = {v}")
print(f"  stack_exprs:")
for k, v in st._stack_exprs.items():
    print(f"    {k} = {v}")
