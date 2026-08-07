#!/usr/bin/env python3
"""CVE_03 safe_copy函数级调试."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary, norm_reg
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_03\vuln_CVE_03.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

# 打印alloc_addr=0x140001777附近的指令
target = 0x140001777
for i, ins in enumerate(instructions):
    addr = ins.get("address", 0)
    if 0x140001750 <= addr <= 0x1400017c0:
        print(f"[{i:4d}] 0x{addr:x} {ins.get('mnemonic','')} {', '.join(ins.get('operands',[]))}")

print("\n--- Analysis with trace ---")

detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)

for i, ins in enumerate(instructions):
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])

    if 0x140001750 <= addr <= 0x1400017c0:
        sym_st = detector._sym_propagator._tracker
        rcx_expr = sym_st.get_expr("rcx")
        rdx_expr = sym_st.get_expr("rdx")
        r8_expr = sym_st.get_expr("r8")
        rax_expr = sym_st.get_expr("rax")
        stack_10 = sym_st.get_stack_expr("rbp+0x10")
        stack_18 = sym_st.get_stack_expr("rbp+0x18")

        print(f"[{i:4d}] 0x{addr:x} {mnem} {', '.join(ops)}")
        print(f"       rax={rax_expr}, rcx={rcx_expr}, rdx={rdx_expr}, r8={r8_expr}")
        print(f"       [rbp+0x10]={stack_10}, [rbp+0x18]={stack_18}")

    detector.analyze_instruction(ins)

findings = detector.finalize(instructions)
print(f"\nRaw findings: {len(detector._raw_findings)}")
for rf in detector._raw_findings:
    # 只看safe_copy相关的
    if 0x140001750 <= rf.get('alloc_addr',0) <= 0x1400017c0:
        print(f"  alloc_addr=0x{rf.get('alloc_addr',0):x}")
        print(f"  write_sym_expr={rf.get('_write_sym_expr')}")
        print(f"  fp_stage={rf.get('fp_stage')}")
        print(f"  fp_filtered={rf.get('fp_filtered')}")
        print(f"  ddssc_detail={rf.get('ddssc_detail')}")

print(f"\nSym snapshots (safe_copy range):")
for addr, snap in detector._sym_snapshots.items():
    if 0x140001750 <= addr <= 0x1400017c0:
        print(f"  0x{addr:x}: {snap}")

print(f"\nFinal findings: {len(findings)}")
