#!/usr/bin/env python3
"""CVE_06 指令级调试 — 在calloc和memset调用点打印状态."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary, norm_reg
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.sym_size_correlator import SymExpr

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_06\vuln_CVE_06.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

# 跟踪alloc_array地址范围 (0x140001760 to 0x1400017c0)
ALLOC_ARRAY_START = 0x140001760
ALLOC_ARRAY_END = 0x1400017c0

detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)

for i, ins in enumerate(instructions):
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])

    if ALLOC_ARRAY_START <= addr <= ALLOC_ARRAY_END:
        # 打印alloc_array中的每条指令和关键状态
        sym_st = detector._sym_propagator._tracker
        rax_expr = sym_st.get_expr("rax")
        rcx_expr = sym_st.get_expr("rcx")
        rdx_expr = sym_st.get_expr("rdx")
        r8_expr = sym_st.get_expr("r8")
        stack_8 = sym_st.get_stack_expr("rbp-0x8")
        stack_10 = sym_st.get_stack_expr("rbp+0x10")
        stack_18 = sym_st.get_stack_expr("rbp+0x18")
        kc_rcx = detector._known_constants.get("rcx")
        kc_rdx = detector._known_constants.get("rdx")

        print(f"[{i:4d}] 0x{addr:x} {mnem} {', '.join(ops)}")
        print(f"       rax={rax_expr}, rcx={rcx_expr}, rdx={rdx_expr}, r8={r8_expr}")
        print(f"       [rbp-0x8]={stack_8}, [rbp+0x10]={stack_10}, [rbp+0x18]={stack_18}")
        print(f"       const: rcx={kc_rcx}, rdx={kc_rdx}")

    detector.analyze_instruction(ins)

findings = detector.finalize(instructions)
print(f"\nRaw findings: {len(detector._raw_findings)}")
for rf in detector._raw_findings:
    print(f"  alloc_addr=0x{rf.get('alloc_addr',0):x}")
    print(f"  alloc_size_range={rf.get('alloc_size_range')}")
    print(f"  write_sym_expr={rf.get('_write_sym_expr')}")
    print(f"  fp_stage={rf.get('fp_stage')}")
    print(f"  ddssc_detail={rf.get('ddssc_detail')}")

print(f"\nSym snapshots:")
for addr, snap in detector._sym_snapshots.items():
    if ALLOC_ARRAY_START <= addr <= ALLOC_ARRAY_END:
        print(f"  0x{addr:x}: {snap}")
