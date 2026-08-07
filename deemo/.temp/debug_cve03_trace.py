#!/usr/bin/env python3
"""CVE_03 调试 — 检查为什么栈槽清除导致误报."""
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

# 找safe_copy函数 (搜索malloc call)
malloc_addrs = []
for i, ins in enumerate(instructions):
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    if mnem == "call" and ops and "malloc" in ops[0].lower():
        malloc_addrs.append((i, ins.get("address", 0)))

print("malloc calls:", malloc_addrs)

# 找safe_copy的范围 (malloc前50字节到后100字节)
if malloc_addrs:
    mi, ma = malloc_addrs[0]
    start_idx = max(0, mi - 30)
    end_idx = min(len(instructions), mi + 40)

    detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
    detector.set_user_func_ranges(user_ranges)
    detector.pre_analyze(instructions)

    for i, ins in enumerate(instructions):
        addr = ins.get("address", 0)
        mnem = ins.get("mnemonic", "")
        ops = ins.get("operands", [])

        if start_idx <= i <= end_idx:
            sym_st = detector._sym_propagator._tracker
            rcx_expr = sym_st.get_expr("rcx")
            rdx_expr = sym_st.get_expr("rdx")
            r8_expr = sym_st.get_expr("r8")
            rax_expr = sym_st.get_expr("rax")
            stack_10 = sym_st.get_stack_expr("rbp+0x10")
            stack_18 = sym_st.get_stack_expr("rbp+0x18")
            stack_8 = sym_st.get_stack_expr("rbp-0x8")

            print(f"[{i:4d}] 0x{addr:x} {mnem} {', '.join(ops)}")
            print(f"       rax={rax_expr}, rcx={rcx_expr}, rdx={rdx_expr}, r8={r8_expr}")
            print(f"       [rbp+0x10]={stack_10}, [rbp+0x18]={stack_18}, [rbp-0x8]={stack_8}")

        detector.analyze_instruction(ins)

    findings = detector.finalize(instructions)
    print(f"\nRaw findings: {len(detector._raw_findings)}")
    for rf in detector._raw_findings:
        print(f"  alloc_addr=0x{rf.get('alloc_addr',0):x}")
        print(f"  write_sym_expr={rf.get('_write_sym_expr')}")
        print(f"  fp_stage={rf.get('fp_stage')}")
        print(f"  fp_filtered={rf.get('fp_filtered')}")
        print(f"  ddssc_detail={rf.get('ddssc_detail')}")
    print(f"Final findings: {len(findings)}")
    for f in findings:
        print(f"  {f.get('type')}, ddssc_verified={f.get('ddssc_verified')}")
