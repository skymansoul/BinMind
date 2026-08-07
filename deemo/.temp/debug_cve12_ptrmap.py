#!/usr/bin/env python3
"""调试CVE_12: 检查memset调用时的ptr_map和size_reg状态"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.disasm_util import norm_reg

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_12', 'vuln_CVE_12.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)
detector = HeapOverflowDetector(
    allocator=AllocatorFamily.GLIBC,
    use_win64_abi='pei' in file_format.lower())
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)

# 自定义指令处理: 在call memset时打印ptr_map状态
for ins in instructions:
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    detector.analyze_instruction(ins)
    
    # 在call指令后打印状态
    if mnem == "call" and ops:
        func = ops[0]
        if "memset" in str(func) or "memcpy" in str(func) or "malloc" in str(func):
            ptr_map = detector._alloc_tracker._ptr_to_alloc
            print(f"\n=== {hex(addr)}: {mnem} {func} ===")
            print(f"ptr_map: {dict(ptr_map)}")
            print(f"known_constants: {dict(detector._known_constants)}")
            print(f"raw_findings count: {len(detector._raw_findings)}")

print(f"\nTotal raw_findings: {len(detector._raw_findings)}")
for f in detector._raw_findings:
    print(f"  write_addr={hex(f.get('write_addr',0))}, alloc_size={f.get('alloc_size')}, write_size={f.get('write_size')}")
