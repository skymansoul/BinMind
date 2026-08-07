#!/usr/bin/env python3
"""查看CVE_05完整函数指令"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.import_resolver import resolve_call_targets

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

# Find the bounded_copy function
write_addr = 5368715183
func_start = 0
for i, ins in enumerate(instructions):
    addr = ins.get("address", 0)
    if addr > write_addr:
        break
    mnem = ins.get("mnemonic", "").lower()
    if mnem in ("ret", "jmp") and i + 1 < len(instructions):
        next_addr = instructions[i+1].get("address", 0)
        if next_addr <= write_addr:
            func_start = i + 1

print(f"Function start: idx={func_start}, addr={instructions[func_start].get('address',0)}")
print("Full function:")
for i in range(func_start, len(instructions)):
    ins = instructions[i]
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    print(f"  {addr}: {mnem} {ops}")
    if mnem == "ret":
        break
