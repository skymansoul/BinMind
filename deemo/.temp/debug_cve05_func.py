#!/usr/bin/env python3
"""检查CVE_05 func_start_idx计算"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.import_resolver import resolve_call_targets

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

target_addr = 5368715183

# Find all ret/jmp before target
for i in range(len(instructions) - 1, -1, -1):
    addr = instructions[i].get("address", 0)
    if addr > target_addr:
        continue
    mnem = instructions[i].get("mnemonic", "").lower()
    if mnem in ("ret", "jmp"):
        next_addr = instructions[i + 1].get("address", 0) if i + 1 < len(instructions) else 0
        print(f"  idx={i} addr={addr}: {mnem} {instructions[i].get('operands',[])} -> next_addr={next_addr}, <=target? {next_addr <= target_addr}")
        if next_addr <= target_addr:
            print(f"  >>> This would be selected as func_start: idx={i+1}, addr={next_addr}")
            break
