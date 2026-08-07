#!/usr/bin/env python3
"""查看CVE_05函数的完整指令范围"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.import_resolver import resolve_call_targets

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

# 打印write_addr前后300字节的所有指令
write_addr = 5368715183
for ins in instructions:
    addr = ins.get("address", 0)
    if addr >= write_addr - 200 and addr <= write_addr + 50:
        mnem = ins.get("mnemonic", "")
        ops = ins.get("operands", [])
        print(f"  {addr}: {mnem} {ops}")
