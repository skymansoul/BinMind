#!/usr/bin/env python3
"""检查jbe的目标地址解析"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import PathConstraintCollector

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

target_addr = 5368715183

# Find the jbe instruction
for i, ins in enumerate(instructions):
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "").lower()
    if mnem == "jbe":
        ops = ins.get("operands", [])
        print(f"jbe at addr={addr}, ops={ops}")
        target = PathConstraintCollector._extract_jump_target(ins)
        fallthrough = PathConstraintCollector._get_fallthrough(instructions, i)
        print(f"  target={target} ({hex(target) if target else 'None'})")
        print(f"  fallthrough={fallthrough} ({hex(fallthrough) if fallthrough else 'None'})")
        print(f"  target <= target_addr? {target <= target_addr if target else 'N/A'}")
        print(f"  fallthrough <= target_addr? {fallthrough <= target_addr if fallthrough else 'N/A'}")
        
        # Also check cmp before this jbe
        if i > 0:
            cmp_ins = instructions[i-1]
            print(f"  prev: {cmp_ins.get('mnemonic','')} {cmp_ins.get('operands',[])}")
            ops = cmp_ins.get("operands", [])
            reg = PathConstraintCollector._norm_reg(ops[0]) if ops else ""
            val = PathConstraintCollector._parse_imm(ops[1]) if len(ops) >= 2 else None
            print(f"  reg={reg}, val={val}")
        break
