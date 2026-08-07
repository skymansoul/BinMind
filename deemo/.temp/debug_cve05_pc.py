#!/usr/bin/env python3
"""精确调试CVE_05路径约束收集失败原因"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import PathConstraintCollector

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

target_addr = 5368715183  # memcpy call

collector = PathConstraintCollector()
pcs = collector.collect(instructions, target_addr, {})
print(f"Collected {len(pcs)} constraints")
for pc in pcs:
    print(f"  {pc}")

# 手动遍历检查
func_start_idx = 0
for i in range(len(instructions) - 1, -1, -1):
    addr = instructions[i].get("address", 0)
    if addr > target_addr:
        continue
    mnem = instructions[i].get("mnemonic", "").lower()
    if mnem in ("ret", "jmp") and i + 1 < len(instructions):
        next_addr = instructions[i + 1].get("address", 0)
        if next_addr <= target_addr:
            func_start_idx = i + 1
            break

print(f"\nfunc_start_idx={func_start_idx}, addr={instructions[func_start_idx].get('address',0)}")

# 遍历函数内指令寻找cmp
print("\nAll cmp/test in function:")
for i in range(func_start_idx, len(instructions)):
    ins = instructions[i]
    addr = ins.get("address", 0)
    if addr >= target_addr:
        break
    mnem = ins.get("mnemonic", "").lower()
    if mnem in ("cmp", "test"):
        ops = ins.get("operands", [])
        reg = collector._norm_reg(ops[0]) if ops else ""
        cmp_val = collector._parse_imm(ops[1]) if len(ops) >= 2 else None
        print(f"  idx={i} addr={addr}: {mnem} {ops} -> reg={reg}, val={cmp_val}")
        
        # Find next jcc
        jcc = collector._find_next_jcc(instructions, i, target_addr)
        if jcc is None:
            print(f"    -> no jcc found")
        else:
            jcc_ins, jcc_idx, jcc_mnem = jcc
            jcc_addr = jcc_ins.get("address", 0)
            target = collector._extract_jump_target(jcc_ins)
            fallthrough = collector._get_fallthrough(instructions, jcc_idx)
            print(f"    -> jcc={jcc_mnem} at {jcc_addr}, target={target}, fallthrough={fallthrough}")
            print(f"    -> target <= target_addr? {target <= target_addr if target else 'N/A'}")
            print(f"    -> fallthrough <= target_addr? {fallthrough <= target_addr if fallthrough else 'N/A'}")
