#!/usr/bin/env python3
"""调试单一样本的反汇编结果."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from modules.analysis.static.disasm_util import disassemble_binary

binary = sys.argv[1] if len(sys.argv) > 1 else \
    "modules/vuln/sample_bins/heap_overflow_cve/CVE_01/vuln_CVE_01.exe"

ins, fmt, main, ranges = disassemble_binary(binary)
print(f"format: {fmt}")
print(f"instructions: {len(ins)}")
print(f"main_addr: {hex(main)}")
print(f"user_ranges: {len(ranges)}")

if ins:
    for i in ins[:20]:
        addr = hex(i["address"])
        mnem = i["mnemonic"]
        ops = i["operands"]
        print(f"  {addr} {mnem} {ops}")

# 检查是否含call malloc/memcpy
calls = [i for i in ins if i["mnemonic"].lower() == "call"]
print(f"\ntotal calls: {len(calls)}")
for c in calls[:15]:
    ops_str = " ".join(c["operands"])
    if any(k in ops_str.lower() for k in ("malloc", "memcpy", "calloc", "realloc", "free", "strcpy", "read")):
        print(f"  {hex(c['address'])} call {ops_str}")
