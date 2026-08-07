#!/usr/bin/env python3
"""CVE_09 反汇编查看."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_09\vuln_CVE_09.exe"
instructions, fmt, main, ranges = disassemble_binary(binary)

for ins in instructions:
    addr = ins.get("address", 0)
    if 0x140001750 <= addr <= 0x1400017c0:
        mnem = ins.get("mnemonic", "")
        ops = " ".join(ins.get("operands", []))
        print(f"0x{addr:x}  {mnem:8s} {ops}")
