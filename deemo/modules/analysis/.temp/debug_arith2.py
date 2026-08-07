import sys
from pathlib import Path
PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
sys.path.insert(0, str(PROJECT_ROOT))
from modules.analysis.static.disasm_util import disassemble_binary, norm_reg

binary = str(PROJECT_ROOT / 'modules/analysis/benchmark/samples_sawce/sawce_arithmetic/sawce_arithmetic_O0.exe')
ins, fmt, main_addr, ranges = disassemble_binary(binary)

# Find the sawce_arithmetic_vuln function
vuln_start = None
for i, inst in enumerate(ins):
    ops = inst.get("operands", [])
    for op in ops:
        if "sawce_arithmetic_vuln" in str(op):
            print(f"Found at ins[{i}]: {inst}")
            # The function entry is the address in the call operand
            pass

# Print instructions in the vuln function area
for i, inst in enumerate(ins):
    mnem = inst.get("mnemonic", "").lower()
    if mnem == "call":
        ops = inst.get("operands", [])
        if ops and ("malloc" in str(ops[0]) or "memcpy" in str(ops[0])):
            # Print 10 instructions before this call
            start = max(0, i-10)
            print(f"\n--- Context around {ops[0]} (ins[{i}]) ---")
            for j in range(start, min(i+2, len(ins))):
                print(f"  [{j}] {ins[j]}")
