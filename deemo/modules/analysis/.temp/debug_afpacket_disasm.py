#!/usr/bin/env python3
"""调试afpacket: 查看反汇编和检测状态."""
import sys
sys.path.insert(0, '.')
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = "modules/analysis/eval/build_tmp_uaf/cve_2020_14386_afpacket_O0.exe"
instructions = _disassemble(binary)

print("Total instructions:", len(instructions))
print()
# Print all user code
for ins in instructions:
    addr = ins['address']
    if 0x140001700 <= addr <= 0x140001900:
        print("0x%x %-8s %s" % (addr, ins['mnemonic'], ins['operands']))
