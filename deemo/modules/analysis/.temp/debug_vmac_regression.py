#!/usr/bin/env python3
"""调试vmac回归: 检查什么导致它从DETECT变成CLEAN."""
import sys
sys.path.insert(0, '.')
from modules.analysis.eval.batch_test_uaf import _disassemble, compile_and_test
from modules.analysis.static.uaf_detect import UAFDetector
from pathlib import Path

binary = "modules/analysis/eval/build_tmp_uaf/cve_2018_17182_vmac_O0.exe"
src = "modules/analysis/benchmark/samples_uaf/cve_2018_17182_vmac/cve_2018_17182_vmac_uaf.c"
if not Path(binary).exists():
    r = compile_and_test(src, binary, "O0")
    print("Compile:", r.get("error", "OK"))

instructions = _disassemble(binary)
detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)

print("Findings before finalize:")
for f in detector._findings:
    print("  ", f)

findings = detector.finalize(instructions)
print("\nFindings after finalize:")
for f in findings:
    print("  ", f)

print("\nObjects:")
for oid, obj in detector._objects.items():
    print("  oid=%d alloc=0x%x freed_at=%s nulled=%s use_after=%s" % (
        oid, obj.alloc_addr,
        [hex(a) for a in obj.freed_at],
        obj.nulled_after_free,
        [hex(a) for a in obj.use_after_free_at]))

# Print relevant disassembly
print("\nDisassembly (user code):")
for ins in instructions:
    addr = ins['address']
    # user func range
    ranges = detector._user_func_ranges
    in_user = any(lo <= addr < hi for lo, hi in ranges) if ranges else True
    if in_user and 0x140001760 <= addr <= 0x140001900:
        print("  0x%x %-8s %s" % (addr, ins['mnemonic'], ins['operands']))
