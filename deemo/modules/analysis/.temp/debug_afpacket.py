#!/usr/bin/env python3
"""调试cve_2020_14386_afpacket回归问题."""
import sys
sys.path.insert(0, '.')
from modules.analysis.eval.batch_test_uaf import _disassemble, compile_and_test
from modules.analysis.static.uaf_detect import UAFDetector
import subprocess

binary = "modules/analysis/eval/build_tmp_uaf/cve_2020_14386_afpacket_O0.exe"
# Make sure it's compiled
from pathlib import Path
src = "modules/analysis/benchmark/samples_uaf/cve_2020_14386_afpacket/cve_2020_14386_afpacket.c"
if not Path(binary).exists():
    r = compile_and_test(src, binary, "O0")
    print("Compile result:", r.get("error", "OK"))
    
instructions = _disassemble(binary)
if not instructions:
    print("Disassembly failed")
    sys.exit(1)

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
