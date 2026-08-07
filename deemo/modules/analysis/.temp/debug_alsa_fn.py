#!/usr/bin/env python3
"""调试alsa FN: 检查路径互斥判定."""
import sys
sys.path.insert(0, '.')
from modules.analysis.eval.batch_test_uaf import _disassemble
from modules.analysis.static.uaf_detect import UAFDetector

binary = "modules/analysis/eval/build_tmp_uaf/cve_2018_7566_alsa_O0.exe"
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

# Print disassembly
print("\nDisassembly:")
for ins in instructions:
    addr = ins['address']
    if 0x140001760 <= addr <= 0x140001820:
        print("  0x%x %-8s %s" % (addr, ins['mnemonic'], ins['operands']))

# Check path analyzer scopes
print("\nPath scopes:")
for s in detector._path_analyzer._scopes:
    print("  jcc=0x%x target=0x%x ft=0x%x merge=0x%x taken=%s ft_range=%s" % (
        s.jcc_addr, s.target, s.fallthrough, s.merge_addr,
        s.taken_range, s.fallthrough_range))

# Check if free and use are mutually exclusive
if detector._objects:
    for oid, obj in detector._objects.items():
        if obj.freed_at:
            free_addr = obj.freed_at[0]
            for ua in obj.use_after_free_at:
                me = detector._path_analyzer.are_mutually_exclusive(free_addr, ua)
                print("\n  free=0x%x use=0x%x mutually_exclusive=%s" % (free_addr, ua, me))
