#!/usr/bin/env python3
"""调试reassign_after_free_safe UAF误报根因."""
import sys, json
sys.path.insert(0, '.')

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

manifest_path = 'modules/analysis/benchmark/samples_uaf_safe/manifest.json'
with open(manifest_path) as f:
    manifest = json.load(f)

binary = None
for entry in manifest:
    if entry['pattern'] == 'reassign_after_free' and entry['variant'] == 'safe' and entry['opt'] == 'O0':
        binary = entry['binary']
        break

instructions = _disassemble(binary)
detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)
findings = detector.finalize(instructions)

print("Binary:", binary)
print("Findings:")
for f in findings:
    print("  ", f)
print()
print("Objects:")
for oid, obj in detector._objects.items():
    print("  oid=%d alloc=0x%x freed_at=%s nulled=%s" % (oid, obj.alloc_addr, [hex(a) for a in obj.freed_at], obj.nulled_after_free))
print()
print("addr_to_obj:", {hex(k): v for k, v in detector._addr_to_obj.items()})
print("reg_to_obj:", detector._reg_to_obj)
print()
print("Disassembly (function area):")
for ins in instructions:
    addr = ins['address']
    if 0x140001750 <= addr <= 0x1400017f0:
        print("  0x%x %-8s %s" % (addr, ins['mnemonic'], ins['operands']))
