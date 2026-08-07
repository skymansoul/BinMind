#!/usr/bin/env python3
"""调试reassign_after_free_safe: 检查findings来源(flow分析 vs GlobalFreeScanner)."""
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

print("Findings before finalize:")
for f in detector._findings:
    print("  ", f)

print()
print("Reg_to_obj after scan:", detector._reg_to_obj)
print("Addr_to_obj after scan:", {hex(k): v for k, v in detector._addr_to_obj.items()})

findings = detector.finalize(instructions)
print()
print("Findings after finalize:")
for f in findings:
    print("  ", f)

print()
print("Objects:")
for oid, obj in detector._objects.items():
    print("  oid=%d alloc=0x%x freed_at=%s nulled=%s use_after=%s" % (
        oid, obj.alloc_addr,
        [hex(a) for a in obj.freed_at],
        obj.nulled_after_free,
        [hex(a) for a in obj.use_after_free_at]))
