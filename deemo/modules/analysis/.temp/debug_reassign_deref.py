#!/usr/bin/env python3
"""调试reassign_after_free_safe: 追踪_check_global_deref扫描过程."""
import sys, json
sys.path.insert(0, '.')

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_global_free_scanner import GlobalFreeScanner
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

# Don't finalize yet - check the GlobalFreeScanner state
scanner = detector._finalizer._global_scanner

# Manually run scan phases to debug
global_to_obj = dict(detector._addr_to_obj)
from modules.analysis.static.disasm_util import resolve_rip_relative, extract_func_name, norm_reg

for ins in instructions:
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    addr = ins.get("address", 0)
    if mnem == "mov" and len(ops) >= 2:
        dst_op = ops[0].strip()
        if "[" in dst_op.lower() and "rip" in dst_op.lower():
            abs_addr = resolve_rip_relative(ins, dst_op, addr)
            if abs_addr is not None:
                src_reg = norm_reg(ops[1].strip())
                oid = detector._reg_to_obj.get(src_reg) if src_reg else None
                if oid is None:
                    oid = global_to_obj.get(abs_addr)
                if oid is not None and abs_addr not in global_to_obj:
                    global_to_obj[abs_addr] = oid

print("global_to_obj:", {hex(k): v for k, v in global_to_obj.items()})

# Phase 2: find free sites
free_sites = []
for idx, ins in enumerate(instructions):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    addr = ins.get("address", 0)
    if mnem != "call" or not ops:
        continue
    callee = extract_func_name(ops[0])
    if callee not in scanner._FREE_FUNCS:
        continue
    if not detector._is_user_code(addr):
        continue
    global_addr = scanner._trace_free_to_global(instructions, idx, addr)
    if global_addr is not None:
        oid = scanner._find_obj_at_free(instructions, idx, global_addr)
        print("Free at 0x%x: global_addr=0x%x oid=%s" % (addr, global_addr, oid))
        if oid is not None and oid in detector._objects:
            obj = detector._objects[oid]
            if addr not in obj.freed_at:
                obj.freed_at.append(addr)
            free_sites.append((addr, global_addr, oid))

print("Free sites:", [(hex(a), hex(g), o) for a, g, o in free_sites])
print()

# Phase 3: check deref
for free_addr, global_addr, oid in free_sites:
    obj = detector._objects.get(oid)
    print("Checking free_addr=0x%x global_addr=0x%x oid=%d nulled=%s" % (free_addr, global_addr, oid, obj.nulled_after_free if obj else "?"))
    # Find the start_idx (first instruction after free_addr)
    for idx, ins in enumerate(instructions):
        addr = ins.get("address", 0)
        if addr > free_addr:
            print("  start_idx=%d start_addr=0x%x" % (idx, addr))
            result = scanner._check_global_deref(instructions, idx, global_addr, free_addr, oid)
            print("  _check_global_deref result:", hex(result) if result else None)
            break
