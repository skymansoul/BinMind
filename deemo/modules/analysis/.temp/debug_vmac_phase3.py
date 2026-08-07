#!/usr/bin/env python3
"""调试vmac: 追踪Phase3的deref检查."""
import sys
sys.path.insert(0, '.')
from modules.analysis.eval.batch_test_uaf import _disassemble
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_global_free_scanner import GlobalFreeScanner
from modules.analysis.static.disasm_util import resolve_rip_relative, extract_func_name, norm_reg

binary = "modules/analysis/eval/build_tmp_uaf/cve_2018_17182_vmac_O0.exe"
instructions = _disassemble(binary)
detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)

scanner = detector._finalizer._global_scanner

# Manually run Phase 1+2 to reproduce
global_to_obj = dict(detector._addr_to_obj)
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

# Phase 2
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
        print("Phase2: free_idx=%d free_addr=0x%x global=0x%x oid=%s" % (idx, addr, global_addr, oid))
        if oid is not None and oid in detector._objects:
            obj = detector._objects[oid]
            if addr not in obj.freed_at:
                obj.freed_at.append(addr)
            free_sites.append((addr, global_addr, oid))

print("Free sites:", [(hex(a), hex(g), o) for a, g, o in free_sites])

# Phase 3 trace
for free_addr, global_addr, oid in free_sites:
    obj = detector._objects.get(oid)
    if not obj or obj.nulled_after_free:
        print("Skipping - nulled")
        continue
    
    start_idx = None
    for idx, ins in enumerate(instructions):
        addr = ins.get("address", 0)
        if addr > free_addr and detector._is_user_code(addr):
            start_idx = idx
            break
    if start_idx is None:
        print("No start_idx found!")
        continue
    
    print("Phase3: start_idx=%d start_addr=0x%x free_addr=0x%x" % (idx, instructions[start_idx]['address'], free_addr))
    
    # Check what _deref_checker.check sees
    result = scanner._deref_checker.check(instructions, start_idx, global_addr, free_addr, oid)
    print("  deref_checker result:", hex(result) if result else None)
    
    # Manual trace of deref check
    loaded_reg = None
    for j in range(start_idx, min(start_idx + 50, len(instructions))):
        ins = instructions[j]
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)
        if not detector._is_user_code(addr):
            continue
        
        # Track load
        if mnem in ("mov", "movzx", "movsx", "movsxd", "lea") and len(ops) >= 2:
            dst = norm_reg(ops[0].strip())
            src_raw = ops[1].strip()
            if "rip" in src_raw.lower() and "[" in src_raw.lower():
                gaddr = resolve_rip_relative(ins, src_raw, addr)
                if gaddr == global_addr:
                    loaded_reg = dst
                    print("  [%d] 0x%x LOADED %s from global" % (j, addr, dst))
        
        # Check deref
        if loaded_reg and mnem in ("mov", "movzx", "movsx", "movsxd", "cmp", "test"):
            for op in ops:
                op_s = op.strip().lower()
                for prefix in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr "):
                    if op_s.startswith(prefix):
                        op_s = op_s[len(prefix):]
                        break
                if "[" in op_s and "]" in op_s:
                    inner = op_s[op_s.find("[")+1:op_s.rfind("]")]
                    base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
                    if base == loaded_reg:
                        print("  [%d] 0x%x DEREF found! base=%s loaded=%s" % (j, addr, base, loaded_reg))
        
        if mnem == "ret":
            loaded_reg = None
