import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_operand_utils import is_indexed_access
from modules.analysis.static.disasm_util import norm_reg, extract_stack_slot, resolve_rip_relative
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 完全替换 _track_pointer_move，精确复刻源码逻辑
def my_track(ins, dst_op, src_op, addr):
    dst_raw, src_raw = dst_op.strip(), src_op.strip()
    dst_reg, src_reg = norm_reg(dst_raw), norm_reg(src_raw)
    
    if addr == 0x1400017ee:
        print(f"  ENTER: dst_reg={dst_reg!r} src_reg={src_reg!r}")
        print(f"  reg_to_obj before: {dict(det._reg_to_obj)}")
    
    if not ("[" in dst_raw.lower() or "[" in src_raw.lower()):
        if addr == 0x1400017ee: print("  PATH: no brackets")
        oid = det._reg_to_obj.get(src_reg)
        if oid is not None: det._reg_to_obj[dst_reg] = oid
        return
    if "[" in dst_raw.lower():
        if addr == 0x1400017ee: print("  PATH: [ in dst")
        abs_addr = resolve_rip_relative(ins, dst_raw, addr)
        if abs_addr is not None:
            oid = det._reg_to_obj.get(src_reg)
            if oid is not None: det._addr_to_obj[abs_addr] = oid
            return
        if det._is_user_code(addr):
            slot = extract_stack_slot(dst_raw)
            if slot is not None:
                oid = det._reg_to_obj.get(src_reg)
                if oid is not None: det._stack_to_obj[slot] = oid
                return
    if "[" in src_raw.lower():
        if addr == 0x1400017ee: print("  PATH: [ in src")
        abs_addr = resolve_rip_relative(ins, src_raw, addr)
        if abs_addr is not None:
            oid = det._addr_to_obj.get(abs_addr)
            if oid is not None:
                det._reg_to_obj[dst_reg] = oid
            return
        if det._is_user_code(addr):
            if addr == 0x1400017ee: print(f"  slot = {extract_stack_slot(src_raw)}")
            slot = extract_stack_slot(src_raw)
            if slot is not None:
                oid = det._stack_to_obj.get(slot)
                if addr == 0x1400017ee: print(f"  stack_oid = {oid}")
                if oid is not None:
                    det._reg_to_obj[dst_reg] = oid
                    return
        if is_indexed_access(src_raw):
            if addr == 0x1400017ee: print("  PATH: indexed access, return without pop")
            return
        if addr == 0x1400017ee: print(f"  PATH: pop {dst_reg}")
        det._reg_to_obj.pop(dst_reg, None)
        return

det._track_pointer_move = my_track

# Process all before 0x1400017ee
for ins in insns:
    det.analyze_instruction(ins)

print(f"\nFinal rax={det._reg_to_obj.get('rax')}")
print(f"Final objects:")
for oid, obj in det._objects.items():
    print(f"  obj{oid}: freed={[hex(x) for x in obj.freed_at]}")
