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

# 直接手动模拟_track_pointer_move的完整逻辑
for ins in insns:
    a = ins['address']
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    
    if a == 0x1400017ee:
        print(f"Processing {hex(a)}: {mnem} {ops}")
        print(f"  reg_to_obj before: {dict(det._reg_to_obj)}")
        
        # 手动执行 _track_pointer_move 逻辑
        dst_raw = ops[0].strip()
        src_raw = ops[1].strip()
        dst_reg = norm_reg(dst_raw)
        src_reg = norm_reg(src_raw)
        
        print(f"  dst_raw={dst_raw!r} src_raw={src_raw!r}")
        print(f"  dst_reg={dst_reg!r} src_reg={src_reg!r}")
        
        cond1 = not ("[" in dst_raw.lower() or "[" in src_raw.lower())
        print(f"  cond1 (no brackets) = {cond1}")
        
        cond2 = "[" in dst_raw.lower()
        print(f"  cond2 ([ in dst) = {cond2}")
        
        cond3 = "[" in src_raw.lower()
        print(f"  cond3 ([ in src) = {cond3}")
        
        if cond3:
            abs_addr = resolve_rip_relative(ins, src_raw, a)
            print(f"  resolve_rip = {abs_addr}")
            if abs_addr is None:
                print(f"  is_user_code = {det._is_user_code(a)}")
                if det._is_user_code(a):
                    slot = extract_stack_slot(src_raw)
                    print(f"  slot = {slot}")
                    if slot is not None:
                        oid = det._stack_to_obj.get(slot)
                        print(f"  stack_oid = {oid}")
                        if oid is None:
                            print(f"  ABOUT TO CHECK is_indexed_access...")
                            idx = is_indexed_access(src_raw)
                            print(f"  is_indexed_access = {idx}")
                            if not idx:
                                print(f"  SHOULD POP {dst_reg}")
        
        # Now actually run it
        det.analyze_instruction(ins)
        print(f"  reg_to_obj after: {dict(det._reg_to_obj)}")
    else:
        det.analyze_instruction(ins)
