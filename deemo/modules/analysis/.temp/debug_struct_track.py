import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.disasm_util import norm_reg, extract_stack_slot, resolve_rip_relative
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

for ins in insns:
    a = ins['address']
    if a == 0x1400017ee:
        print(f"BEFORE {hex(a)}: {ins['mnemonic']} {ins['operands']}")
        print(f"  ops[0]={ins['operands'][0]!r} ops[1]={ins['operands'][1]!r}")
        dst_raw = ins['operands'][0].strip()
        src_raw = ins['operands'][1].strip()
        dst_reg = norm_reg(dst_raw)
        src_reg = norm_reg(src_raw)
        print(f"  dst_raw={dst_raw!r} src_raw={src_raw!r}")
        print(f"  dst_reg={dst_reg!r} src_reg={src_reg!r}")
        print(f"  '[' in dst_raw.lower()={('[' in dst_raw.lower())}")
        print(f"  '[' in src_raw.lower()={('[' in src_raw.lower())}")
        print(f"  not ('[' in dst or '[' in src) = {not ('[' in dst_raw.lower() or '[' in src_raw.lower())}")
        print(f"  reg_to_obj before: {dict(det._reg_to_obj)}")
        
        # 手动执行 _track_pointer_move 的逻辑
        abs_addr = resolve_rip_relative(ins, src_raw, a)
        print(f"  resolve_rip_relative({src_raw!r}) = {abs_addr}")
        slot = extract_stack_slot(src_raw)
        print(f"  extract_stack_slot({src_raw!r}) = {slot}")
        if slot:
            print(f"  _stack_to_obj.get({slot!r}) = {det._stack_to_obj.get(slot)}")
        
        det.analyze_instruction(ins)
        print(f"  reg_to_obj after: {dict(det._reg_to_obj)}")
    else:
        det.analyze_instruction(ins)
