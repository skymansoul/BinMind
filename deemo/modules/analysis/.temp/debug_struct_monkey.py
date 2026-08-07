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

# Monkey-patch _track_pointer_move to trace execution
original_track = det._track_pointer_move.__func__

def traced_track(self, ins, dst_op, src_op, addr):
    rax_before = self._reg_to_obj.get('rax')
    original_track(self, ins, dst_op, src_op, addr)
    rax_after = self._reg_to_obj.get('rax')
    if addr == 0x1400017ee:
        print(f"TRACE {hex(addr)}: {ins['mnemonic']} {ins['operands']}")
        print(f"  dst_op={dst_op!r} src_op={src_op!r}")
        print(f"  rax: {rax_before} -> {rax_after}")
        print(f"  is_indexed_access(src_op) = {is_indexed_access(src_op)}")
        # 手动逐步执行
        dst_raw, src_raw = dst_op.strip(), src_op.strip()
        print(f"  step1: not ([ in dst or [ in src) = {not ('[' in dst_raw.lower() or '[' in src_raw.lower())}")
        print(f"  step2: [ in dst = {'[' in dst_raw.lower()}")
        print(f"  step3: [ in src = {'[' in src_raw.lower()}")
        if '[' in src_raw.lower():
            abs_addr = resolve_rip_relative(ins, src_raw, addr)
            print(f"  step4: resolve_rip_relative = {abs_addr}")
            if abs_addr is None and self._is_user_code(addr):
                slot = extract_stack_slot(src_raw)
                print(f"  step5: slot = {slot}")
                if slot is not None:
                    oid = self._stack_to_obj.get(slot)
                    print(f"  step6: stack_to_obj[{slot}] = {oid}")
            print(f"  step7: is_indexed_access = {is_indexed_access(src_raw)}")

import types
det._track_pointer_move = types.MethodType(traced_track, det)

for ins in insns:
    det.analyze_instruction(ins)
