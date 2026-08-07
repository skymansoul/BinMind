import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 替换 _track_pointer_move 为带调试版本
original = det._track_pointer_move

def patched(ins, dst_op, src_op, addr):
    rax_before = det._reg_to_obj.get('rax')
    original(ins, dst_op, src_op, addr)
    rax_after = det._reg_to_obj.get('rax')
    if addr == 0x1400017ee and rax_before != rax_after:
        print(f"  _track_pointer_move changed rax: {rax_before} -> {rax_after}")
    elif addr == 0x1400017ee:
        print(f"  _track_pointer_move did NOT change rax: {rax_before} (expected pop)")

det._track_pointer_move = patched

for ins in insns:
    a = ins['address']
    if a == 0x1400017ee:
        print(f"Before {hex(a)}: rax={det._reg_to_obj.get('rax')}")
    det.analyze_instruction(ins)
    if a == 0x1400017ee:
        print(f"After {hex(a)}: rax={det._reg_to_obj.get('rax')}")
        print(f"  _findings so far: {len(det._findings)}")
        # 检查deref_checker
        mnem = ins.get("mnemonic","").lower()
        ops = ins.get("operands",[])
        print(f"  mnem={mnem} ops={ops}")
