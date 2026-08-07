# 调试 afpacket O0: 分析检测器内部状态
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.uaf_detect import UAFDetector

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2020_14386_afpacket_O0.exe"

instructions, fmt, main_addr, user_ranges = disassemble_binary(binary)
print(f"Instructions: {len(instructions)}")
print(f"User func ranges count: {len(user_ranges)}")

# 打印 v_2020 函数区域指令
print("\n--- v_2020 function instructions ---")
for ins in instructions:
    addr = ins.get("address", 0)
    if 0x140001760 <= addr <= 0x140001837:
        mnem = ins.get("mnemonic", "")
        ops = ins.get("operands", [])
        print(f"  {hex(addr)}: {mnem} {', '.join(ops)}")

# 运行检测器
print("\n--- Running detector ---")
detector = UAFDetector(use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)

# 逐步分析关键指令
for ins in instructions:
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    
    detector.analyze_instruction(ins)
    
    # 打印关键指令后的状态
    if 0x140001760 <= addr <= 0x140001837 and mnem in ("call", "mov", "lea", "jmp", "je", "jle"):
        if mnem == "call" and ops:
            from modules.analysis.static.disasm_util import extract_func_name
            fname = extract_func_name(ops[0])
            if fname in ("malloc", "free", "memset", "printf"):
                print(f"  {hex(addr)}: {mnem} {fname}")
                print(f"    _reg_to_obj: {dict(detector._reg_to_obj)}")
                print(f"    _addr_to_obj keys: {[hex(a) for a in detector._addr_to_obj.keys()]}")

print(f"\nObjects: {len(detector._objects)}")
for oid, obj in detector._objects.items():
    print(f"  obj#{oid}: alloc={hex(obj.alloc_addr)}, freed_at={[hex(a) for a in obj.freed_at]}, "
          f"uaf_at={[hex(a) for a in obj.use_after_free_at]}")

print(f"\n_addr_to_obj: {[(hex(a), oid) for a, oid in detector._addr_to_obj.items()]}")
print(f"Findings (raw): {len(detector._findings)}")
for f in detector._findings:
    print(f"  {f}")

findings = detector.finalize(instructions)
print(f"\nFinalized findings: {len(findings)}")
for f in findings:
    print(f"  {f}")

# 检查 is_indexed_access
from modules.analysis.static.uaf_operand_utils import is_indexed_access
test_ops = [
    "QWORD PTR [rdx+rax*1]",
    "QWORD PTR [rax*8+0x0]",
    "QWORD PTR [rip+0xd870]",
    "BYTE PTR [rax]",
    "QWORD PTR [rdx+rax*1]",
]
print("\n--- is_indexed_access tests ---")
for op in test_ops:
    print(f"  '{op}' → {is_indexed_access(op)}")
