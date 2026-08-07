# 调试 loop_accumulate O2 反汇编
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary

for opt in ["O2", "Os"]:
    binary = rf'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_{opt}.exe'
    instrs, fmt, main_addr, user_ranges = disassemble_binary(binary)
    print(f"\n{'='*60}")
    print(f"loop_accumulate {opt}: {len(instrs)} ins, {len(user_ranges)} user ranges")

    # 找到 sawce_loop_accumulate_vuln 函数范围
    for lo, hi in user_ranges:
        func_ins = [x for x in instrs if lo <= x.get("address", 0) < hi]
        if 10 < len(func_ins) < 60:
            # 检查是否是vuln函数 (含call malloc)
            has_malloc = any(
                i.get("mnemonic","").lower()=="call" and
                "malloc" in str(i.get("operands",[""])[0]).lower()
                for i in func_ins
            )
            if has_malloc:
                # 检查是否有循环 (后向跳转)
                has_back = False
                for i, ins in enumerate(func_ins):
                    mnem = ins.get("mnemonic", "").lower()
                    if mnem.startswith("j") and mnem != "jmp":
                        ops = ins.get("operands", [])
                        if ops:
                            op0 = ops[0].split("<")[0].strip()
                            try:
                                target = int(op0, 16)
                                if target < ins.get("address", 0):
                                    has_back = True
                                    print(f"  BACK EDGE: [{i}] 0x{ins.get('address',0):x} {mnem} {ops}")
                            except:
                                pass
                if has_back or len(func_ins) < 30:
                    print(f"\n  Function [0x{lo:x}, 0x{hi:x}) ({len(func_ins)} ins):")
                    for j, fi in enumerate(func_ins):
                        print(f"    [{j}] 0x{fi.get('address',0):x} {fi.get('mnemonic','')} {fi.get('operands',[])}")
                    break

# 也检查 Os
binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_Os.exe'
instrs, fmt, main_addr, user_ranges = disassemble_binary(binary)
print(f"\n{'='*60}")
print(f"loop_accumulate Os: {len(instrs)} ins")
for lo, hi in user_ranges:
    func_ins = [x for x in instrs if lo <= x.get("address", 0) < hi]
    if 10 < len(func_ins) < 60:
        has_malloc = any(
            i.get("mnemonic","").lower()=="call" and
            "malloc" in str(i.get("operands",[""])[0]).lower()
            for i in func_ins
        )
        if has_malloc and len(func_ins) < 30:
            print(f"\n  Function [0x{lo:x}, 0x{hi:x}) ({len(func_ins)} ins):")
            for j, fi in enumerate(func_ins):
                print(f"    [{j}] 0x{fi.get('address',0):x} {fi.get('mnemonic','')} {fi.get('operands',[])}")
            break
