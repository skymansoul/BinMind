# 调试 loop_accumulate O0 反汇编中 memcpy 附近的指针映射
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_O0.exe'
instrs, fmt, main_addr, user_ranges = disassemble_binary(binary)
print(f"Total: {len(instrs)} instructions, {len(user_ranges)} user func ranges")

# 找到包含 sawce_loop_accumulate_vuln 的 user range
for lo, hi in user_ranges:
    for i, ins in enumerate(instrs):
        if ins.get("address", 0) == lo:
            # 打印前几条看函数名
            if lo <= ins.get("address", 0) < hi:
                if i < len(instrs) - 1:
                    # 找到函数区域, 打印全部
                    func_ins = [x for x in instrs if lo <= x.get("address", 0) < hi]
                    if len(func_ins) > 5 and len(func_ins) < 80:
                        print(f"\n=== Function range [0x{lo:x}, 0x{hi:x}) ({len(func_ins)} ins) ===")
                        for j, fi in enumerate(func_ins):
                            print(f"  [{j}] 0x{fi.get('address',0):x} {fi.get('mnemonic','')} {fi.get('operands',[])}")
            break

# 也找 malloc call 附近
print("\n=== Searching for 'malloc' calls ===")
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops and "malloc" in str(ops[0]).lower():
        addr = ins.get("address", 0)
        # 在用户区域?
        is_user = any(lo <= addr < hi for lo, hi in user_ranges)
        if is_user:
            print(f"\n  malloc call at [{i}] 0x{addr:x} (user code)")
            for j in range(max(0, i-5), min(i+40, len(instrs))):
                jins = instrs[j]
                jaddr = jins.get("address", 0)
                juser = any(lo <= jaddr < hi for lo, hi in user_ranges)
                tag = "USER" if juser else "CRT"
                print(f"    [{j}] 0x{jaddr:x} ({tag}) {jins.get('mnemonic','')} {jins.get('operands',[])}")
            break

# 找 memcpy calls
print("\n=== Searching for 'memcpy' calls ===")
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops and "memcpy" in str(ops[0]).lower():
        addr = ins.get("address", 0)
        is_user = any(lo <= addr < hi for lo, hi in user_ranges)
        if is_user:
            print(f"\n  memcpy call at [{i}] 0x{addr:x} (user code)")
            for j in range(max(0, i-15), min(i+5, len(instrs))):
                jins = instrs[j]
                jaddr = jins.get("address", 0)
                print(f"    [{j}] 0x{jaddr:x} {jins.get('mnemonic','')} {jins.get('operands',[])}")
