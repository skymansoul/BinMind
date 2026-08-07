# 调试 derived_boundary 和 loop_accumulate 的反汇编指令
import sys, json
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary

# 1. derived_boundary O0 — 确认 padding 修复后 is_overflow(128, 129) 的行为
print("=" * 60)
print("TEST 1: HeapAllocModel.is_overflow(128, 129)")
from modules.analysis.static.heap_alloc_model import HeapAllocModel, AllocatorFamily
m = HeapAllocModel(AllocatorFamily.GLIBC)
chunk = m.actual_chunk_size(128)
usable = m.usable_size(128)
ok, reason = m.is_overflow(128, 129)
print(f"  chunk_size(128) = {chunk}")
print(f"  usable_size(128) = {usable}")
print(f"  is_overflow(128, 129) = {ok}")
print(f"  reason = {reason}")

# 2. loop_accumulate O0 — 检查反汇编中的跳转指令格式
print("\n" + "=" * 60)
print("TEST 2: loop_accumulate O0 disassembly")
binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_O0.exe'
instrs, fmt, main_addr, user_ranges = disassemble_binary(binary)
print(f"  Total instructions: {len(instrs)}")
# 找到所有跳转指令
jcc_count = 0
back_jcc_count = 0
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    if mnem.startswith("j") and mnem != "jmp":
        ops = ins.get("operands", [])
        jcc_count += 1
        if ops:
            print(f"  [{i}] addr=0x{ins.get('address',0):x} mnem={mnem} ops={ops}")
            # 尝试解析目标
            op0 = ops[0]
            # 清理 <...> 尾缀
            clean = op0.split("<")[0].strip().split()[0] if "<" in op0 else op0
            try:
                target = int(clean, 16) if clean.startswith("0x") else int(clean)
                if target < ins.get("address", 0):
                    back_jcc_count += 1
                    print(f"    -> BACK EDGE to 0x{target:x}")
            except:
                print(f"    -> CANNOT PARSE: '{op0}' (cleaned: '{clean}')")
    elif mnem == "jmp":
        ops = ins.get("operands", [])
        if ops:
            op0 = ops[0]
            clean = op0.split("<")[0].strip().split()[0] if "<" in op0 else op0
            try:
                target = int(clean, 16) if clean.startswith("0x") else int(clean)
                if target < ins.get("address", 0):
                    back_jcc_count += 1
                    print(f"  [{i}] addr=0x{ins.get('address',0):x} JMP BACK to 0x{target:x} ops={ops}")
            except:
                pass

print(f"\n  Total jcc: {jcc_count}, back edges: {back_jcc_count}")

# 3. 展示 loop_accumulate_vuln 函数附近的指令
print("\n" + "=" * 60)
print("TEST 3: loop_accumulate_vuln function area")
# 找到 call malloc 附近
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops and "malloc" in ops[0].lower():
        print(f"\n  Found malloc call at [{i}] addr=0x{ins.get('address',0):x}")
        # 打印后续40条指令
        for j in range(i, min(i+50, len(instrs))):
            jins = instrs[j]
            print(f"    [{j}] 0x{jins.get('address',0):x} {jins.get('mnemonic','')} {jins.get('operands',[])}")
        break
