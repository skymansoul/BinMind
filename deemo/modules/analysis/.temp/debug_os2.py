import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_overflow_Os.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)

# 找到用户函数范围内的所有指令
user_insns = []
for inst in ins:
    addr = inst.get("address", 0)
    if any(lo <= addr < hi for lo, hi in ranges):
        user_insns.append(inst)

print(f"User instructions: {len(user_insns)} / {len(ins)}")

# 查找 rep movs, movaps 等
for inst in user_insns:
    mnem = inst.get("mnemonic", "").lower()
    ops = inst.get("operands", [])
    addr = inst.get("address", 0)
    if mnem.startswith("rep") or mnem in ("movaps", "movups", "movdqa", "movdqu", "movsb", "movsd", "movsq"):
        print(f"  [{hex(addr)}] {mnem} {ops}")
    elif mnem == "call" and ops:
        target = ops[0].lower()
        if "memcpy" in target or "malloc" in target or "memmove" in target:
            print(f"  [{hex(addr)}] {mnem} {ops[0]}")

# 查找 malloc(0x14000176c) 附近的指令
print("\n--- Around malloc 0x14000176c ---")
for i, inst in enumerate(ins):
    addr = inst.get("address", 0)
    if abs(addr - 0x14000176c) < 100:
        mnem = inst.get("mnemonic", "").lower()
        ops = inst.get("operands", [])
        marker = " <-- MALLOC" if addr == 0x14000176c else ""
        print(f"  [{hex(addr)}] {mnem} {ops}{marker}")

# 在 malloc 后找写入指令
print("\n--- After malloc 0x14000176c (next 30 insns) ---")
found = False
count = 0
for inst in ins:
    addr = inst.get("address", 0)
    if addr == 0x14000176c:
        found = True
    if found and count < 30:
        mnem = inst.get("mnemonic", "").lower()
        ops = inst.get("operands", [])
        print(f"  [{hex(addr)}] {mnem} {ops}")
        count += 1
