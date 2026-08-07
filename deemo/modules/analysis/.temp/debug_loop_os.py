# 调试 Os loop_accumulate
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary

path = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_Os.exe'
instrs, fmt, main_addr, user_ranges = disassemble_binary(path)

# 找到所有包含 memcpy 的区域, 打印前后 30 条指令
memcpy_indices = []
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops:
        for op in ops:
            if "memcpy" in op.lower():
                memcpy_indices.append(i)

print(f"Found {len(memcpy_indices)} memcpy calls")
for mi in memcpy_indices[:3]:
    print(f"\n{'='*60}")
    print(f"memcpy at index {mi}, addr 0x{instrs[mi].get('address',0):x}")
    start = max(0, mi - 20)
    end = min(len(instrs), mi + 10)
    for j in range(start, end):
        ins = instrs[j]
        addr = ins.get("address", 0)
        mnem = ins.get("mnemonic", "")
        ops = ins.get("operands", [])
        ops_str = ", ".join(ops)
        marker = " <<<" if j == mi else ""
        print(f"  [{j:4d}] 0x{addr:x}  {mnem:8s} {ops_str}{marker}")

# 也找后向跳转 (循环)
print(f"\n{'='*60}")
print("Backward jumps (loops):")
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    if not mnem.startswith("j") or mnem == "jmp":
        continue
    ops = ins.get("operands", [])
    if not ops:
        continue
    op = ops[0].strip().lower()
    if "<" in op:
        op = op.split("<")[0].strip()
    try:
        target = int(op, 16) if op.startswith("0x") or (len(op) >= 6 and all(c in "0123456789abcdef" for c in op)) else int(op)
    except ValueError:
        continue
    cur_addr = ins.get("address", 0)
    if target < cur_addr:
        print(f"  [{i:4d}] 0x{cur_addr:x}  {mnem} -> 0x{target:x} (backward, offset=-{cur_addr-target})")
