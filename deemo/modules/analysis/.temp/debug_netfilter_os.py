"""调试netfilter Os: 追踪GlobalFreeScanner的检测流程"""
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.disasm_util import resolve_rip_relative, extract_func_name, norm_reg

exe = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2020_25211_netfilter_Os.exe'

# 用和batch_test_uaf相同的方式反汇编
out = subprocess.run(
    ["objdump", "-d", "-M", "intel", exe],
    capture_output=True, text=True, timeout=30
).stdout

instructions = []
for line in out.split("\n"):
    parts = line.strip().split("\t")
    if len(parts) < 3:
        continue
    try:
        addr = int(parts[0].strip().rstrip(":"), 16)
        mnem_part = parts[2].split()
        mnem = mnem_part[0] if mnem_part else ""
        ops = []
        if len(mnem_part) > 1:
            for o in " ".join(mnem_part[1:]).split(","):
                ops.append(o.strip())
        instructions.append({"address": addr, "mnemonic": mnem, "operands": ops})
    except (ValueError, IndexError):
        continue

print(f"Total instructions: {len(instructions)}")

# 打印用户函数区域(0x140001760-0x1400017b0)
print("\n=== User functions (0x140001760-0x1400017b0) ===")
for i, ins in enumerate(instructions):
    addr = ins.get('address', 0)
    if 0x140001760 <= addr <= 0x1400017b0:
        ops = ins.get('operands', [])
        print(f"  [{i:4d}] 0x{addr:x}: {ins.get('mnemonic','')} {', '.join(ops)}")

# 运行检测器
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(instructions)

print(f"\n=== _user_func_ranges ===")
for lo, hi in det._user_func_ranges:
    print(f"  0x{lo:x} - 0x{hi:x}")

for ins in instructions:
    det.analyze_instruction(ins)

findings = det.finalize(instructions)
print(f"\n=== Findings: {len(findings)} ===")
for f in findings:
    print(f"  type={f.get('type')} addr=0x{f.get('address',0):x} freed_at=0x{f.get('freed_at',0):x} gap={f.get('instr_gap')}")

# 检查GlobalFreeScanner
print(f"\n=== _addr_to_obj: {dict(det._addr_to_obj)} ===")
print(f"=== _objects: ===")
for oid, o in det._objects.items():
    print(f"  oid={oid} alloc=0x{o.alloc_addr:x} freed_at={[hex(x) for x in o.freed_at]} nulled={o.nulled_after_free}")

# 检查_is_user_code
print(f"\n=== _is_user_code check ===")
for test_addr in [0x140001760, 0x140001780, 0x140001792, 0x14000178c, 0x14000179e]:
    result = det._is_user_code(test_addr)
    print(f"  0x{test_addr:x}: _is_user_code={result}")

# 检查GlobalFreeScanner步骤
scanner = det._finalizer._global_scanner
FREE_FUNCS = scanner._FREE_FUNCS

print(f"\n=== Scanning for call/jmp to free ===")
for idx, ins in enumerate(instructions):
    mnem = ins.get('mnemonic', '').lower()
    ops = ins.get('operands', [])
    if mnem not in ('call', 'jmp') or not ops:
        continue
    callee = extract_func_name(ops[0])
    if callee not in FREE_FUNCS:
        continue
    addr = ins.get('address', 0)
    if not det._is_user_code(addr):
        print(f"  Found {mnem} {callee} at 0x{addr:x} (idx={idx}) -- NOT user code, skipped")
        continue
    print(f"  Found {mnem} {callee} at 0x{addr:x} (idx={idx})")
    
    global_addr = scanner._trace_free_to_global(instructions, idx, addr)
    print(f"    global_addr from _trace_free_to_global: {global_addr}")
    
    if global_addr is not None:
        oid = scanner._find_obj_at_free(instructions, idx, global_addr)
        print(f"    obj_id from _find_obj_at_free: {oid}")
        
        if oid is not None and oid in det._objects:
            obj = det._objects[oid]
            print(f"    object: alloc_addr=0x{obj.alloc_addr:x} freed_at={[hex(x) for x in obj.freed_at]}")
            
            start_idx = None
            for idx2, ins2 in enumerate(instructions):
                a2 = ins2.get('address', 0)
                if a2 > addr and det._is_user_code(a2):
                    start_idx = idx2
                    break
            print(f"    start_idx (first user code after free): {start_idx}")
            if start_idx is not None:
                start_ins = instructions[start_idx]
                print(f"    start instruction: 0x{start_ins.get('address',0):x} {start_ins.get('mnemonic','')} {start_ins.get('operands',[])}")
                
                deref_addr = scanner._deref_checker.check(
                    instructions, start_idx, global_addr, addr, oid)
                print(f"    deref_addr from checker: {deref_addr}")
        else:
            print(f"    oid is None or not in _objects!")
