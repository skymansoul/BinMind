"""调试alsa O2: 追踪检测器在error path上的对象追踪"""
import sys, os, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector

exe = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
out = subprocess.run(['objdump', '-d', '-M', 'intel', exe], capture_output=True, text=True, timeout=30).stdout

instructions = []
for line in out.split('\n'):
    parts = line.strip().split('\t')
    if len(parts) < 3: continue
    try:
        addr = int(parts[0].strip().rstrip(':'), 16)
        mnem_part = parts[2].split()
        mnem = mnem_part[0] if mnem_part else ''
        ops = [o.strip() for o in ' '.join(mnem_part[1:]).split(',') if o.strip()] if len(mnem_part) > 1 else []
        instructions.append({'address': addr, 'mnemonic': mnem, 'operands': ops})
    except: continue

print(f"Total instructions: {len(instructions)}")

# 打印用户函数区域
print("\n=== v_2018_7566_alsa_process ===")
for i, ins in enumerate(instructions):
    addr = ins.get('address', 0)
    if 0x140001760 <= addr <= 0x1400017ef:
        ops = ins.get('operands', [])
        print(f"  [{i:4d}] 0x{addr:x}: {ins.get('mnemonic','')} {', '.join(ops)}")

# 运行检测器并追踪状态
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(instructions)

print(f"\n=== _user_func_ranges ===")
for lo, hi in det._user_func_ranges:
    print(f"  0x{lo:x} - 0x{hi:x}")

# 逐指令分析，打印关键状态变化
TARGET_RANGE = range(0x140001760, 0x1400017f0)
for i, ins in enumerate(instructions):
    addr = ins.get('address', 0)
    if addr not in TARGET_RANGE:
        det.analyze_instruction(ins)
        continue
    
    mnem = ins.get('mnemonic', '')
    ops = ins.get('operands', [])
    
    # 在分析前打印状态
    r2o = {k: v for k, v in det._reg_to_obj.items()}
    s2o = {k: v for k, v in det._stack_to_obj.items()}
    a2o = {k: v for k, v in det._addr_to_obj.items()}
    
    det.analyze_instruction(ins)
    
    r2o2 = {k: v for k, v in det._reg_to_obj.items()}
    s2o2 = {k: v for k, v in det._stack_to_obj.items()}
    
    changed = r2o != r2o2 or s2o != s2o2
    marker = " ***" if changed else ""
    
    print(f"\n  [{i:4d}] 0x{addr:x}: {mnem} {', '.join(ops)}{marker}")
    if r2o2:
        print(f"    _reg_to_obj: {r2o2}")
    if s2o2:
        print(f"    _stack_to_obj: {s2o2}")
    if a2o:
        print(f"    _addr_to_obj: {a2o}")
    
    # 打印findings
    if det._findings:
        print(f"    FINDINGS: {det._findings}")

findings = det.finalize(instructions)
print(f"\n=== Final findings: {len(findings)} ===")
for f in findings:
    print(f"  {f}")

print(f"\n=== Objects ===")
for oid, o in det._objects.items():
    print(f"  oid={oid} alloc=0x{o.alloc_addr:x} freed_at={[hex(x) for x in o.freed_at]} nulled={o.nulled_after_free} use_after_free_at={[hex(x) for x in o.use_after_free_at]}")
