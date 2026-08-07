import sys, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_17182_vmac_Os.exe'
out = subprocess.run(['objdump','-d','-M','intel', binary], capture_output=True, text=True).stdout

insns = []
for line in out.split('\n'):
    parts = line.strip().split('\t')
    if len(parts) < 3: continue
    try:
        addr = int(parts[0].strip().rstrip(':'), 16)
        mnem_part = parts[2].split()
        mnem = mnem_part[0] if mnem_part else ''
        ops = []
        if len(mnem_part) > 1:
            for o in ' '.join(mnem_part[1:]).split(','):
                ops.append(o.strip())
        insns.append({'address': addr, 'mnemonic': mnem, 'operands': ops})
    except: continue

from modules.analysis.static.uaf_detect import UAFDetector
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)

# Check: what does GlobalFreeScanner find?
from modules.analysis.static.uaf_global_free_scanner import GlobalFreeScanner
scanner = GlobalFreeScanner(det)

# Trace the scanner
global_addr = 0x140009080
free_addr = 0x140001767

# Find start_idx
start_idx = None
for idx, ins in enumerate(insns):
    addr = ins.get("address", 0)
    if addr > free_addr and det._is_user_code(addr):
        start_idx = idx
        break

print(f"free_addr=0x{free_addr:x}, start_idx={start_idx}")
print(f"Instruction at start_idx: {insns[start_idx]}")

# Find the store instruction
for j in range(start_idx, min(start_idx + 50, len(insns))):
    ins = insns[j]
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    addr = ins.get("address", 0)
    
    # Check is_reassign
    is_reassign = scanner._deref_checker._is_reassign_to_new(
        insns, j, ins, ops, mnem, addr, global_addr, start_idx)
    
    # Check for jmp between start_idx and j
    has_jmp = False
    for k in range(start_idx, j):
        kmn = insns[k].get("mnemonic", "").lower()
        if kmn == "jmp":
            has_jmp = True
            break
    
    if mnem == "mov" and ops and "rip" in ops[0].lower() and "[" in ops[0].lower():
        from modules.analysis.static.disasm_util import resolve_rip_relative
        gaddr = resolve_rip_relative(ins, ops[0], addr)
        gaddr_str = hex(gaddr) if gaddr else "None"
        print(f"  j={j} addr={addr:#x} {mnem} {ops} gaddr={gaddr_str} is_reassign={is_reassign} has_jmp_before={has_jmp}")

# Now run the full scan
print("\nRunning full GlobalFreeScanner:")
new_findings = scanner.scan(insns)
print(f"New findings: {new_findings}")
