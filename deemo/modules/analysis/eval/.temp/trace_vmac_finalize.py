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

# Check state before finalize
print("Before finalize:")
for oid, obj in det._objects.items():
    print(f"  obj {oid}: alloc={obj.alloc_addr:#x} freed_at={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free}")
print(f"  _addr_to_obj: {det._addr_to_obj}")
print(f"  _reg_to_obj: {det._reg_to_obj}")
print(f"  findings: {det._findings}")

findings = det.finalize(insns)
print(f"\nAfter finalize:")
for oid, obj in det._objects.items():
    print(f"  obj {oid}: alloc={obj.alloc_addr:#x} freed_at={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free}")
print(f"  findings: {findings}")
