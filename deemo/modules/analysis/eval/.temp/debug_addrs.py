import sys, subprocess, re
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2016_10150_kvm_uaf_O0.exe'
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

from modules.analysis.static.uaf_pre_analyzer import UAFPreAnalyzer, _LIBC_NAMES
from modules.analysis.static.disasm_util import is_crt_func

pa = UAFPreAnalyzer()
pa.analyze_from_instructions(insns)

print("User func addrs:")
for a in sorted(pa._user_func_addrs):
    print(f"  {a:#x}")

print("\nAll func starts (first 20):")
for a in sorted(pa._all_func_starts)[:20]:
    print(f"  {a:#x}")
