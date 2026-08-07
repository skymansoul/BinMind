import sys, subprocess
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

# What calls 0x140001768?
for ins in insns:
    if ins['mnemonic'] == 'call' and ins['operands']:
        callee = ins['operands'][-1]
        parts = callee.split()
        if parts:
            try:
                target = int(parts[0], 16)
                if target == 0x140001768:
                    print(f"Call to 0x140001768 from {ins['address']:#x}: {ins['operands']}")
            except: pass

# Is 0x140001768 a function label?
import re
for line in out.split('\n'):
    if '140001768' in line:
        print(f"  {line.strip()}")
