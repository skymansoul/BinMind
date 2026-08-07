import sys, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2016_10150_kvm_uaf_O0.exe'
out = subprocess.run(['objdump','-d','-M','intel', binary], capture_output=True, text=True).stdout

# Check if function labels are captured in instructions
lines_with_labels = [l for l in out.split('\n') if '<' in l and '>:' in l]
print(f"Function label lines: {len(lines_with_labels)}")
for l in lines_with_labels[:15]:
    print(f"  {l.strip()}")

# Check what the structured parser sees
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

# Check the operands of call instructions - do they have <func_name>?
calls = [i for i in insns if i['mnemonic'] == 'call']
print(f"\nCall instructions: {len(calls)}")
for c in calls[:15]:
    print(f"  {c['address']:#x}: {c['operands']}")
