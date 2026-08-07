import sys, subprocess, re
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2016_10150_kvm_uaf_O0.exe'
out = subprocess.run(['objdump','-d','-M','intel', binary], capture_output=True, text=True).stdout

# Find the instruction that resolves to target=0x140001877 name=rax
for line in out.split('\n'):
    parts = line.strip().split('\t')
    if len(parts) < 3: continue
    try:
        addr = int(parts[0].strip().rstrip(':'), 16)
    except: continue
    
    mnem_part = parts[2].split()
    mnem = mnem_part[0] if mnem_part else ''
    ops_str = ' '.join(mnem_part[1:]) if len(mnem_part) > 1 else ''
    
    # Check if this call resolves to rax with target 0x140001877
    if mnem == 'call' and '140001877' in parts[2]:
        # Parse operands
        ops = []
        if len(mnem_part) > 1:
            for o in ' '.join(mnem_part[1:]).split(','):
                ops.append(o.strip())
        callee = ops[-1] if ops else ''
        print(f"  addr={addr:#x} mnem={mnem} ops={ops} callee={callee!r}")
        
        # Try parsing
        name_match = re.search(r'<([^>]+)>', callee)
        if name_match:
            name = name_match.group(1).split("@")[0]
        else:
            name = callee.strip("<>").split("@")[0].split(".")[-1]
        
        try:
            addr_part = callee.split()[0]
            target = int(addr_part, 16)
            print(f"    name={name!r} addr_part={addr_part!r} target={target:#x}")
        except:
            print(f"    name={name!r} (parse failed)")
