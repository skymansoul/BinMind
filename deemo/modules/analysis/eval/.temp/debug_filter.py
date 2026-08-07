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

from modules.analysis.static.disasm_util import is_crt_func
from modules.analysis.static.uaf_pre_analyzer import _LIBC_NAMES

# Show the call that resolves to each user func addr
for ins in insns:
    if ins.get("mnemonic") == "call" and ins.get("operands"):
        callee = ins["operands"][-1]
        name_match = re.search(r'<([^>]+)>', callee)
        if name_match:
            name = name_match.group(1).split("@")[0]
        else:
            name = callee.strip("<>").split("@")[0].split(".")[-1]
        
        if not name or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            continue
        
        try:
            target = int(callee.split()[0], 16)
        except:
            continue
        
        crt = is_crt_func(name)
        libc = name in _LIBC_NAMES
        dunder = name.startswith("__") and not name.startswith("__user_")
        is_user = not crt and not libc and not dunder
        
        if is_user and target in (0x14000162f, 0x140001877, 0x140009600):
            print(f"BUG: {name} target={target:#x} crt={crt} libc={libc} dunder={dunder}")
        elif target in (0x14000162f, 0x140001877, 0x140009600):
            print(f"OK:   {name} target={target:#x} crt={crt} libc={libc} dunder={dunder}")
