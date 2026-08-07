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

# Patch to trace
original = UAFPreAnalyzer.analyze_from_instructions

def patched(self, instructions):
    self._ins_by_addr = {ins.get("address", 0): ins for ins in instructions}
    self._user_func_addrs = set()
    all_starts = set()
    
    for ins in instructions:
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
                addr_part = callee.split()[0]
                target = int(addr_part, 16)
                all_starts.add(target)
            except (ValueError, IndexError):
                pass

            crt = is_crt_func(name)
            libc = name in _LIBC_NAMES
            dunder = name.startswith("__") and not name.startswith("__user_")
            
            if target in (0x14000162f, 0x140001877, 0x140009600):
                print(f"  target={target:#x} name={name} crt={crt} libc={libc} dunder={dunder} -> {'SKIP' if (crt or libc or dunder) else 'ADD'}")

            if crt or libc or dunder:
                continue

            try:
                self._user_func_addrs.add(target)
            except (ValueError, IndexError):
                pass

    if instructions:
        first = instructions[0].get("address", 0)
        all_starts.add(first)
    self._all_func_starts = all_starts

UAFPreAnalyzer.analyze_from_instructions = patched

from modules.analysis.static.uaf_detect import UAFDetector
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
print(f"\nUser func addrs: {sorted(hex(a) for a in det._pre_analyzer._user_func_addrs)}")
