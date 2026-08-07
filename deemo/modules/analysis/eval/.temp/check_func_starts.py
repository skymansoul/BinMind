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

# Find all call targets
call_targets = set()
for ins in insns:
    if ins['mnemonic'] == 'call' and ins['operands']:
        callee = ins['operands'][-1]
        parts = callee.split()
        if parts:
            try:
                target = int(parts[0], 16)
                call_targets.add(target)
            except: pass

# Is main (0x140001760) a call target?
main_addr = 0x140001760
print(f"main at {main_addr:#x}, is call target: {main_addr in call_targets}")
print(f"Total call targets: {len(call_targets)}")

# What's the nearest call target after main?
targets_after_main = sorted(t for t in call_targets if t > main_addr)
if targets_after_main:
    print(f"Next call target after main: {targets_after_main[0]:#x} (gap={targets_after_main[0]-main_addr})")
else:
    print("No call target after main")

# What about all function start addresses from labels?
import re
func_start_addrs = set()
for line in out.split('\n'):
    line = line.strip()
    if line.endswith(">:") and "<" in line:
        try:
            addr = int(line.split()[0].rstrip(":"), 16)
            func_start_addrs.add(addr)
        except: pass

print(f"\nTotal function starts from labels: {len(func_start_addrs)}")
print(f"main in func_start_addrs: {main_addr in func_start_addrs}")

# Next function start after main
func_starts_after_main = sorted(s for s in func_start_addrs if s > main_addr)
if func_starts_after_main:
    print(f"Next function start after main: {func_starts_after_main[0]:#x}")
