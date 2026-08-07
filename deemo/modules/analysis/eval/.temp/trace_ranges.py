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

from modules.analysis.static.uaf_detect import UAFDetector

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

print("All user_func_ranges:")
for lo, hi in det._user_func_ranges:
    print(f"  {lo:#x} - {hi:#x} ({hi-lo} bytes)")

print(f"\nmain at 0x140001760 = {0x140001760}")
print(f"_is_user_code(0x140001760) = {det._is_user_code(0x140001760)}")
print(f"_is_user_code(0x140001772) = {det._is_user_code(0x140001772)}")  # malloc
print(f"_is_user_code(0x140001788) = {det._is_user_code(0x140001788)}")  # free
print(f"_is_user_code(0x1400017aa) = {det._is_user_code(0x1400017aa)}")  # printf
