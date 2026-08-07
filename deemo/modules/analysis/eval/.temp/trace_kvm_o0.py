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

for ins in insns:
    addr = ins['address']
    if 0x140001760 <= addr <= 0x1400017b5:
        before = dict(det._reg_to_obj)
        det.analyze_instruction(ins)
        after = det._reg_to_obj
        if before != after or ins['mnemonic'] in ('call','ret'):
            print(f'{addr:#x} {ins["mnemonic"]:8s} {str(ins["operands"]):50s} reg={dict(after)}')
