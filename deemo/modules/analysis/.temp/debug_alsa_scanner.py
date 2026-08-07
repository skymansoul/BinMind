"""调试alsa O2: GlobalFreeScanner对error path free的追踪"""
import sys, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.disasm_util import extract_func_name

exe = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
out = subprocess.run(['objdump', '-d', '-M', 'intel', exe], capture_output=True, text=True, timeout=30).stdout

instructions = []
for line in out.split('\n'):
    parts = line.strip().split('\t')
    if len(parts) < 3: continue
    try:
        addr = int(parts[0].strip().rstrip(':'), 16)
        mnem_part = parts[2].split()
        mnem = mnem_part[0] if mnem_part else ''
        ops = [o.strip() for o in ' '.join(mnem_part[1:]).split(',') if o.strip()] if len(mnem_part) > 1 else []
        instructions.append({'address': addr, 'mnemonic': mnem, 'operands': ops})
    except: continue

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(instructions)
for ins in instructions:
    det.analyze_instruction(ins)

scanner = det._finalizer._global_scanner

# error path free at 0x1400017e0
for idx, ins in enumerate(instructions):
    if ins.get('address') == 0x1400017e0:
        print(f'Error path free at idx={idx}')
        global_addr = scanner._trace_free_to_global(instructions, idx, 0x1400017e0)
        print(f'  _trace_free_to_global: {global_addr}')
        
        for j in range(idx-1, max(-1, idx-10), -1):
            i2 = instructions[j]
            a2 = i2['address']
            print(f'  [{j}] 0x{a2:x}: {i2["mnemonic"]} {i2["operands"]}')
            mn = i2.get('mnemonic','').lower()
            if mn == 'call': break
        break

# normal path free at 0x1400017bf
for idx, ins in enumerate(instructions):
    if ins.get('address') == 0x1400017bf:
        print(f'\nNormal path free at idx={idx}')
        global_addr = scanner._trace_free_to_global(instructions, idx, 0x1400017bf)
        print(f'  _trace_free_to_global: {global_addr}')
        
        for j in range(idx-1, max(-1, idx-10), -1):
            i2 = instructions[j]
            a2 = i2['address']
            print(f'  [{j}] 0x{a2:x}: {i2["mnemonic"]} {i2["operands"]}')
            mn = i2.get('mnemonic','').lower()
            if mn == 'call': break
        break

print(f'\n_addr_to_obj: {dict(det._addr_to_obj)}')
print(f'_objects:')
for oid, o in det._objects.items():
    print(f'  oid={oid} alloc=0x{o.alloc_addr:x} freed_at={[hex(x) for x in o.freed_at]}')
