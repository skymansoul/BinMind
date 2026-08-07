"""调试alsa O2: LocalFreeDerefScanner._trace_free_to_alloc"""
import sys, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_local_free_deref import LocalFreeDerefScanner
from modules.analysis.static.disasm_util import extract_func_name, norm_reg

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

scanner = LocalFreeDerefScanner(det)

# 找error path free at 0x1400017e0
for idx, ins in enumerate(instructions):
    if ins.get('address') == 0x1400017e0:
        print(f'Error path free at idx={idx}, addr=0x1400017e0')
        
        # 手动执行 _trace_free_to_alloc 步骤
        arg0 = det._arg_regs[0]
        print(f'arg0 = {arg0}')
        search_reg = arg0
        for k in range(idx - 1, max(-1, idx - 20), -1):
            i2 = instructions[k]
            mnem = i2.get('mnemonic', '').lower()
            ops = i2.get('operands', [])
            a2 = i2.get('address', 0)
            print(f'  [{k}] 0x{a2:x}: {mnem} {ops}  (search_reg={search_reg})')
            if mnem == 'call' and ops:
                func = extract_func_name(ops[0])
                print(f'    -> call to {func}')
                if func in det.ALLOC_FUNCS:
                    alloc_addr = i2.get('address', 0)
                    print(f'    -> ALLOC at 0x{alloc_addr:x}')
                    for oid, obj in det._objects.items():
                        if obj.alloc_addr == alloc_addr:
                            print(f'    -> Found oid={oid}')
                            break
                    break
                if func in scanner._FREE_FUNCS:
                    print(f'    -> FREE, breaking')
                    break
            if mnem == 'ret':
                print(f'    -> ret, breaking')
                break
            if mnem in ('mov', 'movzx', 'movsx') and len(ops) >= 2:
                dst = norm_reg(ops[0].strip())
                src = norm_reg(ops[1].strip())
                print(f'    -> dst={dst} src={src}')
                if dst == search_reg:
                    if src in ('rax', 'eax'):
                        search_reg = 'rax'
                        print(f'    -> search_reg changed to rax')
                    elif '[' in ops[1].lower():
                        from modules.analysis.static.uaf_local_free_deref import LocalFreeDerefScanner as L
                        slot = L._extract_stack_key(ops[1])
                        print(f'    -> stack slot: {slot}')
                        if slot is not None:
                            found_reg = L._find_stack_to_reg(instructions, k, slot)
                            print(f'    -> stack_to_reg: {found_reg}')
                            if found_reg:
                                search_reg = found_reg
        break

# 也在normal path free (0x1400017bf)
for idx, ins in enumerate(instructions):
    if ins.get('address') == 0x1400017bf:
        print(f'\nNormal path free at idx={idx}, addr=0x1400017bf')
        oid = scanner._trace_free_to_alloc(instructions, idx, 0x1400017bf)
        print(f'  _trace_free_to_alloc: {oid}')
        break
