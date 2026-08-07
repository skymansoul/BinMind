import subprocess, pathlib, sys, traceback, json
sys.path.insert(0, '.')

BASE = pathlib.Path('modules/analysis')
BUILD_TMP = BASE / 'eval' / 'build_tmp_uaf'
CVE_DIR = BASE / 'benchmark' / 'samples_uaf'

def disasm(binary_path):
    out = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
                         capture_output=True, text=True, timeout=30).stdout
    insns = []
    func_name = ''
    for line in out.split('\n'):
        if line.startswith('0') and '<' in line and '>:' in line:
            func_name = line.split('<')[1].split('>')[0]
            continue
        parts = line.strip().split('\t')
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0].strip().rstrip(':'), 16)
            mnem_part = parts[2].split()
            mnem = mnem_part[0] if mnem_part else ''
            ops = []
            if len(mnem_part) > 1:
                for o in ' '.join(mnem_part[1:]).split(','):
                    ops.append(o.strip())
            insns.append({'address': addr, 'mnemonic': mnem, 'operands': ops,
                         'func': func_name})
        except (ValueError, IndexError):
            continue
    return insns

# 分析所有CVE FN: 对比O0 vs O2/Os 的关键差异
fn_list = [
    ('cve_2016_10150_kvm', 'Os'),
    ('cve_2018_17182_vmac', 'Os'),
    ('cve_2018_7566_alsa', 'O2'),
    ('cve_2019_15291_brcm', 'Os'),
    ('cve_2019_2215_binder', 'O2'),
    ('cve_2020_14386_afpacket', 'O2'),
    ('cve_2020_25211_netfilter', 'O2'),
    ('cve_2021_34866_ebpf', 'Os'),
]

for cve_name, opt in fn_list:
    cve_dir = CVE_DIR / cve_name
    c_files = list(cve_dir.glob('*.c'))
    if not c_files:
        continue
    src = str(c_files[0])

    # 编译O0和目标opt
    for o in ['O0', opt]:
        binary = str(BUILD_TMP / f'{cve_name}_{o}.exe')
        r = subprocess.run(
            ['x86_64-w64-mingw32-gcc', f'-{o}', '-no-pie',
             '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
             '-w', '-o', binary, src],
            capture_output=True, text=True, timeout=30)

    # 运行检测
    results = {}
    for o in ['O0', opt]:
        binary = str(BUILD_TMP / f'{cve_name}_{o}.exe')
        insns = disasm(binary)
        try:
            from modules.analysis.static.uaf_detect import UAFDetector
            det = UAFDetector(use_win64_abi=True)
            det.pre_analyze(insns)
            for ins in insns:
                det.analyze_instruction(ins)
            findings = det.finalize(insns)
            stats = det.stats()
            results[o] = {'stats': stats, 'findings': len(findings), 'det': det, 'insns': insns}
        except Exception as e:
            results[o] = {'error': str(e)}

    o0 = results.get('O0', {})
    ox = results.get(opt, {})

    print(f"\n{'='*60}")
    print(f"{cve_name} {opt}")
    print(f"  O0: alloc={o0.get('stats',{}).get('objects_allocated','?')} "
          f"freed={o0.get('stats',{}).get('objects_freed','?')} "
          f"uaf={o0.get('stats',{}).get('uaf_detected','?')} "
          f"findings={o0.get('findings','?')}")
    print(f"  {opt}: alloc={ox.get('stats',{}).get('objects_allocated','?')} "
          f"freed={ox.get('stats',{}).get('objects_freed','?')} "
          f"uaf={ox.get('stats',{}).get('uaf_detected','?')} "
          f"findings={ox.get('findings','?')}")

    # 找用户函数中的关键模式差异
    if 'det' in ox and 'det' in o0:
        ox_det = ox['det']
        o0_det = o0['det']
        ox_insns = ox['insns']
        o0_insns = o0['insns']

        # 在 O2/Os 中找用户函数区域的 free 调用
        for i, ins in enumerate(ox_insns):
            if ins['mnemonic'] != 'call' or not ins['operands']:
                continue
            if '<free' not in ins['operands'][0].lower():
                continue
            if not ox_det._is_user_code(ins['address']):
                continue
            # 检查free之后的指令——是否有置NULL
            context = ox_insns[i:min(i+10, len(ox_insns))]
            has_null = False
            has_deref = False
            for c in context:
                raw = ' '.join(c['operands']).lower()
                if '0x0' in raw and 'rip' in raw and 'mov' in c['mnemonic'].lower():
                    if not ox_det._is_user_code(c['address']):
                        continue
                    has_null = True
                if c['mnemonic'] in ('movzx', 'movsx') and '[' in ' '.join(c['operands']).lower():
                    if ox_det._is_user_code(c['address']):
                        reg = c['operands'][1].strip().lower()
                        for prefix in ('qword ptr ', 'dword ptr ', 'byte ptr ', 'word ptr '):
                            if reg.startswith(prefix):
                                reg = reg[len(prefix):]
                                break
                        inner = reg[reg.find('[')+1:reg.rfind(']')] if '[' in reg else ''
                        base = inner.split('+')[0].split('-')[0].strip()
                        if base in ('rax', 'rbx', 'rcx', 'rdx'):
                            has_deref = True

            if has_null or has_deref:
                print(f"  free@{ins['address']:#x} [{ins['func'][:25]}]: "
                      f"null_after={has_null} deref_after={has_deref}")

    # 对比O0中同一函数
    if 'det' in o0:
        o0_det = o0['det']
        o0_insns = o0['insns']
        for i, ins in enumerate(o0_insns):
            if ins['mnemonic'] != 'call' or not ins['operands']:
                continue
            if '<free' not in ins['operands'][0].lower():
                continue
            if not o0_det._is_user_code(ins['address']):
                continue
            context = o0_insns[i:min(i+5, len(o0_insns))]
            for c in context:
                if c['mnemonic'] in ('movzx', 'movsx') and ox_det._is_user_code(c['address']):
                    print(f"  [O0] free@{ins['address']:#x} → deref@{c['address']:#x} "
                          f"[{c['func'][:25]}] {c['mnemonic']} {', '.join(c['operands'])}")
