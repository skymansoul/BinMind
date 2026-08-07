import subprocess, pathlib, json, sys, traceback
sys.path.insert(0, '.')

BASE = pathlib.Path('modules/analysis')
BUILD_TMP = BASE / 'eval' / 'build_tmp_uaf'

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
                         'func': func_name, 'raw': line.strip()})
        except (ValueError, IndexError):
            continue
    return insns

def run_uaf(binary_path):
    insns = disasm(binary_path)
    try:
        from modules.analysis.static.uaf_detect import UAFDetector
        det = UAFDetector(use_win64_abi=True)
        det.pre_analyze(insns)
        for ins in insns:
            det.analyze_instruction(ins)
        findings = det.finalize(insns)
        stats = det.stats()
        return stats, findings, insns, det
    except Exception as e:
        traceback.print_exc()
        return None, None, insns, None

# 分析 cve_2018_7566_alsa O2（free数不变但检测失败）
cve = 'cve_2018_7566_alsa'
for opt in ['O0', 'O2']:
    binary = str(BUILD_TMP / f'{cve}_{opt}.exe')
    src_dir = BASE / 'benchmark' / 'samples_uaf' / cve
    c_file = list(src_dir.glob('*.c'))[0]
    r = subprocess.run(
        ['x86_64-w64-mingw32-gcc', f'-{opt}', '-no-pie',
         '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
         '-w', '-o', binary, str(c_file)],
        capture_output=True, text=True, timeout=30)

    stats, findings, insns, det = run_uaf(binary)
    print(f"\n=== {cve} {opt} ===")
    print(f"  Stats: {stats}")
    print(f"  Findings: {len(findings) if findings else 0}")

    # 找所有malloc/free调用及其函数名
    for i, ins in enumerate(insns):
        if ins['mnemonic'] == 'call' and ins['operands']:
            target = ins['operands'][0]
            if any(x in target.lower() for x in ['<malloc', '<free', '<calloc', '<realloc']):
                func = target.split('<')[1].split('>')[0] if '<' in target else '?'
                # 找前5条指令
                context = insns[max(0,i-5):i+3]
                print(f"\n  {ins['func']} @ {ins['address']:#x}: call {func}")
                for c in context:
                    marker = '>>>' if c['address'] == ins['address'] else '   '
                    if det:
                        is_user = det._is_user_code(c['address'])
                        reg_map = {k:v for k,v in det._reg_to_obj.items()} if hasattr(det, '_reg_to_obj') else {}
                    else:
                        is_user = '?'
                        reg_map = {}
                    print(f"    {marker} {c['address']:#010x} [{c['func'][:20]:20s}] {c['mnemonic']:8s} {', '.join(c['operands'])}")
