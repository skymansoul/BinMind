import subprocess, pathlib, sys

BASE = pathlib.Path('modules/analysis')
CVE_DIR = BASE / 'benchmark' / 'samples_uaf'
BUILD_TMP = BASE / 'eval' / 'build_tmp_uaf'

# CVE FN列表 — O2和Os分别分析
fn_cves = {
    'cve_2016_10150_kvm': ['Os'],
    'cve_2018_17182_vmac': ['Os'],
    'cve_2018_7566_alsa': ['O2'],
    'cve_2019_15291_brcm': ['Os'],
    'cve_2019_2215_binder': ['O2', 'Os'],
    'cve_2020_14386_afpacket': ['O2', 'Os'],
    'cve_2020_25211_netfilter': ['O2', 'Os'],
    'cve_2021_34866_ebpf': ['Os'],
}

for cve_name, opts in fn_cves.items():
    cve_dir = CVE_DIR / cve_name
    c_files = list(cve_dir.glob('*.c'))
    if not c_files:
        continue
    src = str(c_files[0])

    for opt in opts:
        binary = str(BUILD_TMP / f'{cve_name}_{opt}.exe')
        # 编译
        r = subprocess.run(
            ['x86_64-w64-mingw32-gcc', f'-{opt}', '-no-pie',
             '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
             '-w', '-o', binary, src],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"  {cve_name} {opt}: COMPILE FAILED")
            continue

        # 反汇编
        out = subprocess.run(['objdump', '-d', '-M', 'intel', binary],
                             capture_output=True, text=True, timeout=30).stdout
        insns = []
        for line in out.split('\n'):
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
                             'raw': line.strip()})
            except (ValueError, IndexError):
                continue

        # 统计malloc/free调用
        malloc_calls = [i for i, ins in enumerate(insns)
                       if ins['mnemonic'] == 'call' and ins['operands']
                       and 'malloc' in ins['operands'][0].lower()]
        free_calls = [i for i, ins in enumerate(insns)
                     if ins['mnemonic'] == 'call' and ins['operands']
                     and '<free' in ins['operands'][0].lower()]
        calloc_calls = [i for i, ins in enumerate(insns)
                       if ins['mnemonic'] == 'call' and ins['operands']
                       and 'calloc' in ins['operands'][0].lower()]
        realloc_calls = [i for i, ins in enumerate(insns)
                        if ins['mnemonic'] == 'call' and ins['operands']
                        and 'realloc' in ins['operands'][0].lower()]

        alloc_count = len(malloc_calls) + len(calloc_calls) + len(realloc_calls)
        free_count = len(free_calls)

        # 对比 O0 的数据
        binary_o0 = str(BUILD_TMP / f'{cve_name}_O0.exe')
        r0 = subprocess.run(
            ['x86_64-w64-mingw32-gcc', '-O0', '-no-pie',
             '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
             '-w', '-o', binary_o0, src],
            capture_output=True, text=True, timeout=30)
        out0 = subprocess.run(['objdump', '-d', '-M', 'intel', binary_o0],
                              capture_output=True, text=True, timeout=30).stdout
        insns0 = []
        for line in out0.split('\n'):
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
                insns0.append({'address': addr, 'mnemonic': mnem, 'operands': ops})
            except (ValueError, IndexError):
                continue

        m0 = sum(1 for ins in insns0 if ins['mnemonic'] == 'call' and ins['operands']
                 and 'malloc' in ins['operands'][0].lower())
        c0 = sum(1 for ins in insns0 if ins['mnemonic'] == 'call' and ins['operands']
                 and 'calloc' in ins['operands'][0].lower())
        f0 = sum(1 for ins in insns0 if ins['mnemonic'] == 'call' and ins['operands']
                 and '<free' in ins['operands'][0].lower())

        print(f"\n{cve_name} {opt}:")
        print(f"  O0: malloc={m0} calloc={c0} free={f0} total_insns={len(insns0)}")
        print(f"  {opt}: malloc={len(malloc_calls)} calloc={len(calloc_calls)} free={len(free_calls)} total_insns={len(insns)}")

        # 如果 O2/Os 下 free 数量为 0 但 O0 有 free — 说明 free 被优化掉了
        if free_count == 0 and f0 > 0:
            print(f"  >>> ROOT CAUSE: free() calls eliminated by {opt} optimization")
        if alloc_count == 0 and (m0 + c0) > 0:
            print(f"  >>> ROOT CAUSE: malloc/calloc() calls eliminated by {opt} optimization")
