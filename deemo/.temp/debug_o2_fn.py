import sys, subprocess, pathlib, json
sys.path.insert(0, '.')

base = pathlib.Path('modules/analysis/benchmark/samples_uaf_safe')
manifest = json.load(open(base / 'manifest.json'))

for e in manifest:
    if e['pattern'] == 'null_after_free' and e['variant'] == 'vuln' and e['opt'] == 'O2':
        print(f"Source: {e['source']}")
        print(f"Binary: {e['binary']}")
        binary = e['binary']
        break

out = subprocess.run(['objdump', '-d', '-M', 'intel', binary], capture_output=True, text=True, timeout=30).stdout
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
        insns.append({'address': addr, 'mnemonic': mnem, 'operands': ops})
    except (ValueError, IndexError):
        continue

print(f'Instructions: {len(insns)}')
# 打印所有用户函数区域 (非CRT) 的指令
for i, ins in enumerate(insns):
    if ins['mnemonic'] == 'call' and ins.get('operands'):
        target = ins['operands'][0]
        if '<malloc' in target or '<free' in target or '<calloc' in target:
            start = max(0, i-10)
            end = min(len(insns), i+15)
            for j in range(start, end):
                a = insns[j]
                marker = '>>>' if j == i else '   '
                print(f'{marker} {a["address"]:#010x} {a["mnemonic"]:8s} {", ".join(a["operands"])}')
            print('---')
