import subprocess, json, pathlib

base = pathlib.Path('modules/analysis/benchmark/samples_uaf_safe')
manifest = json.load(open(base / 'manifest.json'))

# 对每个vuln变体O2样本，检查其用户函数是否被优化掉
for e in manifest:
    if e['variant'] != 'vuln' or e['opt'] != 'O2':
        continue
    binary = e['binary']
    if not pathlib.Path(binary).exists():
        continue
    out = subprocess.run(['objdump', '-d', '-M', 'intel', binary], capture_output=True, text=True, timeout=30).stdout
    lines = out.split('\n')
    # 找trigger函数
    for i, line in enumerate(lines):
        if 'trigger_' in line and '<' in line and '>:' in line:
            func_name = line.split('<')[1].split('>')[0]
            # 看这个函数有多少条实际指令（非nop非ret）
            func_lines = []
            for j in range(i+1, min(i+50, len(lines))):
                if lines[j].strip() == '':
                    break
                func_lines.append(lines[j].strip())
            actual_insns = [l for l in func_lines if l and not l.startswith('nop') and not l.startswith('ret') and '\t' in l]
            has_malloc = any('malloc' in l or 'calloc' in l for l in func_lines)
            has_free = any('free' in l for l in func_lines)
            status = 'OPTIMIZED_OUT' if len(actual_insns) == 0 else f'{len(actual_insns)} insns'
            print(f"{e['pattern']:25s} {func_name:45s} {status:15s} malloc={'Y' if has_malloc else 'N'} free={'Y' if has_free else 'N'}")
            if len(actual_insns) > 0 and len(actual_insns) < 10:
                for l in func_lines:
                    if '\t' in l:
                        print(f"    {l}")
            break
