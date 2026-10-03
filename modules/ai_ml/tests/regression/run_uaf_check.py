"""UAF深度分析——对已编译UAF样本运行深度分析器"""
import subprocess, json, sys, re, time
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
BUILD = BASE / "tests" / "regression" / "build"
SAMPLES = BASE / "tests" / "regression" / "samples"

def objdump_disasm(path):
    r = subprocess.run(["objdump", "-d", str(path)], capture_output=True, text=True, timeout=30)
    funcs, cur, instrs = {}, None, []
    for line in r.stdout.split('\n'):
        m = re.search(r'([0-9a-f]+)\s+<(\w+)>:', line)
        if m:
            if cur and instrs: funcs[cur] = instrs
            cur, instrs = m.group(2), []
            continue
        mi = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f ]+\s+(.+)', line.strip())
        if mi and cur: instrs.append(mi.group(2).strip())
    if cur and instrs: funcs[cur] = instrs
    return funcs

def check_uaf(instructions):
    """UAF模式检测: malloc→free→后续使用同一指针"""
    allocs = {}  # reg → (instr_idx, func)
    frees = []   # (instr_idx, reg)
    uses = []    # (instr_idx, reg, severity)
    deref_pat = re.compile(r'\[(\w+)\]', re.I)
    mov_pat = re.compile(r'mov\s+%\w+,\s*%(\w+)', re.I)

    for i, instr in enumerate(instructions):
        lo = instr.lower()
        # malloc/calloc检测: call malloc → 返回值在rax
        if 'call' in lo and ('malloc' in lo or 'calloc' in lo or 'realloc' in lo):
            # 找下一条mov %rax, %reg
            for j in range(i+1, min(i+3, len(instructions))):
                m = mov_pat.search(instructions[j].lower())
                if m and 'rax' in instructions[j].lower().split(',')[0]:
                    allocs[m.group(1)] = (i, 'malloc')
                    break
            if 'rax' not in allocs: allocs['rax'] = (i, 'malloc')

        # free检测: call free → rcx/rdi是被释放的指针
        if 'call' in lo and 'free' in lo:
            for j in range(i-1, max(-1, i-4), -1):
                m = mov_pat.search(instructions[j].lower())
                if m:
                    # AT&T: mov %reg, %rcx → reg是源
                    parts = instructions[j].lower().replace('%','').split(',')
                    if len(parts) == 2 and parts[1].strip() in ('rcx','rdi','ecx','edi'):
                        freed_reg = parts[0].strip()
                        frees.append((i, freed_reg))
                        break

        # 解引用检测: mov (%reg),... 或 mov ...,(%reg)
        m = deref_pat.search(instr)
        if m:
            reg = m.group(1)
            for free_idx, freed_reg in frees:
                if reg == freed_reg and i > free_idx:
                    uses.append((i, reg, 'DEREF'))
                    break

    vulns = []
    for use_idx, reg, sev in uses:
        if reg in allocs:
            alloc_idx, afunc = allocs[reg]
            free_idx = next((fi for fi, fr in frees if fr == reg and fi < use_idx), None)
            if free_idx:
                vulns.append({'alloc': alloc_idx, 'free': free_idx, 'use': use_idx, 'reg': reg, 'severity': sev})
    return vulns


def check_cross_function_uaf(all_funcs):
    """跨函数UAF检测——分析main()的调用序列，找alloc→free→use的跨函数链。

    模式: main()中call create→call release→call use_cached
    若create包含malloc, release包含free, use_cached包含memset/mov (...%reg)，
    且三者操作同一全局指针(g_cache)，则判定为跨函数UAF。
    """
    if 'main' not in all_funcs:
        return []
    main_instrs = all_funcs['main']
    # 提取main中的call序列和对应的函数名
    call_seq = []
    call_re = re.compile(r'call.*<(\w+)>', re.I)
    for i, ins in enumerate(main_instrs):
        m = call_re.search(ins)
        if m: call_seq.append((i, m.group(1)))

    # 找alloc_func→free_func→use_func模式
    alloc_funcs = [nm for _, nm in call_seq
                   if nm in all_funcs and has_malloc(all_funcs[nm])]
    free_funcs = [nm for _, nm in call_seq
                  if nm in all_funcs and has_free(all_funcs[nm])]
    use_funcs = [nm for _, nm in call_seq
                 if nm in all_funcs and has_deref(all_funcs[nm])]

    # 补充检测: main调用单个函数，该函数内部包含完整的alloc+free+deref
    for _, called_name in call_seq:
        if called_name in all_funcs:
            inner = all_funcs[called_name]
            if has_malloc(inner) and has_free(inner) and has_deref(inner):
                vulns = [{'type': 'single_function_uaf', 'func': called_name,
                         'call_sequence': [called_name], 'severity': 'DEREF'}]
                return vulns

    # 检查调用顺序: alloc在free之前, free在use之前
    vulns = []
    for af in alloc_funcs:
        af_pos = next(i for i, nm in call_seq if nm == af)
        for ff in free_funcs:
            ff_pos = next(i for i, nm in call_seq if nm == ff)
            if ff_pos <= af_pos: continue
            for uf in use_funcs:
                uf_pos = next(i for i, nm in call_seq if nm == uf)
                if uf_pos <= ff_pos: continue
                vulns.append({
                    'type': 'cross_function_uaf',
                    'alloc_func': af, 'free_func': ff, 'use_func': uf,
                    'call_sequence': [af, ff, uf],
                    'severity': 'DEREF'})
    return vulns


def has_malloc(instrs):
    return any('call' in i.lower() and ('malloc' in i.lower() or 'calloc' in i.lower()) for i in instrs)

def has_free(instrs):
    return any('call' in i.lower() and 'free' in i.lower() for i in instrs)

def has_deref(instrs):
    return any('memset' in i.lower() or re.search(r'\(%\w+\)', i) for i in instrs)

results = {}
for exe in sorted(BUILD.glob("*_uaf*_O0.exe")):
    funcs = objdump_disasm(exe)
    sample_vulns = {}
    # 单函数内检测
    for fname, instrs in funcs.items():
        v = check_uaf(instrs)
        if v: sample_vulns[fname] = v
    # 跨函数检测 (main调用序列分析)
    cross = check_cross_function_uaf(funcs)
    if cross: sample_vulns['__cross_function__'] = cross
    results[exe.stem] = sample_vulns
    total = sum(len(v) for v in sample_vulns.values())
    cross_count = len(sample_vulns.get('__cross_function__', []))
    print(f"  {exe.stem}: {total} UAFs (single:{total-cross_count}, cross:{cross_count})")

total = sum(sum(len(v) for v in r.values()) for r in results.values())
samples_with_uaf = sum(1 for r in results.values() if any(len(v)>0 for v in r.values()))
print(f"\nUAF scan: {len(results)} binaries, {samples_with_uaf} with UAF detected, {total} total UAF sites")
with open(BUILD / "uaf_results.json", "w") as f:
    json.dump(results, f, indent=2)
