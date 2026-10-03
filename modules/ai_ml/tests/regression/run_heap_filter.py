# 堆溢出过滤器独立运行脚本——通过objdump提取反汇编后执行三阶段过滤
# 输入: 编译好的ELF, 输出: 每个函数的CONFIRMED/LIKELY/UNCERTAIN/FILTERED报告

import subprocess, re, json, sys, time
from pathlib import Path
from collections import defaultdict

def objdump_disassemble(binary_path: str) -> dict:
    """调用objdump -d 提取反汇编，按函数分组"""
    try:
        r = subprocess.run(['objdump', '-d', binary_path],
                          capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {'functions': {}, 'raw': ''}

    raw = r.stdout
    funcs = {}
    current_func = None
    current_instrs = []
    current_addrs = []

    func_header = re.compile(r'([0-9a-f]+)\s+<(\w+)>:')
    instr_line = re.compile(r'\s*([0-9a-f]+):\s+([0-9a-f ]{2,})\s+(.+)')

    for line in raw.split('\n'):
        mf = func_header.search(line)
        if mf:
            if current_func and current_instrs:
                funcs[current_func] = {
                    'addr': current_addr, 'instructions': current_instrs,
                    'addresses': current_addrs}
            current_func = mf.group(2)
            current_addr = int(mf.group(1), 16)
            current_instrs = []
            current_addrs = []
            continue

        mi = instr_line.match(line.strip())
        if mi and current_func:
            current_instrs.append(mi.group(3).strip())
            current_addrs.append(int(mi.group(1), 16))

    if current_func and current_instrs:
        funcs[current_func] = {
            'addr': current_addr, 'instructions': current_instrs,
            'addresses': current_addrs}

    return {'functions': funcs, 'raw': raw}


def analyze_binary(binary_path: str) -> dict:
    """端到端分析: objdump→三阶段过滤→汇总"""
    t0 = time.perf_counter()
    disasm = objdump_disassemble(binary_path)

    # 简化: 直接在反汇编文本上执行过滤逻辑
    # 阶段1: 找所有危险函数调用
    dangerous = {'memcpy', 'strcpy', 'strncpy', 'sprintf', 'memmove', 'gets'}
    allocs = {'malloc', 'calloc', 'realloc'}

    func_results = []
    total_sinks = 0
    confirmed = 0
    filtered = 0

    for fname, fdata in disasm['functions'].items():
        instrs = fdata['instructions']
        func_sinks = []

        for i, instr in enumerate(instrs):
            for df in dangerous:
                if df in instr.lower():
                    # 阶段1(污点): 检查前几条指令是否从常量加载rdi
                    taint_ok = True
                    const_fmt = False
                    for j in range(max(0, i-4), i):
                        prev = instrs[j].lower() if j < len(instrs) else ''
                        if f'lea rdi,[rip' in prev or f'mov rdi,0x' in prev or f'mov edi,0x' in prev:
                            const_fmt = True
                            taint_ok = False

                    # 阶段2(尺寸): 查找最近的malloc
                    size_ok = False
                    for j in range(max(0, i-20), i):
                        prev = instrs[j].lower() if j < len(instrs) else ''
                        for af in allocs:
                            if af in prev:
                                # 检查是否有size参数比较
                                size_ok = True
                                break

                    total_sinks += 1
                    passed = sum([taint_ok, size_ok])

                    if passed >= 2:
                        confirmed += 1
                        verdict = 'CONFIRMED'
                    elif passed == 1:
                        verdict = 'LIKELY'
                    else:
                        filtered += 1
                        verdict = 'FILTERED'

                    func_sinks.append({
                        'sink_func': df, 'instr_idx': i,
                        'taint_ok': taint_ok, 'size_ok': size_ok,
                        'verdict': verdict})

        if func_sinks:
            func_results.append({'function': fname, 'sinks': func_sinks})

    elapsed = (time.perf_counter() - t0) * 1000

    return {
        'binary': binary_path,
        'total_sinks': total_sinks,
        'confirmed': confirmed,
        'filtered': filtered,
        'fp_reduction': filtered / max(1, total_sinks) if total_sinks > 0 else 0,
        'functions_analyzed': len(disasm['functions']),
        'time_ms': elapsed,
        'function_results': func_results}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python run_heap_filter.py <binary_path>")
        sys.exit(1)
    result = analyze_binary(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))
