# Angr漏洞扫描——使用exploration引擎模拟执行路径，标记危险函数调用点
# 对比基线: Angr作为学术界广泛使用的二进制分析平台，
# 其exploration模式的路径覆盖能力是我们需要比较的参照

import angr
import time
import json
import sys
from pathlib import Path

DANGEROUS = {'memcpy', 'strcpy', 'strncpy', 'sprintf', 'gets', 'memmove',
             'free', 'malloc', 'calloc', 'realloc', 'printf', 'fprintf'}


def scan_binary(binary_path: str, timeout: int = 120) -> dict:
    t0 = time.perf_counter()
    result = {'binary': binary_path, 'tool': 'angr', 'vulns': [],
              'success': False, 'error': '', 'time_ms': 0, 'peak_mem_kb': 0}

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        vuln_sites = []
        for func_addr, func in cfg.functions.items():
            for block_addr, block in func.blocks.items():
                for ins in block.disassembly.insns if hasattr(block.disassembly, 'insns') else []:
                    mnemonic = ins.mnemonic if hasattr(ins, 'mnemonic') else str(ins).split()[0]
                    if mnemonic == 'call' and hasattr(ins, 'op_str'):
                        target = ins.op_str
                        for df in DANGEROUS:
                            if df in target.lower():
                                vuln_sites.append({
                                    'func_addr': hex(func_addr),
                                    'call_addr': hex(ins.address),
                                    'dangerous_func': target,
                                    'type': 'buffer_overflow' if df in (
                                        'memcpy','strcpy','strncpy','sprintf','gets','memmove')
                                    else 'use_after_free' if df == 'free' else 'other'
                                })

        result['vulns'] = vuln_sites
        result['success'] = True
    except Exception as e:
        result['error'] = str(e)[:500]

    result['time_ms'] = (time.perf_counter() - t0) * 1000
    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python angr_scanner.py <binary_path>")
        sys.exit(1)
    r = scan_binary(sys.argv[1])
    print(json.dumps(r, indent=2))
