"""Angr 对比实验脚本 — exploration 漏洞点分析.

设计决策:
  - 为什么用 exploration 而非 full symbolic execution:
    exploration 沿 CFG 做基本块遍历, 在每个 call 指令处检查是否为危险函数,
    比 full symbolic execution 快 ~10x, 适合批量对比实验。
  - 超时 120s: Angr 在 strip 后的中大型二进制 (>500KB) 容易路径爆炸,
    120s 是实用性上限。
"""

import json
import sys
import time
import os


def analyze_with_angr(binary_path: str) -> dict:
    """Angr CFG exploration + 危险函数检测."""
    result = {
        'binary': os.path.basename(binary_path),
        'vulns_found': 0,
        'vulns': [],
        'elapsed_sec': 0.0,
        'error': '',
    }

    try:
        import angr
        import claripy
    except ImportError:
        result['error'] = 'angr not installed'
        return result

    start = time.time()
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        dangerous_funcs = {
            'printf', 'sprintf', 'snprintf', 'fprintf',
            'malloc', 'free', 'realloc', 'calloc',
            'memcpy', 'strcpy', 'strcat', 'gets', 'scanf',
            'read', 'recv', 'recvfrom',
        }

        for func_addr, func in cfg.kb.functions.items():
            func_name = func.name.lower() if func.name else ''
            for block_addr in func.block_addrs_set:
                try:
                    block = proj.factory.block(block_addr)
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            # 解析 call 目标
                            targets = cfg.kb.functions.callgraph.get(
                                func_addr, set())
                            for target in targets:
                                target_name = cfg.kb.functions.get(
                                    target)
                                if target_name and target_name.name:
                                    tname = target_name.name.lower()
                                    for df in dangerous_funcs:
                                        if df in tname:
                                            result['vulns_found'] += 1
                                            result['vulns'].append({
                                                'func': func_name,
                                                'addr': hex(block_addr),
                                                'dangerous_call': tname,
                                            })
                except Exception:
                    continue

    except Exception as e:
        result['error'] = str(e)[:200]
    finally:
        result['elapsed_sec'] = round(time.time() - start, 2)

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'usage: run_angr.py <binary>'}))
        sys.exit(1)
    result = analyze_with_angr(sys.argv[1])
    print(json.dumps(result, indent=2))
