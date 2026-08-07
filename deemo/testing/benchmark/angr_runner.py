# Angr exploration模式漏洞点分析 —— 通过符号执行探索危险函数可达路径。
# 创建: 2026-08-02

import os, sys, time

ANGR_AVAILABLE = False
try:
    import angr, claripy
    ANGR_AVAILABLE = True
except ImportError:
    pass


DANGEROUS_FUNCTIONS = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
                        'memcpy', 'memmove', 'free', 'malloc', 'printf']


def run_angr_scan(binaries: dict, timeout_sec: int = 120) -> list:
    """用Angr exploration模式扫描所有二进制, 搜索危险函数调用。"""
    results = []
    if not ANGR_AVAILABLE:
        return results

    for name, info in binaries.items():
        if not isinstance(info, dict) or not info.get("success"):
            continue
        binary_path = info.get("binary_path", "")
        if not os.path.exists(binary_path):
            continue

        t0 = time.time()
        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast()
            findings = 0
            # 对入口函数做exploration, 搜索危险函数调用
            entry = proj.entry
            state = proj.factory.blank_state(addr=entry)
            simgr = proj.factory.simulation_manager(state)
            try:
                simgr.explore(find=lambda s: any(
                    proj.loader.find_symbol(fn) is not None
                    and s.addr == proj.loader.find_symbol(fn).rebased_addr
                    for fn in DANGEROUS_FUNCTIONS
                ), avoid=[], num_find=10)
                findings += len(simgr.found)
            except Exception:
                pass
            # 回退: CFG静态搜索
            if findings == 0:
                for func in cfg.functions.values():
                    for block in func.blocks:
                        for insn in block.capstone.insns:
                            if insn.mnemonic == 'call':
                                try:
                                    callee = cfg.functions.get(insn.operands[0].imm)
                                    if callee and callee.name in DANGEROUS_FUNCTIONS:
                                        findings += 1
                                except Exception:
                                    pass
            dt = time.time() - t0
            results.append(type('R', (), {
                'success': True, 'sample_name': name,
                'binary_path': binary_path,
                'stdout': f'Angr: {findings} dangerous calls found',
                'stderr': '', 'duration_sec': dt, 'exit_code': 0,
            })())
        except Exception as e:
            dt = time.time() - t0
            results.append(type('R', (), {
                'success': False, 'sample_name': name,
                'binary_path': binary_path,
                'stdout': '', 'stderr': str(e), 'duration_sec': dt,
                'exit_code': -1,
            })())

    return results
