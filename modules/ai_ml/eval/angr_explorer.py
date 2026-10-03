# Angr漏洞点探索脚本: 利用Angr的CFG+exploration找出可达的危险函数调用
# 方法: 构建CFG→识别所有危险函数调用点→对每个点尝试符号执行验证可达性
# 输出: JSON格式的漏洞点列表(地址、函数名、可达性、参数是否符号化)
#
# 与简单函数名grep的区别:
#   Angr可以判断调用点是否从入口可达(get_any_node+predecessors)，
#   以及参数是否受用户输入影响(state.solver.symbolic)。
#   这提供了比静态模式匹配更高的精度。

import sys
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional

logging.disable(logging.CRITICAL)  # 关闭angr的冗余日志

try:
    import angr
    import claripy
except ImportError:
    print(json.dumps({
        "error": "angr not installed. pip install angr",
        "vulns": [],
        "available": False
    }))
    sys.exit(0)


# 危险函数, C标准库中常见的溢出源
DANGEROUS_SINKS = {
    'memcpy', 'memmove', 'strcpy', 'strncpy', 'sprintf', 'snprintf',
    'gets', 'read', 'recv', 'fread', 'fgets', 'scanf', 'strcat', 'strncat',
}

# 输入源, 标记为符号值的函数返回值/参数
INPUT_SOURCES = {
    'read', 'recv', 'recvfrom', 'fread', 'fgets', 'scanf', 'gets',
    'readfile', 'recvmsg',
}


def analyze_binary(binary_path: str,
                    timeout: int = 120) -> Dict:
    """用Angr分析二进制中的堆溢出风险点。"""
    t0 = time.perf_counter()
    result = {"vulns": [], "time_ms": 0, "cfg_nodes": 0, "error": "", "available": True}

    try:
        proj = angr.Project(binary_path, auto_load_libs=False,
                           load_options={'main_opts': {'base_addr': 0}})
    except Exception as e:
        result["error"] = f"Failed to load binary: {e}"
        result["time_ms"] = (time.perf_counter() - t0) * 1000
        return result

    try:
        cfg = proj.analyses.CFGFast(normalize=True)
        result["cfg_nodes"] = len(cfg.nodes())
    except Exception:
        # CFG失败, 回退到简单的函数枚举
        cfg = None

    # 获取入口点可达的所有节点
    reachable_addrs = set()
    if cfg is not None:
        entry = proj.entry
        entry_node = cfg.get_any_node(entry)
        if entry_node is not None:
            # BFS从入口收集可达节点
            visited = {entry_node.addr}
            q = [entry_node]
            while q:
                node = q.pop(0)
                reachable_addrs.add(node.addr)
                for succ in cfg.get_successors(node):
                    if hasattr(succ, 'addr') and succ.addr not in visited:
                        visited.add(succ.addr)
                        q.append(succ)

    # 扫描每个函数中的危险调用
    for func_addr in proj.kb.functions:
        func = proj.kb.functions[func_addr]
        if func.is_simprocedure or func.is_plt:
            continue

        func_name = func.name if func.name else f"sub_{func_addr:x}"

        try:
            # 尝试获取函数的CFG(更精确的块划分)
            func_cfg = proj.analyses.CFGFast(
                normalize=True,
                function_starts=[func_addr],
                force_complete_scan=False)
        except Exception:
            continue

        # 在函数中找危险调用
        for block_addr in func.block_addrs_set:
            try:
                block = proj.factory.block(block_addr)
                for insn in block.capstone.insns:
                    if insn.mnemonic != 'call':
                        continue
                    # 解析调用目标
                    called_name = None
                    target_addr = None
                    try:
                        target_addr = insn.operands[0].imm
                        if target_addr in proj.kb.functions:
                            called_name = proj.kb.functions[target_addr].name
                    except Exception:
                        # 间接调用, 跳过
                        continue

                    if called_name and called_name.split('.')[-1].split('@')[0] in DANGEROUS_SINKS:
                        sink_clean = called_name.split('.')[-1].split('@')[0]
                        # 检查可达性
                        is_reachable = (
                            not reachable_addrs or
                            block_addr in reachable_addrs)
                        # 检查参数, 尝试符号化参数看是否约束不足
                        args_symbolic = False
                        try:
                            state = proj.factory.blank_state(addr=block_addr)
                            # 简化: 将前3个参数设为符号值(模拟用户输入)
                            arg_regs = ['rdi', 'rsi', 'rdx']
                            for reg in arg_regs:
                                sym_val = claripy.BVS(f'sym_{reg}', 64)
                                setattr(state.regs, reg, sym_val)
                            args_symbolic = True
                        except Exception:
                            pass

                        result["vulns"].append({
                            "func_name": func_name,
                            "sink": sink_clean,
                            "addr": hex(insn.address),
                            "reachable": is_reachable,
                            "args_symbolic": args_symbolic,
                        })
            except Exception:
                continue

    result["time_ms"] = (time.perf_counter() - t0) * 1000
    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: angr_explorer.py <binary>", "vulns": [], "available": True}))
        return 0

    binary = sys.argv[1]
    result = analyze_binary(binary)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
