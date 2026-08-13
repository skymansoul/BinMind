# -*- coding: utf-8 -*-
"""Angr 分析助手 — 参数提取、寄存器族归一化、CFG 兼容与可达判定.

供 eval/angr_explorer.py 使用; 常量与助手按依赖关系内聚, 与主分析器解耦.
"""

import re
from typing import Dict, List, Optional, Tuple

_DANGEROUS_WRITES = {
    'memcpy', 'memmove', 'strcpy', 'strncpy', 'sprintf',
    'snprintf', 'strcat', 'strncat', 'gets', 'fgets',
    'read', 'fread', 'recv', 'recvfrom',
}

_ALLOC_FUNCS = {
    'malloc', 'calloc', 'realloc', '_Znwm', '_Znam',
}

# x86-64 调用约定: SysV=rdi/rsi/rdx/rcx/r8/r9, Win64=rcx/rdx/r8/r9/r10/r11
_ARG_REGS_SYSV = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_ARG_REGS_WIN64 = ['rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']
# alloc size 参数索引: malloc/calloc/realloc → arg0; write size 参数索引
# memcpy/memmove/memset → arg2; snprintf → arg1
_ALLOC_SIZE_ARG = {'malloc': 0, 'calloc': 0, 'realloc': 1, '_znwm': 0, '_znam': 0}
_WRITE_SIZE_ARG = {'memcpy': 2, 'memmove': 2, 'memset': 2, 'snprintf': 1,
                   'strncpy': 2, 'strncat': 2}


def extract_arg_from_disasm(proj, cfg, call_addr: int,
                            target_reg: str) -> int:
    """在 call 指令所在基本块及其前驱块中反向搜索目标寄存器的立即数赋值.

    搜索策略:
      1. 取 call 所在 CFG 节点, 遍历其块指令 (含 call 自身)
      2. 若本块未找到, 沿前驱块回溯 (最多 3 层)
      3. 匹配 mov/push 到 target_reg (含子寄存器归一化) 的立即数
    """
    node = cfg_node(cfg, call_addr)
    seen_blocks = set()
    for depth in range(4):
        if node is None or node.addr in seen_blocks:
            break
        seen_blocks.add(node.addr)
        try:
            block = node.block
            if block is not None:
                insns = list(block.capstone.insns)
                for insn in reversed(insns):
                    if insn.address > call_addr and depth == 0:
                        continue
                    mnemonic = insn.mnemonic.lower()
                    op_str = insn.op_str.lower()
                    if mnemonic in ('mov', 'movl', 'movq', 'li', 'ldr'):
                        dst = op_str.split(',')[0].strip()
                        if reg_family(dst) == target_reg:
                            imm = parse_immediate_from_operand(
                                op_str.split(',')[-1].strip())
                            if imm > 0:
                                return imm
                    if mnemonic == 'push':
                        imm = parse_immediate_from_operand(op_str)
                        if imm > 0:
                            return imm
        except Exception:
            pass
        # 前驱节点
        try:
            preds = cfg.get_predecessors(node.addr)
        except Exception:
            preds = []
        node = preds[0] if preds else None
    return 0


def reg_family(reg: str) -> str:
    """子寄存器 → 64 位族名."""
    reg = reg.strip().strip('[]').lower()
    fam = {
        'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
        'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
        'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
        'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
        'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    }
    if reg in fam:
        return fam[reg]
    for i in range(8, 16):
        b = f'r{i}'
        if reg == b or reg == f'r{i}d' or reg == f'r{i}w' or reg == f'r{i}b':
            return b
    return reg


def cfg_node(cfg, addr):
    """定位包含 addr 的 CFG 基本块节点 (跨 angr 版本)."""
    for meth in ('get_any_node', 'get_node'):
        try:
            n = getattr(cfg, meth)(addr)
            if n is not None:
                return n
        except Exception:
            continue
    # 包含地址的块: 遍历节点按地址区间匹配
    try:
        nodes = list(cfg.graph.nodes())
    except Exception:
        return None
    for n in nodes:
        try:
            b = n.block
            if b is None:
                continue
            size = b.bytes.popcount() if hasattr(b.bytes, 'popcount') else 0
            if n.addr <= addr < n.addr + max(size, len(b.bytes or b'') or 1):
                return n
        except Exception:
            if n.addr <= addr < n.addr + 64:
                return n
    return None


def parse_immediate_from_operand(op: str) -> int:
    """从操作数字符串解析立即数."""
    op = op.strip()
    # 十六进制
    if op.startswith('0x') or op.startswith('0X'):
        try: return int(op, 16)
        except ValueError: return 0
    # 十进制或偏移表示 [rbp-0x10]
    m = re.search(r'(0x[0-9a-fA-F]+|\d+)', op)
    if m:
        try:
            val = m.group(1)
            return int(val, 16) if val.startswith('0x') else int(val)
        except ValueError:
            pass
    return 0


def find_dangerous_callees(cfg, target_funcs: set) -> List[int]:
    """在 CFG 中查找所有属于危险写入函数的入口地址."""
    sites = []
    for addr, func in cfg.functions.items():
        name_lower = func.name.lower()
        if any(t in name_lower for t in target_funcs):
            sites.append(addr)
    return sites


def is_reachable_from(cfg, src_addr: int, dst_addr: int) -> bool:
    """简化可 reach 判定: 两者在同一函数内.

    完整实现需要做调用图可达性分析 (CG + CFG), 这里做保守近似:
    若 dest 所在函数被 src 所在函数直接/间接调用, 返回 True.
    """
    src_func = cfg.functions.get(src_addr)
    dst_func = cfg.functions.get(dst_addr)
    if src_func is None or dst_func is None:
        return False
    # 同函数
    if src_func.addr == dst_func.addr:
        return True
    # 检查调用图: src_func 是否调用 dst_func
    try:
        cg = cfg.functions.callgraph if hasattr(cfg.functions, 'callgraph') else None
        if cg and src_func.addr in cg:
            return dst_func.addr in cg[src_func.addr]
    except Exception:
        pass
    return True  # 保守: 假设 reachable
