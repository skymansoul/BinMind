# 指令索引化别名图-寄存器间mov/lea/间接内存存取建立等价关系
# 解决"两个malloc都返回rax→别名污染"-寄存器复用导致别名误判
#
# 图结构: Dict[str, Set[Tuple[str, int]]]
#   键: 寄存器/内存标签名
#   值: {(邻居名, 建立该边的最低指令索引), ...}
# 闭包计算时仅考虑 min_idx ≤ edge_idx 的边, 从而隔离不同alloc的作用域
#
# 理论: Andersen式指针分析的轻量寄存器版本
#       + 指令索引化解决跨alloc的寄存器复用污染

from __future__ import annotations

import re
from typing import Dict, Set, Tuple, List, Optional
from collections import defaultdict


# 非寄存器关键字-mov/lea中作为大小前缀或修饰符出现
_NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr', 'xmmword',
            'ymmword', 'zmmword', 'tbyte', 'oword', 'mmword'}


def build_alias_graph(instructions: List[str]
                      ) -> Dict[str, Set[Tuple[str, int]]]:
    """构建指令索引化的寄存器别名图。

    追踪5种别名建立方式:
      1. mov reg1, reg2 → reg1和reg2值等价
      2. lea reg1, [reg2] → reg1和reg2地址等价
      3. mov [regA], regB → 间接存储(记录regB存到regA指向的位置)
      4. mov regC, [regD] → 若regD有间接存储记录, 建立别名
      5. mov [rsp/rbp+N], reg → 栈暂存; mov reg, [rsp/rbp+N] → 恢复
    """
    graph: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
    # 间接内存存储: (mem_reg, index) → {stored_regs}
    indirect_stores: Dict[Tuple[str, int], Set[str]] = defaultdict(set)

    def _i(s):
        return int(s, 16) if '0x' in s.lower() else int(s)

    for idx, instr in enumerate(instructions):
        instr = instr.strip().lower()
        # 双ABI: mov %src,%dst (AT&T) 或 mov dst,src (Intel)
        m = re.match(r'mov\s+%?(\w+),\s*%?(\w+)', instr)
        if m:
            r1, r2 = m.group(1), m.group(2)
            if (r1 not in _NON_REG and r2 not in _NON_REG
                    and not r1.startswith(('0x', '[')) and not r1[0].isdigit()
                    and not r2.startswith(('0x', '[')) and not r2[0].isdigit()):
                graph[r1].add((r2, idx))
                graph[r2].add((r1, idx))
        # 双ABI: lea offset(%base),%dst (AT&T) 或 lea dst,[base+off] (Intel)
        m = re.match(r'lea\s+[^(]*\(%?(\w+)\)\s*,\s*%?(\w+)', instr)
        if m:
            base, dst = m.group(1), m.group(2)
            if base not in ('rip', 'eip') and dst not in _NON_REG:
                graph[dst].add((base, idx))
                graph[base].add((dst, idx))
        m = re.match(r'lea\s+%?(\w+),\s*\[(\w+)(?:[+\-]\w+)?\]', instr)
        if m:
            dst, base = m.group(1), m.group(2)
            if base not in ('rip', 'eip') and dst not in _NON_REG:
                graph[dst].add((base, idx))
                graph[base].add((dst, idx))
        # 双ABI间接存储: AT&T mov %val,(%addr) / Intel mov [addr],val
        m = re.match(r'mov\s+%?(\w+)\s*,\s*\(\s*%?(\w+)\s*\)', instr)
        if m:
            val_reg, addr_reg = m.group(1), m.group(2)
            if val_reg not in _NON_REG and not val_reg[0].isdigit():
                indirect_stores[(addr_reg, idx)].add(val_reg)
        m = re.match(r'mov\s+(?:\w+\s+ptr\s+)?\[(\w+)\]\s*,\s*%?(\w+)', instr)
        if m:
            addr_reg, val_reg = m.group(1), m.group(2)
            if val_reg not in _NON_REG and addr_reg not in _NON_REG:
                indirect_stores[(addr_reg, idx)].add(val_reg)
        # 双ABI间接加载: AT&T mov (%addr),%dst / Intel mov dst,[addr]
        m = re.match(r'mov\s*\(\s*%?(\w+)\s*\)\s*,\s*%?(\w+)', instr)
        intel_load = False
        if not m:
            m = re.match(r'mov\s+%?(\w+),\s*(?:\w+\s+ptr\s+)?\[(\w+)\]', instr)
            intel_load = True
        if m:
            addr_reg2 = m.group(1) if not intel_load else m.group(2)
            dst = m.group(2) if not intel_load else m.group(1)
            if addr_reg2 not in _NON_REG and dst not in _NON_REG:
                for (ar, store_idx), stored_vals in indirect_stores.items():
                    if ar == addr_reg2:
                        for sv in stored_vals:
                            graph[dst].add((sv, idx))
                            graph[sv].add((dst, idx))
        # 双ABI栈暂存: AT&T mov %src,N(%rsp/%rbp) / Intel mov [rsp+N],src
        m = re.match(
            r'mov\s+%?(\w+)\s*,\s*'
            r'(0x[0-9a-f]+|\d+)\s*\(\s*%?(rsp|rbp)\s*\)', instr)
        if m:
            src, off_str, base = m.group(1), m.group(2), m.group(3)
            if src not in _NON_REG:
                off_val = _i(off_str)
                mem_label = f"stack_{base}_{off_val}"
                graph[mem_label].add((src, idx))
        m = re.match(
            r'mov\s+(?:\w+\s+ptr\s+)?\[(rsp|rbp)([+\-]\w+)\]\s*,\s*%?(\w+)', instr)
        if m:
            base, off_str, src = m.group(1), m.group(2), m.group(3)
            if src not in _NON_REG:
                off_val = _i(off_str)
                mem_label = f"stack_{base}_{off_val}"
                graph[mem_label].add((src, idx))
        # 双ABI栈恢复: AT&T mov N(%rsp/%rbp),%dst / Intel mov dst,[rsp+N]
        m = re.match(
            r'mov\s+(0x[0-9a-f]+|\d+)\s*\(\s*%?(rsp|rbp)\s*\)\s*,\s*%?(\w+)', instr)
        if m:
            off_str, base, dst = m.group(1), m.group(2), m.group(3)
            if dst not in _NON_REG:
                off_val = _i(off_str)
                mem_label = f"stack_{base}_{off_val}"
                for neighbor, edge_idx in list(graph.get(mem_label, set())):
                    graph[dst].add((neighbor, idx))
                    graph[neighbor].add((dst, idx))
        m = re.match(
            r'mov\s+%?(\w+),\s*(?:\w+\s+ptr\s+)?\[(rsp|rbp)([+\-]\w+)\]', instr)
        if m:
            dst, base, off_str = m.group(1), m.group(2), m.group(3)
            if dst not in _NON_REG:
                off_val = _i(off_str)
                mem_label = f"stack_{base}_{off_val}"
                for neighbor, edge_idx in list(graph.get(mem_label, set())):
                    graph[dst].add((neighbor, idx))
                    graph[neighbor].add((dst, idx))
    return dict(graph)


def transitive_closure(start: str,
                        graph: Dict[str, Set[Tuple[str, int]]],
                        min_idx: int = 0,
                        max_idx: int = 999999,
                        stop_nodes: Optional[Set[str]] = None
                        ) -> Set[str]:
    """BFS计算别名传递闭包-仅考虑[min_idx, max_idx)窗口内的边
    stop_nodes: 可到达但不再扩展的节点(用于阻断rax等规范寄存器的跨alloc桥接)"""
    visited = {start}
    q = [start]
    stop = stop_nodes or set()
    while q:
        node = q.pop(0)
        if node in stop and node != start:
            continue
        for neighbor, edge_idx in graph.get(node, set()):
            if neighbor not in visited and min_idx <= edge_idx < max_idx:
                visited.add(neighbor)
                q.append(neighbor)
    return visited


# 栈槽别名映射
# 栈槽穿透: mov %rax, N(%rbp)存储→mov N(%rbp), %rdi加载→建立别名链
# 返回 Dict[slot_key, source_reg] 用于liveness追踪穿透栈槽

_STK_RE = re.compile(
    r'mov\s+%?(\w+)\s*,\s*([+-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*%?(rbp|rsp)\s*\)')
_STK_LD_RE = re.compile(
    r'mov\s+([+-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*%?(rbp|rsp)\s*\)\s*,\s*%?(\w+)')


def build_stack_alias_map(instructions: List[str]) -> Dict[str, str]:
    """预扫描栈存储→构建slot→source_reg映射(AT&T+Intel)。
    slot格式: stk_{rbp|rsp}_{offset}"""
    sm: Dict[str, str] = {}
    for il in instructions:
        il = il.strip().lower()
        m = _STK_RE.match(il)
        if m:
            sm[f"stk_{m.group(3)}_{m.group(2)}"] = m.group(1)
            continue
        m = _STK_LD_RE.match(il)
        if m and m.group(3) not in _NON_REG:
            sm.setdefault(f"stk_{m.group(2)}_{m.group(1)}", m.group(3))
    return sm
