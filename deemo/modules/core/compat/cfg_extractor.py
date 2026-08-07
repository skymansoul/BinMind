# coding: utf-8
"""
CFG 子图提取 — 从指令流中构建从 alloc_site 到 write_site 的 CFG 子图.

与 path_abstract_interpret.py 的关系: 本模块负责 CFG 构建,
path_abstract_interpret.py 在构建好的 CFG 上做抽象解释.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CFGNode:
    """控制流图节点."""
    addr: int
    op_type: str = ''           # 'alloc' | 'write' | 'branch' | 'merge' | 'other'
    alloc_size: int = 0
    write_size: int = 0
    ptr_var: str = ''
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)


def extract_cfg_subgraph(
    instructions: List[Dict],
    ir_ops: Dict[int, Dict],
    alloc_site: int,
    write_site: int,
) -> Dict[int, CFGNode]:
    """从指令流中提取从 alloc_site 到 write_site 的 CFG 子图.

    只保留可达路径上的节点, 减少分析范围.
    """
    # 先构建完整 CFG
    nodes: Dict[int, CFGNode] = {}

    for insn in instructions:
        addr = insn.get('addr', 0)
        if addr == 0:
            continue
        op_type = _classify_op(insn, ir_ops.get(addr, {}))
        node = CFGNode(addr=addr, op_type=op_type)
        if op_type == 'alloc':
            ir = ir_ops.get(addr, {})
            node.alloc_size = ir.get('alloc_size', 0)
        elif op_type == 'write':
            ir = ir_ops.get(addr, {})
            node.write_size = ir.get('write_size', 0)
        nodes[addr] = node

    # 边: 顺序流 + 跳转边
    sorted_addrs = sorted(nodes.keys())
    for i, addr in enumerate(sorted_addrs):
        if i + 1 < len(sorted_addrs):
            next_addr = sorted_addrs[i + 1]
            nodes[addr].successors.append(next_addr)
            nodes[next_addr].predecessors.append(addr)

    for addr, op in ir_ops.items():
        if addr not in nodes:
            continue
        target = op.get('jump_target', op.get('branch_target', 0))
        if target and target in nodes:
            if target not in nodes[addr].successors:
                nodes[addr].successors.append(target)
            if addr not in nodes[target].predecessors:
                nodes[target].predecessors.append(addr)

    # 反向 BFS: 从 write_site 追溯到 alloc_site
    if write_site not in nodes or alloc_site not in nodes:
        return nodes

    reachable: Set[int] = set()
    q = deque([write_site])
    while q:
        cur = q.popleft()
        if cur in reachable:
            continue
        reachable.add(cur)
        node = nodes.get(cur)
        if node:
            for pred in node.predecessors:
                if pred not in reachable and pred >= alloc_site:
                    q.append(pred)

    return {addr: n for addr, n in nodes.items() if addr in reachable}


def _classify_op(insn: Dict, ir_op: Dict) -> str:
    """根据指令和 IR 操作分类节点类型."""
    mnemonic = insn.get('mnemonic', '').lower()
    callee = ir_op.get('callee', '').lower()

    if any(f in callee for f in ('malloc', 'calloc', 'realloc', 'new')):
        return 'alloc'
    if any(f in callee for f in ('memcpy', 'memmove', 'strcpy', 'strncpy',
                                  'sprintf', 'read', 'fread', 'recv')):
        return 'write'
    if mnemonic in ('jmp', 'jz', 'jnz', 'je', 'jne', 'jb', 'jbe', 'ja', 'jae',
                    'jl', 'jle', 'jg', 'jge', 'js', 'jns', 'b', 'bl', 'b.eq',
                    'b.ne', 'b.lt', 'b.gt'):
        return 'branch'
    if mnemonic in ('cmp', 'test', 'tst'):
        return 'cmp_bounds'
    return 'other'
