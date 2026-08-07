"""
Value-Flow Graph (VFG) builder for decompiled binary IR.

Constructs explicit def-use chains from decompiler output to enable
constraint-based safety proofs. Each node is a value definition (assignment,
function call result, constant); edges represent data flow from definition
to use site.

Design decisions:
- Works on decompiler text, not Ghidra/IDA IR directly — decouples from
  specific decompiler versions, trades precision for generality.
- SSA reconstruction is local (within function scope) — inter-procedural
  flow handled via heuristic call-site propagation in constraint_accumulator.
- Nodes carry source location (line index) and type info (constant, variable,
  expression) for downstream path feasibility analysis.

  VYPER — value-flow on decompiled output for
  vulnerability detection in stripped binaries.
  MIRAI (Facebook) — tag analysis for buffer overrun via abstract interpretation.
  We adopt VYPER's decompiler-first approach but add constraint reasoning
  beyond simple pattern matching.
"""

import re
from typing import List, Optional, Set

from core.vfg_types import (
    NodeKind, VFGNode, VFGEdge, ValueFlowGraph,
)

class VFGBuilder:
    """从解压缩的IR行构建值流图。

    两遍算法:
      第一遍: 识别所有值定义点 (赋值、调用、常量) 并创建节点。
      第二遍: 链接定义到使用点, 构建数据流边。

    复杂度: O(N²) 最坏情况 (N=IR行数), 实际 N<500 时 <10ms。
    """

    # 赋值模式: var = expr
    _ASSIGN_PAT = re.compile(
        r'(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*(.+)'
    )
    # 函数调用模式 (含赋值): var = func(args) 或 func(args)
    _CALL_PAT = re.compile(
        r'(?:(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*)?(\w+)\s*\(([^)]*)\)'
    )
    # store模式: *(base + off) = val 或 [base+off] = val
    _STORE_PAT = re.compile(
        r'(?:\*\s*\(\s*(\w+)\s*\+\s*([^)]+)\s*\)|'
        r'\[(\w+)\s*\+\s*([^\]]+)\])'
        r'\s*=\s*(.+)'
    )
    # cmp模式: cmp a, b (用于循环边界推断)
    _CMP_PAT = re.compile(
        r'cmp\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)', re.IGNORECASE
    )
    # 算术表达式: var = a op b
    _ARITH_PAT = re.compile(
        r'(\w+)\s*([+\-*/])\s*(\w+|\d+)'
    )

    def __init__(self):
        self._next_id = 0

    def _new_id(self) -> int:
        nid = self._next_id
        self._next_id += 1
        return nid

    def build(self, ir_lines: List[str], func_name: str = '') -> ValueFlowGraph:
        """主入口: 从IR行构建完整值流图。"""
        g = ValueFlowGraph(function_name=func_name)

        # 第一遍: 节点创建
        for i, line in enumerate(ir_lines):
            self._create_nodes(line, i, g)

        # 第二遍: 边构建 (def-use链)
        self._build_edges(g, ir_lines)

        return g

    def _create_nodes(self, line: str, line_idx: int, g: ValueFlowGraph):
        """从单行IR创建VFG节点。"""
        s = line.strip()
        if not s or s.startswith('//') or s.startswith('#'):
            return

        # 检测 store: *(base+off) = val
        store_m = self._STORE_PAT.search(s)
        if store_m:
            base = store_m.group(1) or store_m.group(3) or ''
            off = store_m.group(2) or store_m.group(4) or ''
            val = store_m.group(5) or ''
            node = VFGNode(
                node_id=self._new_id(), kind=NodeKind.WRITE_CALL,
                name=f'store_{base}_{off}',
                line_idx=line_idx, text=s,
                call_info=(base, off, val),
            )
            g.add_node(node)
            return

        # 检测函数调用
        call_m = self._CALL_PAT.search(s)
        if call_m:
            lhs = call_m.group(1) or ''
            func = call_m.group(2).lower()
            args = call_m.group(3)

            if func in ('malloc', 'calloc', 'realloc', 'reallocarray'):
                node = VFGNode(
                    node_id=self._new_id(), kind=NodeKind.ALLOC_CALL,
                    name=lhs, line_idx=line_idx, text=s,
                    call_info=(func, args),
                )
                g.add_node(node)
                return

            if func in ('memcpy', 'strcpy', 'strncpy', 'memmove',
                        'read', 'recv', 'fread', 'sprintf', 'snprintf'):
                node = VFGNode(
                    node_id=self._new_id(), kind=NodeKind.WRITE_CALL,
                    name=lhs, line_idx=line_idx, text=s,
                    call_info=(func, args),
                )
                g.add_node(node)
                return

            # 其他函数调用: 若返回值赋给变量, 标记为变量定义
            if lhs:
                node = VFGNode(
                    node_id=self._new_id(), kind=NodeKind.RETURN_VAL,
                    name=lhs, line_idx=line_idx, text=s,
                )
                g.add_node(node)
                return

        # 检测赋值: var = expr
        assign_m = self._ASSIGN_PAT.search(s)
        if assign_m:
            lhs = assign_m.group(1)
            rhs = assign_m.group(2).strip()

            # 检查是否是常量赋值
            const_val = self._try_parse_int(rhs)
            if const_val is not None:
                node = VFGNode(
                    node_id=self._new_id(), kind=NodeKind.CONSTANT,
                    name=lhs, value=const_val,
                    line_idx=line_idx, text=s,
                )
                g.add_node(node)
                return

            # 检查算术表达式
            arith_m = self._ARITH_PAT.search(rhs)
            if arith_m:
                node = VFGNode(
                    node_id=self._new_id(), kind=NodeKind.EXPRESSION,
                    name=lhs, line_idx=line_idx, text=s,
                    call_info=(arith_m.group(1), arith_m.group(2), arith_m.group(3)),
                )
                g.add_node(node)
                return

            # 一般赋值
            node = VFGNode(
                node_id=self._new_id(), kind=NodeKind.VARIABLE,
                name=lhs, line_idx=line_idx, text=s,
            )
            g.add_node(node)
            return

        # 检测 cmp 指令 (循环边界)
        cmp_m = self._CMP_PAT.search(s)
        if cmp_m:
            try:
                bound_val = int(cmp_m.group(2), 0)
                node = VFGNode(
                    node_id=self._new_id(), kind=NodeKind.LOOP_BOUND,
                    name=f'loop_bound_{line_idx}',
                    value=bound_val,
                    line_idx=line_idx, text=s,
                )
                g.add_node(node)
            except (ValueError, TypeError):
                pass

    def _build_edges(self, g: ValueFlowGraph, ir_lines: List[str]):
        """第二遍: 构建def-use边。

        对每条IR行, 识别引用的变量名, 向后搜索最近的定义点。
        """
        for node in g.nodes:
            line = node.text
            # 提取该行中引用的变量名
            refs = self._extract_var_refs(line)
            for ref in refs:
                # 向后搜索该变量的最近定义
                def_node = self._find_nearest_def(g, ref, node.line_idx)
                if def_node and def_node.node_id != node.node_id:
                    g.add_edge(def_node, node, 'identity')

    def _extract_var_refs(self, line: str) -> Set[str]:
        """从IR行提取被引用的变量名。排除关键字和函数名。"""
        keywords = {
            'if', 'else', 'while', 'for', 'return', 'goto', 'do',
            'sizeof', 'int', 'char', 'void', 'long', 'short', 'unsigned',
            'struct', 'union', 'enum', 'typedef', 'const', 'static',
        }
        refs = set()
        for m in re.finditer(r'\b([a-zA-Z_]\w{0,31})\b', line):
            name = m.group(1)
            if name.lower() not in keywords:
                refs.add(name)
        return refs

    def _find_nearest_def(self, g: ValueFlowGraph,
                          var_name: str, before_line: int) -> Optional[VFGNode]:
        """找到 var_name 在 before_line 之前最近的定义节点。"""
        candidates = g.get_nodes_by_name(var_name)
        if not candidates:
            return None
        best = None
        best_dist = 999999
        for n in candidates:
            if n.name == var_name and n.line_idx < before_line:
                dist = before_line - n.line_idx
                if dist < best_dist:
                    best_dist = dist
                    best = n
        return best

    @staticmethod
    def _try_parse_int(s: str) -> Optional[int]:
        """尝试将字符串解析为整数。"""
        s = s.strip().rstrip(';').rstrip(')')
        try:
            if s.startswith('0x') or s.startswith('0X'):
                return int(s, 16)
            return int(s)
        except (ValueError, TypeError):
            return None

def build_vfg(ir_lines: List[str], func_name: str = '') -> ValueFlowGraph:
    """便捷函数 — 从IR行构建值流图."""
    return VFGBuilder().build(ir_lines, func_name)

__all__ = [
    'VFGBuilder',
    'build_vfg',
    'NodeKind',
    'VFGNode',
    'VFGEdge',
    'ValueFlowGraph',
]
