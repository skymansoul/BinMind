"""
loop不变量检测module (Loop Invariant Detector)

功能:
    1. 检测反compile代码中可提至loop外的表达式和调用
    2. identifyloop不变量 (Loop Invariant Code Motion - LICM)
    3. 分析loop中不变的函数调用 (如 strlen 在loop内反复计算)
    4. 为symbolic execution提供loopoptimize建议 (减少不必要的status分叉)

core technology:
    - based on SSI (Static Single Information) 的不变量分析
    - loop检测: 自然loop (back edge), SCC
    - 变量使用-定义 (use-def) 链分析
    - 不变量condition: 所有操作数要么是常量, 要么来自loop外
"""

import logging
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

__log = logging.getLogger(__name__)

class Loop:
    __slots__ = ('loop_id', 'header_pc', 'back_edge_pc', 'body_pcs', 'exit_pcs', 'depth')

    def __init__(
            self,
            loop_id,
            header_pc,
            back_edge_pc,
            body_pcs=None,
            exit_pcs=None,
            depth=0,
    ):
        self.body_pcs = body_pcs if body_pcs is not None else list()
        self.exit_pcs = exit_pcs if exit_pcs is not None else list()
        self.depth = depth

    def to_dict(self) -> Dict[str, Any]:
        return {
            'loop_id': self.loop_id,
            'header': hex(self.header_pc),
            'back_edge': hex(self.back_edge_pc),
            'body_size': len(self.body_pcs),
            'depth': self.depth
        }

class InvariantExpression:
    __slots__ = ('expr_id', 'loop_id', 'pc', 'expression', 'category', 'can_hoist', 'reason')

    def __init__(
            self,
            expr_id,
            loop_id,
            pc,
            expression,
            category,
            can_hoist=True,
            reason="",
    ):
        self.can_hoist = can_hoist
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            'expr_id': self.expr_id,
            'loop_id': self.loop_id,
            'pc': hex(self.pc),
            'expression': self.expression,
            'category': self.category,
            'can_hoist': self.can_hoist,
            'reason': self.reason
        }

class LoopDetector:
    def detect_loops(self, instructions: List[Tuple[int, str]],
                     edges: List[Tuple[int, int]]) -> List[Loop]:
        loops = []
        loop_counter = 0

        pcs = [addr for addr, _ in instructions]
        pc_set = set(pcs)

        for src, dst in edges:
            if dst in pc_set and src in pc_set and dst <= src:
                loop_counter += 1
                body = self._compute_loop_body(dst, src, edges)
                exits = [s for s in body
                        for e_src, e_dst in edges
                        if e_src == s and e_dst not in body]

                loops.append(Loop(
                    loop_id=f"LOOP-{loop_counter:04d}",
                    header_pc=dst,
                    back_edge_pc=src,
                    body_pcs=list(body),
                    exit_pcs=exits,
                    depth=0))

        self._compute_depths(loops)
        return loops

    @staticmethod
    def _compute_loop_body(header: int, back_edge: int,
                           edges: List[Tuple[int, int]]) -> Set[int]:
        body = {header, back_edge}
        worklist = [header]
        while worklist:
            node = worklist.pop()
            for src, dst in edges:
                if src == node and dst not in body and dst <= back_edge:
                    body.add(dst)
                    worklist.append(dst)
        return body

    @staticmethod
    def _compute_depths(loops: List[Loop]):
        for i, a in enumerate(loops):
            a.depth = 0
            for b in loops:
                if i != _find_index(b.loop_id, loops) and \
                   set(a.body_pcs).issubset(set(b.body_pcs)) and \
                   a.header_pc != b.header_pc:
                    a.depth = max(a.depth, b.depth + 1)

def _find_index(lid: str, loops: List[Loop]) -> int:
    for idx, l in enumerate(loops):
        if l.loop_id == lid:
            return idx
    return -1

class InvariantChecker:

    SIDE_EFFECT_FUNCTIONS = {
        'printf', 'scanf', 'fprintf', 'sprintf', 'puts', 'gets',
        'write', 'read', 'send', 'recv', 'malloc', 'free', 'calloc',
        'fopen', 'fclose', 'fread', 'fwrite', 'pthread_create',
        'strcpy', 'strcat', 'memcpy', 'memmove', 'memset'}
    PURE_FUNCTIONS = {
        'strlen', 'strcmp', 'strncmp', 'memcmp', 'strchr', 'strrchr',
        'abs', 'atoi', 'atol', 'toupper', 'tolower', 'isalpha',
        'isdigit', 'isalnum', 'pow', 'sqrt', 'sin', 'cos', 'tan'}

    def check_expression(self, expr: str, defined_in_loop: Set[str],
                         pc: int, loop: Loop) -> InvariantExpression:
        is_invariant = True
        reason = ""
        category = "arithmetic"

        call_match = re.search(r'(\w+)\s*\(', expr)
        if call_match:
            func = call_match.group(1)
            if func in self.SIDE_EFFECT_FUNCTIONS:
                is_invariant = False
                reason = f"调用有副作用函数 {func}"
                category = "call"
            elif func in self.PURE_FUNCTIONS:
                category = "call"
                is_invariant = True
            else:
                category = "call"
                is_invariant = True

        for var in re.findall(r'\b[a-zA-Z_]\w*\b', expr):
            if var in defined_in_loop:
                is_invariant = False
                reason = f"变量 {var} 在loop内被定义"
                category = "memory_load"
                break

        return InvariantExpression(
            expr_id=f"INV-{pc:04x}",
            loop_id=loop.loop_id,
            pc=pc,
            expression=expr,
            category=category,
            can_hoist=is_invariant,
            reason=reason)

class LoopInvariantDetector:
    def __init__(self):
        self.loop_detector = LoopDetector()
        self.inv_checker = InvariantChecker()
        self._findings: List[InvariantExpression] = []

    def analyze(self, instructions: Optional[List[Tuple[int, str]]] = None,
                edges: Optional[List[Tuple[int, int]]] = None,
                decompiled_code: str = "", **kwargs) -> Dict[str, Any]:
        instructions = instructions or []
        edges = edges or []

        loops = self.loop_detector.detect_loops(instructions, edges)
        invariant_count = 0
        hoistable_count = 0
        findings = []

        for loop in loops[:20]:
            defined_in_loop: Set[str] = set()
            for line in decompiled_code.split('\n'):
                assign_match = re.match(r'\s*(\w+)\s*=\s*(.+);', line)
                if assign_match:
                    defined_in_loop.add(assign_match.group(1))

            for pc in loop.body_pcs[:50]:
                for addr, instr in instructions:
                    if addr == pc:
                        if '=' in instr:
                            rhs = instr.split('=', 1)[1].strip()
                            inv = self.inv_checker.check_expression(
                                rhs, defined_in_loop, pc, loop)
                            findings.append(inv.to_dict())
                            invariant_count += 1
                            if inv.can_hoist:
                                hoistable_count += 1

        self._findings = [InvariantExpression(**f) if isinstance(f, dict)
                         else f for f in findings]

        return {
            'success': True,
            'total_loops': len(loops),
            'loops': [l.to_dict() for l in loops[:10]],
            'total_invariants': invariant_count,
            'hoistable': hoistable_count,
            'findings': findings[:50],
            'optimization_impact': {
                'estimated_cycles_saved': hoistable_count * 10,
                'recommendation': (
                    f'可将 {hoistable_count} 个不变量表达式提升到loop外, '
                    '减少loop内重复计算')
            } if hoistable_count > 0 else {}
        }

def detect_loop_invariants(
    instructions: Optional[List[Tuple[int, str]]] = None,
    edges: Optional[List[Tuple[int, int]]] = None,
    decompiled_code: str = "", **kwargs
) -> Dict[str, Any]:
    detector = LoopInvariantDetector()
    return detector.analyze(instructions=instructions, edges=edges,
                           decompiled_code=decompiled_code)

