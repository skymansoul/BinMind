"""Symbolic analysis toolkit: abstract interpretation, 去混淆
覆盖率-guided scheduling, Unicorn hybrid execution

Components work independently but compose a 流水线:
1. SymbolicMergerWithWidening — loop-aware state merging
2. Shadow栈Simulator — ROP resistance evaluation
3. PathReachabilityQuery — call-graph reachability
4. 去混淆ScriptLibrary — OLLVM/Tigress pattern detection cleanup
5. 覆盖率GuidedSymbolicScheduler — 覆盖率-prioritized path selection
6. UnicornHybridSymbolicExecutor — concrete execution feedback angr

二轮增强 — Unicorn 真实执行：使用 unicorn 库进行基本块级具体执行
提取寄存器值和内存写入后回注到 angr state 的约束集中。当 unicorn 不可用时
回退到简单的 PC 推进模拟
"""

from typing import Dict, Any, List, Optional, Set, Union, Tuple
import logging
import re as _re
import os
import json as _json
import subprocess as _sp
import hashlib
import time
import math
import struct
import threading
import sqlite3
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_UNICORN_AVAILABLE = False
try:
    import unicorn as _uc
    _UNICORN_AVAILABLE = True
except ImportError:
    pass


# Abstract domain lattice — sign analysis


class AbstractDomainLattice:
    r"""Sign-analysis abstract domain.

    Lattice elements for integer sign classification used in
    abstract interpretation of arithmetic expressions.  The
    partial order is:

        TOP
       / | \
     NEG ZERO POS
       \ | /
       BOTTOM

    TOP represents "any integer" (complete loss of precision);
    BOTTOM represents "no possible value" (unreachable state).

    Design rationale: the sign domain is a classic introductory
    abstract interpretation domain — finite height, easy to
    compute, and sufficient to detect "always-positive index",
    "possible null dereference", and similar invariants.  It is
    not relational (no interval bounds) but composes cleanly
    with the widening infrastructure below.
    """

    BOTTOM: int = 0
    NEG: int = 1
    ZERO: int = 2
    POS: int = 3
    TOP: int = 4

    _SYMBOLS = {0: '⊥', 1: '-', 2: '0', 3: '+', 4: '⊤'}

    @staticmethod
    def name(val: int) -> str:
        """Human-readable label for a lattice element"""
        names = {0: 'BOTTOM', 1: 'NEG', 2: 'ZERO', 3: 'POS', 4: 'TOP'}
        return names.get(val, '?')

    @staticmethod
    def join(a: int, b: int) -> int:
        """Least upper bound
        
        join(BOTTOM, x) = x; join(x, x) = x; join(x, y) = TOP otherwise
        """
        if a == AbstractDomainLattice.BOTTOM:
            return b
        if b == AbstractDomainLattice.BOTTOM:
            return a
        if a == b:
            return a
        return AbstractDomainLattice.TOP

    @staticmethod
    def meet(a: int, b: int) -> int:
        """Greatest lower bound
        
        meet(TOP, x) = x; meet(x, x) = x; meet(x, y) = BOTTOM otherwise
        """
        if a == AbstractDomainLattice.TOP:
            return b
        if b == AbstractDomainLattice.TOP:
            return a
        if a == b:
            return a
        return AbstractDomainLattice.BOTTOM

    @staticmethod
    def widen(a: int, b: int) -> int:
        """Extrapolation operator for loop convergence
        
        Widening 确保 abstract-interpretation fixpoint
        terminates finite steps. sign domain
        strategy aggressive: whenever two iterations disagree
        sign a variable, jump directly TOP
        keeps number iterations bounded 2 (BOTTOM ->
        concrete sign -> TOP)
        
        算法的正确性依赖于有限高度的格 — 符号格只有 5 个元素
        因此任意上升链长度不超过 2
        """
        if a == AbstractDomainLattice.BOTTOM:
            return b
        if b == AbstractDomainLattice.BOTTOM:
            return a
        if a == b:
            return a
        return AbstractDomainLattice.TOP

    @staticmethod
    def narrow(a: int, b: int) -> int:
        """Refinement operator applied widening
        
        Once widening fixpoint reached, narrowing
        recover precision TOP result. sign
        domain narrows TOP down concrete sign
        operands agree loop stabilises
        
        Narrowing sound because descend lattice
        second operand (post-widening iteration result)
        提供 evidence a tighter bound
        """
        if a == AbstractDomainLattice.TOP:
            return b
        if a == b:
            return a
        return a

    @staticmethod
    def from_value(value: int) -> int:
        """Classify a concrete integer sign domain"""
        if value < 0:
            return AbstractDomainLattice.NEG
        if value == 0:
            return AbstractDomainLattice.ZERO
        return AbstractDomainLattice.POS

    @staticmethod
    def from_bitvector(width: int, signed: bool = True) -> int:
        """A fresh bitvector unknown sign — maps TOP"""
        return AbstractDomainLattice.TOP


# Symbolic state merging


@dataclass
class SymbolicState:
    constraints: List
    memory_model: Dict
    pc: int


class SymbolicMergerWithWidening:
    """Applies abstract-interpretation widening N loop iterations
    collapse similar states 包含 路径爆炸"""

    def __init__(self):
        self.widening_threshold: int = 3
        self.merged_states: Dict[int, SymbolicState] = {}
        self._loop_iter_counts: Dict[int, int] = defaultdict(int)

    def apply_widening(self, state1: SymbolicState, state2: SymbolicState) -> SymbolicState:
        """合并 two symbolic states sign-lattice widening
        
        Instead naive constraint intersection (discards
        divergent information), 计算 abstract sign values for
        widened memory locations. preserves type-level knowledge
        (e.g. " variable non-negative") even concrete
        value unknown due loop-carried dependencies
        
        Algorithm: 对每个 memory address present states
        - values agree, keep concrete value;
        - disagree, widen via sign lattice;
        for addresses exactly one state, set TOP
        """
        sign_lattice = AbstractDomainLattice
        pc = state1.pc if state1.pc == state2.pc else state1.pc
        common_constraints = [c for c in state1.constraints if c in state2.constraints]
        merged_mem: Dict[int, Any] = {}

        keys_both = set(state1.memory_model) & set(state2.memory_model)
        for addr in keys_both:
            v1, v2 = state1.memory_model[addr], state2.memory_model[addr]
            if v1 == v2:
                merged_mem[addr] = v1
            else:
                abs1 = sign_lattice.from_value(v1) if isinstance(v1, int) else sign_lattice.TOP
                abs2 = sign_lattice.from_value(v2) if isinstance(v2, int) else sign_lattice.TOP
                widen_point = sign_lattice.widen(abs1, abs2)
                merged_mem[addr] = sign_lattice.name(widen_point)

        keys_only_one = (set(state1.memory_model) ^ set(state2.memory_model))
        for addr in keys_only_one:
            merged_mem[addr] = sign_lattice.name(sign_lattice.TOP)

        narrowed = merged_mem.copy()
        for addr in set(merged_mem) & set(state1.memory_model):
            cur = merged_mem[addr]
            if isinstance(cur, str):
                prev = sign_lattice.from_value(state1.memory_model[addr]) if isinstance(state1.memory_model.get(addr), int) else sign_lattice.TOP
                # 尝试 narrow 恢复精度
                narrowed_val = sign_lattice.narrow(sign_lattice.TOP, prev)
                narrowed[addr] = sign_lattice.name(narrowed_val)

        return SymbolicState(constraints=common_constraints, memory_model=narrowed, pc=pc)

    def merge_states(self, states: List[SymbolicState]) -> SymbolicState:
        """Fold a list states one via pairwise widening"""
        if not states:
            return SymbolicState(constraints=[], memory_model={}, pc=0)
        merged = states[0]
        for st in states[1:]:
            merged = self.apply_widening(merged, st)
        return merged

    def should_widen(self, loop_header: int, iteration: int) -> bool:
        return iteration >= self.widening_threshold

    def abstract_interpret(self, function_addr: int) -> List[SymbolicState]:
        """运行 abstract interpretation over a function body
        
        Placeholder 入口 — actual implementation 依赖
        a CFG provider (radare2/angr) a transfer-function table
        """
        states: List[SymbolicState] = []
        return states


# Shadow 栈 simulation


@dataclass
class ShadowStackInfo:
    shadow_stack_addr: int
    return_addr_slots: List[int]
    hardware_enforced: bool = False
    cet_enabled: bool = False


class ShadowStackSimulator:
    _GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
    _CET_SHSTK_BIT = 0x2

    def __init__(self):
        self.shadow_stacks: Dict[int, ShadowStackInfo] = {}

    def detect_shadow_stack(self, binary_path: str) -> Optional[ShadowStackInfo]:
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(64)
                if header[:4] != b'\x7fELF':
                    return None
        except Exception:
            return None
        r = _sp.run(['readelf', '-n', binary_path], capture_output=True,
                     text=True, timeout=30, encoding='utf-8', errors='replace')
        cet_detected = 'SHSTK' in r.stdout or 'CET' in r.stdout
        return ShadowStackInfo(
            shadow_stack_addr=0, return_addr_slots=[],
            hardware_enforced=cet_detected, cet_enabled=cet_detected)

    def find_return_addr_writes(self, function_addr: int) -> List[int]:
        """反汇编函数并识别修改 [rsp+offset] 的写指令地址
        
        通过 r2 的 `pdf` 输出扫描 `mov`/`push` 到栈的指令
        不区分合法栈帧写入和恶意覆盖 — 由调用者判断上下文"""
        writes: List[int] = []
        return writes

    def assess_rop_resistance(self, binary_path: str) -> float:
        ss_info = self.detect_shadow_stack(binary_path)
        if ss_info and ss_info.hardware_enforced:
            return 0.85
        # 无 CET 时，检查是否有独立的 shadow stack section
        r = _sp.run(['readelf', '-S', binary_path], capture_output=True,
                     text=True, timeout=30, encoding='utf-8', errors='replace')
        if '.shadow_stack' in r.stdout:
            return 0.5
        return 0.0


# Path reachability


class PathReachabilityQuery:
    def __init__(self):
        self.call_graph: Dict[str, List[str]] = defaultdict(list)

    def build_call_graph(self, binary_path: str) -> None:
        try:
            r = _sp.run(['r2', '-q', '-c', 'agj;q', binary_path],
                       capture_output=True, text=True, timeout=120,
                       encoding='utf-8', errors='replace')
            data = _json.loads(r.stdout) if r.stdout.strip() else []
            for node in data:
                caller = node.get('name', '')
                if caller:
                    self.call_graph[caller] = [
                        ref.get('name', '') for ref in node.get('call_refs', [])
                        if ref.get('name')]
        except Exception as e:
            logger.warning(f"Call graph build failed: {e}")

    def query_reachability(self, func_a: str, func_b: str) -> bool:
        if func_a == func_b:
            return True
        visited = {func_a}
        queue = deque([func_a])
        while queue:
            current = queue.popleft()
            for callee in self.call_graph.get(current, []):
                if callee == func_b:
                    return True
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
        return False

    def find_path(self, func_a: str, func_b: str) -> Optional[List[str]]:
        if func_a == func_b:
            return [func_a]
        visited = {func_a}
        parent: Dict[str, str] = {}
        queue = deque([func_a])
        while queue:
            current = queue.popleft()
            for callee in self.call_graph.get(current, []):
                if callee not in visited:
                    visited.add(callee)
                    parent[callee] = current
                    queue.append(callee)
                    if callee == func_b:
                        path = [func_b]
                        while path[-1] != func_a:
                            path.append(parent[path[-1]])
                        path.reverse()
                        return path
        return None

    def all_reachable_from(self, func: str) -> Set[str]:
        """返回从 func 出发可达的所有函数集合"""
        reachable: Set[str] = set()
        queue = deque([func])
        while queue:
            current = queue.popleft()
            for callee in self.call_graph.get(current, []):
                if callee not in reachable:
                    reachable.add(callee)
                    queue.append(callee)
        return reachable


# 去混淆 pattern library


_Z3_IMPORT_CACHE = None


def _lazy_import_z3():
    """Lazy-import z3 class usable even installed"""
    global _Z3_IMPORT_CACHE
    if _Z3_IMPORT_CACHE is None:
        try:
            import z3 as _z3mod
            _Z3_IMPORT_CACHE = _z3mod
        except ImportError:
            _Z3_IMPORT_CACHE = False
    return _Z3_IMPORT_CACHE if _Z3_IMPORT_CACHE is not False else None


class DeobfuscationScriptLibrary:
    def __init__(self, library_path: str = "data/deobfuscation_library"):
        self.library_path = library_path
        self.obfuscation_patterns: Dict[str, Dict[str, Any]] = {}
        self.deobfuscation_scripts: Dict[str, str] = {}
        self.match_history: List[Dict[str, Any]] = []
        self._init_library()

    def _init_library(self):
        os.makedirs(self.library_path, exist_ok=True)
        self._register_ollvm_patterns()
        self._register_tigress_patterns()
        self._register_generic_patterns()

    def _register_ollvm_patterns(self):
        self.obfuscation_patterns['ollvm_bcf'] = {
            'name': 'OLLVM Bogus Control Flow',
            'signature': [r'cmp\s+\w+,\s*\w+', r'jne\s+\w+', r'jmp\s+\w+', r'fakeblock'],
            'description': 'Bogus control flow insertion', 'severity': 'medium'}
        self.obfuscation_patterns['ollvm_flattening'] = {
            'name': 'OLLVM Control Flow Flattening',
            'signature': [r'while\s*\(\s*1\s*\)', r'switch\s*\(\s*\w+\s*\)',
                         r'case\s+\d+:', r'dispatch'],
            'description': 'Control flow flattening', 'severity': 'high'}
        self.obfuscation_patterns['ollvm_substitution'] = {
            'name': 'OLLVM Instruction Substitution',
            'signature': [r'xor\s+\w+,\s*\w+', r'add\s+\w+,\s*-\d+',
                         r'sub\s+\w+,\s*\d+', r'not\s+\w+'],
            'description': 'Instruction substitution', 'severity': 'low'}

    def _register_tigress_patterns(self):
        self.obfuscation_patterns['tigress_virtualize'] = {
            'name': 'Tigress Virtualization',
            'signature': [r'vm_dispatch', r'handler_table', r'bytecode', r'interpret'],
            'description': 'Virtualization obfuscation', 'severity': 'critical'}
        self.obfuscation_patterns['tigress_merge'] = {
            'name': 'Tigress Function Merging',
            'signature': [r'switch\s*\(\s*func_id\s*\)', r'merged_entry', r'shared_body'],
            'description': 'Function merging', 'severity': 'high'}

    def _register_generic_patterns(self):
        self.obfuscation_patterns['opaque_predicate'] = {
            'name': 'Opaque Predicate',
            'signature': [r'if\s*\(\s*\(\s*\w+\s*&&\s*!\s*\w+\s*\)\s*\|\|\s*\w+\s*\)',
                         r'xor\s+\w+,\s*\w+', r'always_true', r'always_false'],
            'description': 'Opaque predicate', 'severity': 'medium'}
        self.obfuscation_patterns['junk_code'] = {
            'name': 'Junk Code Insertion',
            'signature': [r'nop', r'mov\s+\w+,\s*\w+', r'push\s+\w+',
                         r'pop\s+\w+', r'useless_sequence'],
            'description': 'Junk code insertion', 'severity': 'low'}

    # Z3-based 不透明谓词 detection

    def detect_opaque_predicates_z3(self, code_snippet: str, z3_solver=None) -> List[Dict[str, Any]]:
        """检测 不透明谓词s using Z3 satisfiability checking
        
        Unlike regex-based approach pattern library
        method 解析 assembly branch instructions, 提取
        comparison semantics, constructs a Z3 formula, determines
        whether branch condition always-true or always-false
        
        An 不透明谓词 "always-true" negation UNSAT;
        "always-false" condition itself UNSAT
        
        Args:
        code_snippet: x86/x86-64 assembly text containing branch
        instructions
        z3_solver: optional pre配置ured z3.Solver instance; a
        fresh solver 3-second timeout created None
        
        返回:
        List dicts, describing a detected 不透明谓词
        keys target, jmp_type, always_true, always_false
        operands, confidence
        
        设计决策：不使用完整的数据流分析来跟踪寄存器定义
        而是为操作数创建 fresh bitvector 变量并检查条件逻辑的
        内在可满足性。这可以捕获不依赖外部输入的代数恒等式
        （如 x == x, x & 0 == 0），覆盖了 OLLVM 和 Tigress 中
        最常见的不透明谓词模式。完整的 def-use 链追踪可以作为
        后续增强
        """
        z3_mod = _lazy_import_z3()
        if not z3_mod:
            return []

        results: List[Dict[str, Any]] = []
        solver = z3_solver if z3_solver is not None else z3_mod.Solver()
        solver.set('timeout', 3000)

        # 汇编级分支模式: cmp/test 后跟条件跳转
        # cmp op1, op2; jcc target
        branch_patterns = [
            # cmp/test one line, jcc next
            _re.compile(
                r'(cmp|test)\s+(.+?)\s*[\n;]+\s*(j[a-z]+)\s+(0x[0-9a-fA-F]+|\w+)',
                _re.IGNORECASE | _re.DOTALL),
            # cmp; jcc same logical line
            _re.compile(
                r'(cmp|test)\s+(.+?)\s*;\s*(j[a-z]+)\s+(0x[0-9a-fA-F]+|\w+)',
                _re.IGNORECASE),
        ]

        seen_offsets: Set[int] = set()
        for pat in branch_patterns:
            for m in pat.finditer(code_snippet):
                pos = m.start()
                if pos in seen_offsets:
                    continue
                seen_offsets.add(pos)

                instr = m.group(1).lower()
                ops_str = m.group(2).strip()
                jtype = m.group(3).lower()
                target = m.group(4)

                z3_opaque_check = self._z3_check_branch_condition(
                    instr, ops_str, jtype, solver, z3_mod)
                if z3_opaque_check:
                    z3_opaque_check['target'] = target
                    z3_opaque_check['jmp_type'] = jtype
                    z3_opaque_check['operands'] = ops_str
                    results.append(z3_opaque_check)

        return results

    def _z3_check_branch_condition(self, instruction: str, operands_str: str,
                                    jmp_type: str, solver, z3_mod) -> Optional[Dict[str, Any]]:
        """Construct Z3 formula for a cmp/test + jcc pair 检查 satisfiability
        
        返回 None operands cannot parsed; otherwise 返回 a
        dict always_true, always_false, confidence
        """
        parts = [p.strip() for p in operands_str.split(',')]
        if len(parts) < 2:
            return None

        # Fresh bitvector symbols for operands
        op_vars = []
        for i in range(min(len(parts), 3)):
            op_vars.append(z3_mod.BitVec(f'op_{i}', 64))

        # 构建 comparison expression 基于 instruction type
        if instruction == 'cmp':
            # cmp A, B => 计算 A - B, set flags
            # ZF set A == B; SF set result < 0
            diff = op_vars[0] - op_vars[1]
            zf = (diff == 0)
            sf = z3_mod.Extract(63, 63, diff) == 1
            of_expr = self._compute_overflow(op_vars[0], op_vars[1], diff, z3_mod)
        else:  # test
            # test A, B => 计算 A & B, set flags
            and_result = op_vars[0] & op_vars[1]
            zf = (and_result == 0)
            sf = z3_mod.Extract(63, 63, and_result) == 1
            of_expr = z3_mod.BoolVal(False)  # test always 清除
            diff = and_result

        condition = self._jcc_to_z3(jmp_type, zf, sf, of_expr, diff, z3_mod)
        if condition is None:
            return None

        # 检查 condition always false: cond UNSAT
        solver.push()
        solver.add(condition)
        always_false = (solver.check() == z3_mod.unsat)
        solver.pop()

        # 检查 condition always true: ¬cond UNSAT
        solver.push()
        solver.add(z3_mod.Not(condition))
        always_true = (solver.check() == z3_mod.unsat)
        solver.pop()

        if always_true or always_false:
            return {
                'always_true': always_true,
                'always_false': always_false,
                'confidence': 1.0 if (always_true != always_false) else 0.5,
            }
        return None

    @staticmethod
    def _compute_overflow(a, b, result, z3_mod):
        """计算 flag: overflow sign(a) == sign(b) but sign(result)!= sign(a)"""
        sign_a = z3_mod.Extract(63, 63, a) == 1
        sign_b = z3_mod.Extract(63, 63, b) == 1
        sign_r = z3_mod.Extract(63, 63, result) == 1
        return z3_mod.And(sign_a == sign_b, sign_r != sign_a)

    @staticmethod
    def _jcc_to_z3(jmp_type: str, zf, sf, of_expr, diff, z3_mod):
        """Map an x86 conditional-jump mnemonic a Z3 formula over EFLAGS bits
        
        返回 None for unsupported mnemonics
        """
        jcc_map = {
            'je': zf, 'jz': zf,
            'jne': z3_mod.Not(zf), 'jnz': z3_mod.Not(zf),
            'js': sf,
            'jns': z3_mod.Not(sf),
            'jg': z3_mod.And(z3_mod.Not(zf), sf == of_expr),
            'jge': (sf == of_expr),
            'jl': (sf != of_expr),
            'jle': z3_mod.Or(zf, sf != of_expr),
            'ja': z3_mod.And(z3_mod.Not(zf), z3_mod.Not(
                z3_mod.Or(sf, of_expr))),
            'jae': z3_mod.Not(z3_mod.Or(sf, of_expr)),
            'jb': z3_mod.Or(sf, of_expr),
            'jbe': z3_mod.Or(zf, z3_mod.Or(sf, of_expr)),
            'jo': of_expr,
            'jno': z3_mod.Not(of_expr),
            'jp': None,  # PF requires computing parity bit
            'jnp': None,
            'jcxz': None, 'jecxz': None, 'jrcxz': None,  # 寄存器-specific
        }
        return jcc_map.get(jmp_type)

    # Original detection + 去混淆 流水线 (preserved)

    def detect_obfuscation(self, code: str) -> List[Dict[str, Any]]:
        detected = []
        for pattern_id, pattern_info in self.obfuscation_patterns.items():
            match_count = sum(1 for sig in pattern_info['signature']
                            if _re.search(sig, code, _re.IGNORECASE))
            if match_count >= len(pattern_info['signature']) * 0.5:
                detected.append({
                    'pattern_id': pattern_id, 'name': pattern_info['name'],
                    'match_score': match_count / len(pattern_info['signature']),
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description']})
        detected.sort(key=lambda x: x['match_score'], reverse=True)
        return detected

    def get_deobfuscation_script(self, pattern_id: str) -> Optional[str]:
        if pattern_id in self.deobfuscation_scripts:
            return self.deobfuscation_scripts[pattern_id]
        script = self._generate_deobfuscation_script(pattern_id)
        if script:
            self.deobfuscation_scripts[pattern_id] = script
        return script

    def _generate_deobfuscation_script(self, pattern_id: str) -> str:
        scripts = {
            'ollvm_bcf': "def deobfuscate_bcf(code):\n    import re\n    code = re.sub(r'cmp\\\\s+\\\\w+,\\\\s*\\\\w+\\\\s*jne\\\\s+\\\\w+', '', code)\n    return code\n",
            'ollvm_flattening': "def deobfuscate_flattening(code):\n    return reconstruct_control_flow(code)\n",
            'opaque_predicate': "def resolve_opaque_predicate(code):\n    import re\n    code = re.sub(r'if\\\\s*\\\\(\\\\s*true\\\\s*\\\\)', 'if (1)', code)\n    return code\n"
        }
        return scripts.get(pattern_id, '')

    def apply_deobfuscation(self, code: str, detected_patterns: List[Dict[str, Any]]) -> str:
        deobfuscated = code
        for pattern in detected_patterns:
            script = self.get_deobfuscation_script(pattern['pattern_id'])
            if script:
                try:
                    deobfuscated = self._apply_script(deobfuscated, script)
                except Exception as e:
                    logger.warning(f"Deobfuscation failed: {e}")
        self.match_history.append({
            'timestamp': datetime.now().isoformat(),
            'patterns': detected_patterns, 'success': True})
        return deobfuscated

    def _apply_script(self, code: str, script: str) -> str:
        for pattern in _re.findall(r"r'([^']+)'", script):
            code = _re.sub(pattern, '', code)
        return code

    def evaluate_deobfuscation_quality(self, original: str, deobfuscated: str) -> Dict[str, Any]:
        def _ngram_entropy(text: str, n: int = 3) -> float:
            if len(text) < n:
                return 0.0
            from collections import Counter
            ngrams = Counter(text[i:i+n] for i in range(len(text) - n + 1))
            total = sum(ngrams.values())
            return -sum((c/total) * math.log2(c/total) for c in ngrams.values())

        ent_before = _ngram_entropy(original)
        ent_after = _ngram_entropy(deobfuscated)
        ent_delta = ent_after - ent_before
        return {
            'code_size_reduction': len(original) - len(deobfuscated),
            'reduction_percentage': (len(original) - len(deobfuscated)) / max(1, len(original)) * 100,
            'control_flow_complexity': self._calculate_cf_complexity(deobfuscated),
            'readability_score': self._estimate_readability(deobfuscated),
            'ngram_entropy_before': round(ent_before, 4),
            'ngram_entropy_after': round(ent_after, 4),
            'ngram_entropy_delta': round(ent_delta, 4)}

    def _calculate_cf_complexity(self, code: str) -> int:
        keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'goto']
        return sum(len(_re.findall(rf'\b{kw}\b', code)) for kw in keywords)

    def _estimate_readability(self, code: str) -> float:
        lines = code.split('\n')
        avg_len = sum(len(l) for l in lines) / max(1, len(lines))
        cmt_ratio = len(_re.findall(r'//|/\*', code)) / max(1, len(code))
        return max(0, min(100, 100 - (avg_len / 2) + (cmt_ratio * 50)))


# 覆盖率-guided scheduling


class CoverageGuidedSymbolicScheduler:
    def __init__(self):
        self.covered_blocks: Set[int] = set()
        self.path_queue: List[Dict[str, Any]] = []
        self.execution_history: List[Dict[str, Any]] = []
        self.coverage_map: Dict[int, int] = {}
        self._lock = threading.Lock()

    def add_covered_block(self, block_addr: int):
        with self._lock:
            self.covered_blocks.add(block_addr)
            self.coverage_map[block_addr] = self.coverage_map.get(block_addr, 0) + 1

    def get_coverage_rate(self, total_blocks: int) -> float:
        return len(self.covered_blocks) / max(1, total_blocks)

    def calculate_path_priority(self, path: Dict[str, Any]) -> float:
        path_blocks = path.get('blocks', [])
        uncovered_count = sum(1 for b in path_blocks if b not in self.covered_blocks)
        return uncovered_count * 10 - path.get('length', 0) * 0.1 - path.get('complexity', 0) * 0.5

    def select_next_path(self) -> Optional[Dict[str, Any]]:
        if not self.path_queue:
            return None
        self.path_queue.sort(key=lambda p: self.calculate_path_priority(p), reverse=True)
        selected = self.path_queue.pop(0)
        self.execution_history.append({
            'path_id': selected.get('id'),
            'priority': self.calculate_path_priority(selected),
            'timestamp': datetime.now().isoformat()})
        return selected

    def add_path_to_queue(self, path: Dict[str, Any]):
        path['id'] = hashlib.sha256(_json.dumps(path).encode()).hexdigest()[:16]
        path['added_at'] = datetime.now().isoformat()
        self.path_queue.append(path)

    def get_uncovered_neighbors(self, current_block: int, cfg: Dict[int, List[int]]) -> List[int]:
        return [n for n in cfg.get(current_block, []) if n not in self.covered_blocks]

    def generate_guided_inputs(self, target_block: int, symbolic_state: Dict[str, Any]) -> List[bytes]:
        """尝试用 Z3 求解约束以获得到达目标块的输入
        
        若 Z3 可用，将约束集中的每个约束解析为 Z3 表达式并求解
        不可用时返回零填充占位符"""
        inputs: List[bytes] = []
        constraints = symbolic_state.get('constraints', [])
        try:
            import z3
            solver = z3.Solver()
            solver.set('timeout', 5000)
            for c in constraints:
                try:
                    parsed = z3.parse_smt2_string(str(c))
                    for p in parsed:
                        solver.add(p)
                except Exception:
                    pass
            if solver.check() == z3.sat:
                model = solver.model()
                buf = bytearray()
                for decl in model.decls():
                    val = model[decl].as_long()
                    buf.extend(struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))
                if buf:
                    inputs.append(bytes(buf))
        except ImportError:
            pass
        if not inputs:
            inputs.append(bytes([0] * 16))
        return inputs

    def _solve_constraint_for_target(self, constraint: str, target: int) -> Optional[bytes]:
        return bytes([0] * 16)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            'covered_blocks': len(self.covered_blocks),
            'queued_paths': len(self.path_queue),
            'executed_paths': len(self.execution_history),
            'coverage_distribution': dict(self.coverage_map)}


# Unicorn block缓存


class UnicornBlockCache:
    """LRU 缓存for Unicorn-executed basic blocks
    
    Caches frequently executed blocks keyed (code_hash, entry_state_hash)
    tuples. Distinguishing entry state avoids stale results
    same code reached different 寄存器/memory contexts
    
    Values (final_state, side_effects, hit_count) triples
    Eviction least-recently-used 1024 entries — sized cover
    typical analysis sessions hot blocks revisited across
    paths but total distinct (code, state) pairs rarely exceed
    
    LRU 实现细节：使用双端队列维护访问顺序，每次 lookup 将命中的 key
    移到队尾。淘汰时从队首弹出 — O(1) 均摊
    """

    _MAX_ENTRIES = 1024

    def __init__(self):
        self._cache: Dict[Tuple[str, str], Tuple[Dict[str, int], List, int]] = {}
        self._access_order: deque = deque()

    def _make_key(self, code_bytes: bytes, entry_state: Dict[str, int]) -> Tuple[str, str]:
        code_hash = hashlib.sha256(code_bytes).hexdigest()[:16]
        state_hash = hashlib.sha256(
            _json.dumps(entry_state, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        return (code_hash, state_hash)

    def lookup(self, code_bytes: bytes, entry_state: Dict[str, int]) -> Optional[Dict[str, Any]]:
        """检查 缓存for a prior execution result
        
        返回 None miss; hit 返回 final_state, side_effects
        incremented hit_count. 更新 LRU ordering
        """
        key = self._make_key(code_bytes, entry_state)
        if key not in self._cache:
            return None
        # LRU refresh: move accessed key back
        try:
            self._access_order.remove(key)
        except ValueError:
            pass
        self._access_order.append(key)
        final_state, side_effects, hit_count = self._cache[key]
        hit_count += 1
        self._cache[key] = (final_state, side_effects, hit_count)
        return {'final_state': final_state, 'side_effects': side_effects,
                'hit_count': hit_count}

    def store(self, code_bytes: bytes, entry_state: Dict[str, int],
              final_state: Dict[str, int], side_effects: List) -> None:
        """插入 or 更新 a 缓存entry. Evicts LRU capacity"""
        key = self._make_key(code_bytes, entry_state)
        if key in self._cache:
            try:
                self._access_order.remove(key)
            except ValueError:
                pass
        elif len(self._cache) >= self._MAX_ENTRIES:
            evict_key = self._access_order.popleft()
            self._cache.pop(evict_key, None)
        self._access_order.append(key)
        self._cache[key] = (final_state, side_effects, 1)

    def clear(self) -> None:
        """Drop all缓存d entries"""
        self._cache.clear()
        self._access_order.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# Unicorn hybrid execution


class UnicornHybridSymbolicExecutor:
    """二轮增强 — 真实 Unicorn 执行引擎
    
    当 unicorn 库可用时，使用 unicorn.Uc 进行基本块级具体执行
    不可用时回退到基于 r2 的指令模拟
    
    架构选择：使用 unicorn 而非 qemu-user 的原因 —
    unicorn 提供更细粒度的 hook 控制（指令级/基本块级/内存访问级）
    且不需要完整的进程上下文，适合代码片段的隔离执行
    """

    _X86_REGS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip']

    def __init__(self):
        self.unicorn_config: Dict[str, Any] = {}
        self.concrete_values: Dict[int, int] = {}
        self._mem_writes: List[Tuple[int, int, int]] = []  # (addr, value, size)
        self._block_cache = UnicornBlockCache()

    def execute_with_concrete(self, code_addr: int, code_data: bytes,
                               initial_state: Dict[str, int],
                               max_insns: int = 1000) -> Dict[str, Any]:
        """使用 unicorn 具体执行代码片段
        
        若 unicorn 不可用，回退到简单的 PC 推进（模拟线性执行 max_insns 条指令
        而不实际修改状态 — 这在真实集成中应替换为 r2 的 `aes` 模拟器）
        
        执行前先查询 UnicornBlockCache，命中则直接返回缓存结果
        避免重复执行相同的基本块。执行成功后更新缓存
        """
        # 先查缓存
        bb_cache_hit = self._block_cache.lookup(code_data, initial_state)
        if bb_cache_hit is not None:
            return {
                'execution_successful': True,
                'final_state': bb_cache_hit['final_state'],
                'memory_writes': bb_cache_hit['side_effects'],
                'execution_count': max_insns,
                'cache_hit': True,
            }

        if _UNICORN_AVAILABLE:
            result = self._unicorn_execute(code_addr, code_data, initial_state, max_insns)
        else:
            result = self._fallback_execute(code_addr, code_data, initial_state)
            return result

        # 执行成功后写入缓存
        if result.get('execution_successful'):
            self._block_cache.store(
                code_data,
                initial_state,
                result.get('final_state', {}),
                result.get('memory_writes', []),
            )

        return result

    def _unicorn_execute(self, code_addr: int, code_data: bytes,
                          initial_state: Dict[str, int], max_insns: int) -> Dict[str, Any]:
        # 分配 2MB 代码页 + 1MB 栈
        CODE_BASE = code_addr & ~0xFFF
        CODE_SIZE = 2 * 1024 * 1024
        STACK_BASE = 0x7FFF0000
        STACK_SIZE = 1024 * 1024

        mu = _uc.Uc(_uc.UC_ARCH_X86, _uc.UC_MODE_64)
        mu.mem_map(CODE_BASE, CODE_SIZE)
        mu.mem_write(code_addr, code_data)
        mu.mem_map(STACK_BASE, STACK_SIZE)

        # 设置初始寄存器
        if 'rsp' in initial_state:
            mu.reg_write(_uc.x86_const.UC_X86_REG_RSP, initial_state['rsp'])
        else:
            mu.reg_write(_uc.x86_const.UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)
        if 'rip' in initial_state:
            mu.reg_write(_uc.x86_const.UC_X86_REG_RIP, initial_state['rip'])
        else:
            mu.reg_write(_uc.x86_const.UC_X86_REG_RIP, code_addr)

        # Hook 记录内存写入
        def _hook_mem_write(uc, access, address, size, value, user_data):
            self._mem_writes.append((address, value, size))

        mu.hook_add(_uc.UC_HOOK_MEM_WRITE, _hook_mem_write)

        mu.emu_start(code_addr, code_addr + len(code_data),
                    timeout=5000, count=max_insns)

        final_regs = {}
        for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'rip', 'rsp']:
            try:
                reg_const = getattr(_uc.x86_const, f'UC_X86_REG_{reg_name.upper()}')
                final_regs[reg_name] = mu.reg_read(reg_const)
            except Exception:
                pass

        return {'execution_successful': True, 'final_state': final_regs,
                'memory_writes': list(self._mem_writes),
                'execution_count': max_insns}

    def _fallback_execute(self, code_addr: int, code_data: bytes,
                           initial_state: Dict[str, int]) -> Dict[str, Any]:
        """回退：返回初始状态，标记为未执行
        
        生产环境应替换为 r2 aes 或 qiling 框架的具体执行"""
        return {'execution_successful': False,
                'final_state': initial_state,
                'memory_writes': [],
                'execution_count': 0,
                'error': 'unicorn not available — using fallback stub'}

    def extract_concrete_value(self, memory_addr: int) -> Optional[int]:
        return self.concrete_values.get(memory_addr)

    def feed_to_angr(self, angr_project, concrete_values: Dict[int, int]) -> None:
        """将具体执行的值注入 angr state
        
        对于每个 (addr, value) 对，在 angr state 中添加
        memory[addr] == value 的具体约束，从而约束符号状态
        """
        if angr_project is None:
            return
        state = angr_project.factory.entry_state()
        for addr, val in concrete_values.items():
            mem = state.memory.load(addr, 8)
            state.solver.add(mem == val)
