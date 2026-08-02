# 2026-07-16

import logging
import struct
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple

logger = logging.getLogger(__name__)

@dataclass
class OpaquePredicate:
    address: int; type: str; confidence: float
    pattern: str = ""; evidence: str = ""


def _try_import_capstone():
    try:
        import capstone as cs
        return cs
    except ImportError:
        return None

def _is_jcc(mnem: str) -> bool:
    jcc_prefixes = {'j', 'jn', 'jb', 'jbe', 'ja', 'jae', 'jl', 'jle', 'jg', 'jge',
                    'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jz', 'jnz', 'je', 'jne',
                    'jc', 'jnc', 'jcxz', 'jecxz'}
    m_lower = mnem.lower().strip()
    return m_lower in jcc_prefixes or m_lower.startswith('j') and len(m_lower) > 1

def _resolve_reg_name(op_str: str, mode: int) -> Optional[str]:
    import re
    m = re.match(r'([a-z]{2,4})(?:\s*,|$)', op_str.lower().strip())
    return m.group(1) if m else None


def _detect_static_opaque(func_bytes: bytes, base_addr: int) -> List[OpaquePredicate]:
    cs = _try_import_capstone()
    if cs is None:
        return []
    results = []
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(func_bytes, base_addr))

    for i, insn in enumerate(instructions):
        mnem = insn.mnemonic.lower().strip()
        op_str = insn.op_str
        addr = insn.address

        if mnem == 'cmp':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2:
                r1 = _resolve_reg_name(parts[0], md.mode)
                r2 = _resolve_reg_name(parts[1], md.mode)
                if r1 and r2 and r1 == r2:
                    if i + 1 < len(instructions):
                        next_insn = instructions[i + 1]
                        if _is_jcc(next_insn.mnemonic):
                            j_type = 'always_false' if next_insn.mnemonic.lower() in {'jnz', 'jne'} else 'always_true'
                            results.append(OpaquePredicate(
                                address=addr, type=j_type, confidence=0.99,
                                pattern='cmp_reg_reg',
                                evidence=f'{insn.mnemonic} {op_str} -> {next_insn.mnemonic}'))
        elif mnem == 'test':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2 and parts[1] == '0':
                r1 = _resolve_reg_name(parts[0], md.mode)
                if r1 and i + 1 < len(instructions):
                    next_insn = instructions[i + 1]
                    if _is_jcc(next_insn.mnemonic):
                        j_type = 'always_false' if next_insn.mnemonic.lower() in {'jnz', 'jne'} else 'always_true'
                        results.append(OpaquePredicate(
                            address=addr, type=j_type, confidence=0.98,
                            pattern='test_reg_0',
                            evidence=f'{insn.mnemonic} {op_str} -> {next_insn.mnemonic}'))
        elif mnem == 'xor':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2:
                r1 = _resolve_reg_name(parts[0], md.mode)
                r2 = _resolve_reg_name(parts[1], md.mode)
                if r1 and r2 and r1 == r2:
                    if i + 1 < len(instructions):
                        next_insn = instructions[i + 1]
                        if _is_jcc(next_insn.mnemonic):
                            j_type = 'always_false' if next_insn.mnemonic.lower() in {'jnz', 'jne'} else 'always_true'
                            results.append(OpaquePredicate(
                                address=addr, type=j_type, confidence=0.99,
                                pattern='xor_reg_reg',
                                evidence=f'{insn.mnemonic} {op_str} -> {next_insn.mnemonic}'))
        elif mnem == 'sub':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2:
                r1 = _resolve_reg_name(parts[0], md.mode)
                r2 = _resolve_reg_name(parts[1], md.mode)
                if r1 and r2 and r1 == r2:
                    if i + 1 < len(instructions):
                        next_insn = instructions[i + 1]
                        if _is_jcc(next_insn.mnemonic):
                            j_type = 'always_false' if next_insn.mnemonic.lower() in {'jnz', 'jne'} else 'always_true'
                            results.append(OpaquePredicate(
                                address=addr, type=j_type, confidence=0.99,
                                pattern='sub_reg_reg',
                                evidence=f'{insn.mnemonic} {op_str} -> {next_insn.mnemonic}'))
        elif mnem == 'or':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2:
                try:
                    imm_val = int(parts[1], 0)
                    if imm_val == -1 or imm_val == 0xFFFFFFFF:
                        if i + 1 < len(instructions):
                            next_insn = instructions[i + 1]
                            if _is_jcc(next_insn.mnemonic):
                                j_type = 'always_true' if next_insn.mnemonic.lower() in {'js', 'jl'} else 'always_false'
                                results.append(OpaquePredicate(
                                    address=addr, type=j_type, confidence=0.97,
                                    pattern='or_reg_minus1',
                                    evidence=f'{insn.mnemonic} {op_str} -> {next_insn.mnemonic}'))
                except (ValueError, IndexError):
                    pass
        elif mnem == 'and':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2 and parts[1] == '0':
                r1 = _resolve_reg_name(parts[0], md.mode)
                if r1 and i + 1 < len(instructions):
                    next_insn = instructions[i + 1]
                    if _is_jcc(next_insn.mnemonic):
                        j_type = 'always_false' if next_insn.mnemonic.lower() in {'jnz', 'jne'} else 'always_true'
                        results.append(OpaquePredicate(
                            address=addr, type=j_type, confidence=0.97,
                            pattern='and_reg_0',
                            evidence=f'{insn.mnemonic} {op_str} -> {next_insn.mnemonic}'))
        elif mnem == 'cmp':
            parts = [p.strip() for p in op_str.split(',')]
            if len(parts) == 2:
                r1 = _resolve_reg_name(parts[0], md.mode)
                try:
                    imm = int(parts[1], 0)
                except ValueError:
                    imm = None
                if r1 and imm is not None:
                    for j_idx in range(max(0, i - 5), i):
                        prev = instructions[j_idx]
                        if prev.mnemonic.lower() == 'cmp':
                            prev_parts = [x.strip() for x in prev.op_str.split(',')]
                            if len(prev_parts) == 2:
                                prev_r = _resolve_reg_name(prev_parts[0], md.mode)
                                try:
                                    prev_imm = int(prev_parts[1], 0)
                                except ValueError:
                                    prev_imm = None
                                if prev_r == r1 and prev_imm == imm:
                                    if i + 1 < len(instructions):
                                        next_insn = instructions[i + 1]
                                        if _is_jcc(next_insn.mnemonic):
                                            results.append(OpaquePredicate(
                                                address=addr, type='always_true', confidence=0.92,
                                                pattern='redundant_cmp',
                                                evidence=f'prev {prev.op_str} == curr {op_str}'))
    return results


def _try_import_angr():
    try:
        import angr, claripy
        return angr, claripy
    except ImportError:
        return None, None

def _angr_find_opaque(binary_path: str, target_func_addr: int) -> List[OpaquePredicate]:
    angr, claripy = _try_import_angr()
    if angr is None:
        return []
    results = []
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
    except Exception as e:
        logger.warning("angr project load failed: %s", e)
        return results
    cfg = proj.analyses.CFGFast()
    func = proj.kb.functions.get(target_func_addr) or cfg.functions.get(target_func_addr)
    if func is None:
        return results
    try:
        state = proj.factory.blank_state(addr=func.addr)
    except Exception:
        return results
    simgr = proj.factory.simulation_manager(state)
    try:
        simgr.step(n=50)
    except Exception:
        pass
    for st in simgr.active:
        if not hasattr(st, 'history') or not hasattr(st.history, 'events'):
            continue
        for ev in st.history.events:
            if hasattr(ev, 'constrained') and ev.constrained is not None:
                try:
                    s = claripy.Solver(); s.add(ev.constrained)
                    check_true = s.satisfiable()
                    s2 = claripy.Solver(); s2.add(claripy.Not(ev.constrained))
                    check_false = s2.satisfiable()
                    if check_true and not check_false:
                        results.append(OpaquePredicate(
                            address=ev.ins_addr if hasattr(ev, 'ins_addr') else target_func_addr,
                            type='always_true', confidence=0.95,
                            pattern='angr_constrained_true', evidence=str(ev.constrained)[:80]))
                    elif not check_true and check_false:
                        results.append(OpaquePredicate(
                            address=ev.ins_addr if hasattr(ev, 'ins_addr') else target_func_addr,
                            type='always_false', confidence=0.95,
                            pattern='angr_constrained_false', evidence=str(ev.constrained)[:80]))
                except Exception:
                    pass
    return results


def _compute_opaqueness_score(results: List[OpaquePredicate]) -> float:
    if not results:
        return 0.0
    pattern_weights = {
        'cmp_reg_reg': 1.0, 'xor_reg_reg': 1.0, 'test_reg_0': 0.95,
        'sub_reg_reg': 0.9, 'and_reg_0': 0.95, 'or_reg_minus1': 0.9,
        'redundant_cmp': 0.85,
        'angr_constrained_true': 1.0, 'angr_constrained_false': 1.0}
    total = sum(pattern_weights.get(r.pattern, 0.5) * r.confidence for r in results)
    return min(1.0, total / max(len(results), 1))


def _find_nested_predicates(predicates: List[OpaquePredicate], gap_threshold: int = 32) -> List[List[OpaquePredicate]]:
    if not predicates:
        return []
    sorted_preds = sorted(predicates, key=lambda p: p.address)
    clusters, current = [], [sorted_preds[0]]
    for i in range(1, len(sorted_preds)):
        if sorted_preds[i].address - current[-1].address <= gap_threshold:
            current.append(sorted_preds[i])
        else:
            clusters.append(current); current = [sorted_preds[i]]
    clusters.append(current)
    return [c for c in clusters if len(c) > 1]


# ---------------------------------------------------------------------------
# Z3 表达式提取 —— 从 Capstone 反汇编指令序列中提取符号表达式
# 用于直接验证两条指令序列的等价性。支持常见的 x86 算术/逻辑操作。
# ---------------------------------------------------------------------------

def _try_import_z3():
    try:
        import z3
        return z3
    except ImportError:
        return None


def lift_instructions_to_z3(instructions: List[str],
                             bit_width: int = 32) -> Optional[Dict[str, any]]:
    """将指令序列提升为 Z3 表达式和符号变量映射。
    返回 {'exprs': {dest_reg: z3_expr, ...}, 'symbols': {reg: BitVec, ...}}
    """
    z3 = _try_import_z3()
    if z3 is None:
        return None

    import re as _re
    symbols: Dict[str, any] = {}
    exprs: Dict[str, any] = {}

    def _get_or_create_sym(name: str):
        if name not in symbols:
            symbols[name] = z3.BitVec(name, bit_width)
        return symbols[name]

    for instr in instructions:
        parts = instr.split('=', 1)
        if len(parts) != 2:
            continue
        lhs = parts[0].strip()
        rhs = parts[1].strip()

        # 解析简单表达式: reg = reg op reg, reg = reg op imm, reg = ~reg
        m_bin = _re.match(r'(\w+)\s*([+\-*&|^])\s*(\w+|0x[0-9a-fA-F]+|\d+)', rhs)
        m_un = _re.match(r'~(\w+)', rhs)
        m_mov = _re.match(r'(\w+|0x[0-9a-fA-F]+|\d+)$', rhs)

        if m_bin:
            op1 = m_bin.group(1)
            op_symbol = m_bin.group(2)
            op2 = m_bin.group(3)
            left = _get_or_create_sym(op1)
            if op2.startswith('0x') or op2.isdigit():
                right = z3.BitVecVal(int(op2, 0), bit_width)
            else:
                right = _get_or_create_sym(op2)
            mapping = {'+': lambda a, b: a + b, '-': lambda a, b: a - b,
                       '*': lambda a, b: a * b, '&': lambda a, b: a & b,
                       '|': lambda a, b: a | b, '^': lambda a, b: a ^ b}
            exprs[lhs] = mapping[op_symbol](left, right)
        elif m_un:
            operand = _get_or_create_sym(m_un.group(1))
            exprs[lhs] = ~operand
        elif m_mov:
            val = m_mov.group(1)
            if val.startswith('0x') or val.isdigit():
                exprs[lhs] = z3.BitVecVal(int(val, 0), bit_width)
            else:
                exprs[lhs] = _get_or_create_sym(val)

    return {'exprs': exprs, 'symbols': symbols}


def verify_instruction_equivalence(seq_a: List[str], seq_b: List[str],
                                    target_reg: str,
                                    bit_width: int = 32) -> Optional[bool]:
    """验证两条指令序列在目标寄存器上的等价性。"""
    lifted_a = lift_instructions_to_z3(seq_a, bit_width)
    lifted_b = lift_instructions_to_z3(seq_b, bit_width)
    if lifted_a is None or lifted_b is None:
        return None

    z3 = _try_import_z3()
    if z3 is None:
        return None

    expr_a = lifted_a['exprs'].get(target_reg)
    expr_b = lifted_b['exprs'].get(target_reg)
    if expr_a is None or expr_b is None:
        return None

    all_syms = set(lifted_a['symbols']) | set(lifted_b['symbols'])
    unified = {}
    for s in all_syms:
        unified[s] = z3.BitVec(s, bit_width)

    def _substitute(expr, syms):
        for name, bv in syms.items():
            expr = z3.substitute(expr, (z3.BitVec(name, bit_width), bv))
        return expr

    ea = _substitute(expr_a, unified)
    eb = _substitute(expr_b, unified)

    solver = z3.Solver()
    solver.add(ea != eb)
    return solver.check() == z3.unsat


class SymbolicExecutor:
    """Opaque predicate detection via capstone + angr + Z3."""

    def __init__(self, binary_path: str, angr_enabled: bool = True):
        self.binary_path = binary_path
        self.data: bytes = b''
        self._angr, self._claripy = (None, None)
        if angr_enabled:
            self._angr, self._claripy = _try_import_angr()
        try:
            with open(binary_path, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            logger.warning("cannot read binary: %s", e)

    def find_opaque_predicates(self, func_addr: int, func_size: int = 4096) -> List[OpaquePredicate]:
        results = []
        end = min(func_addr + func_size, len(self.data))
        func_bytes = self.data[func_addr:end]
        cap_results = _detect_static_opaque(func_bytes, func_addr)
        results.extend(cap_results)
        if self._angr is not None:
            try:
                angr_results = _angr_find_opaque(self.binary_path, func_addr)
                cap_addrs = {r.address for r in cap_results}
                for r in angr_results:
                    if r.address not in cap_addrs:
                        results.append(r)
            except Exception as e:
                logger.debug("angr path failed: %s", e)
        results.sort(key=lambda r: r.address)
        return results

    def get_opaque_score(self, func_addr: int, func_size: int = 4096) -> float:
        return _compute_opaqueness_score(self.find_opaque_predicates(func_addr, func_size))

    def find_nested(self, func_addr: int, func_size: int = 4096) -> List[List[OpaquePredicate]]:
        return _find_nested_predicates(self.find_opaque_predicates(func_addr, func_size))

    def classify(self, func_addr: int, func_size: int = 4096) -> Dict:
        preds = self.find_opaque_predicates(func_addr, func_size)
        always_true = [p for p in preds if p.type == 'always_true']
        always_false = [p for p in preds if p.type == 'always_false']
        nested = self.find_nested(func_addr, func_size)
        return {
            'total': len(preds),
            'always_true': len(always_true), 'always_false': len(always_false),
            'nested_groups': len(nested),
            'opaqueness_score': round(_compute_opaqueness_score(preds), 3),
            'top_predicates': preds[:5]}
