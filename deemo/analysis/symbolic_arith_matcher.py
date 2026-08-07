"""
符号执行指令匹配器 — 从汇编IR行中识别并应用算术/内存/分支操作.

保持单一职责: IR模式→状态变换.
所有函数返回 bool 表示是否匹配成功, 通过修改传入的 state 生效.

同时定义 SymExpr (符号表达式) 以避免循环导入.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional


# SymExpr — 符号表达式: base + Σ coef_i * sym_i

@dataclass
class SymExpr:
    """符号表达式: base + Σ coef_i * sym_i."""
    base: int = 0
    terms: Dict[str, int] = field(default_factory=dict)

    def eval_bounds(self, sym_ranges: Dict[str, Tuple[int, int]]) -> Tuple[int, int]:
        lo = hi = self.base
        for sym, coef in self.terms.items():
            slo, shi = sym_ranges.get(sym, (0, 2**20))
            if coef >= 0:
                lo += coef * slo
                hi += coef * shi
            else:
                lo += coef * shi
                hi += coef * slo
        return max(0, lo), hi

    def add_constant(self, n: int) -> "SymExpr":
        return SymExpr(self.base + n, dict(self.terms))

    def mul_constant(self, n: int) -> "SymExpr":
        if n == 0:
            return SymExpr(0)
        return SymExpr(self.base * n, {s: c * n for s, c in self.terms.items()})

    def shl_constant(self, n: int) -> "SymExpr":
        return SymExpr(self.base << n, {s: c << n for s, c in self.terms.items()})

    def __repr__(self) -> str:
        parts = [f"{c}*{s}" for s, c in self.terms.items()]
        if self.base:
            parts.append(str(self.base))
        return "Sym(" + "+".join(parts or ["0"]) + ")"


def sym_const(n: int) -> SymExpr:
    """创建常量符号表达式."""
    return SymExpr(n)


# 指令匹配器

def try_arith_insn(tl: str, regs: Dict, locals_map: Dict) -> bool:
    """匹配算术/数据移动指令, 修改 regs/locals_map.

    支持: mov imm, mov reg, add, sub, imul, shl, xor, lea, movzx, movsx.
    """
    # mov reg, imm
    m = re.match(r'mov\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$', tl)
    if m:
        regs[m.group(1)] = sym_const(int(m.group(2), 0))
        return True

    # mov reg, reg
    m = re.match(r'mov\s+(\w+)\s*,\s*(\w+)\s*$', tl)
    if m:
        src = regs.get(m.group(2))
        if src:
            regs[m.group(1)] = src
        return True

    # add reg, imm
    m = re.match(r'add\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', tl)
    if m and m.group(1) in regs:
        regs[m.group(1)] = regs[m.group(1)].add_constant(int(m.group(2), 0))
        return True

    # sub reg, imm
    m = re.match(r'sub\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', tl)
    if m and m.group(1) in regs:
        regs[m.group(1)] = regs[m.group(1)].add_constant(-int(m.group(2), 0))
        return True

    # imul reg, reg, imm
    m = re.match(r'imul\s+(\w+)\s*,\s*(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', tl)
    if m and m.group(2) in regs:
        regs[m.group(1)] = regs[m.group(2)].mul_constant(int(m.group(3), 0))
        return True

    # shl reg, imm
    m = re.match(r'shl\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', tl)
    if m and m.group(1) in regs:
        regs[m.group(1)] = regs[m.group(1)].shl_constant(int(m.group(2), 0))
        return True

    # xor reg, reg (清零)
    m = re.match(r'xor\s+(\w+)\s*,\s*\1', tl)
    if m:
        regs[m.group(1)] = sym_const(0)
        return True

    # lea reg, [reg + reg*scale]
    m = re.match(
        r'lea\s+(\w+)\s*,\s*\[(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\]', tl)
    if m:
        base = regs.get(m.group(2))
        idx = regs.get(m.group(3))
        scale = int(m.group(4))
        if base and idx:
            regs[m.group(1)] = SymExpr(
                base.base + idx.base * scale,
                {s: base.terms.get(s, 0) + idx.terms.get(s, 0) * scale
                 for s in set(base.terms) | set(idx.terms)})
        return True

    # lea reg, [reg + imm]
    m = re.match(
        r'lea\s+(\w+)\s*,\s*\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', tl)
    if m and m.group(2) in regs:
        regs[m.group(1)] = regs[m.group(2)].add_constant(
            int(m.group(3), 0))
        return True

    # movzx (零扩展) — 作为赋值传递
    m = re.match(
        r'movzx\s+(\w+)\s*,\s*(?:byte|word|dword)\s*(?:ptr\s*)?\[?(\w+)\]?', tl)
    if m:
        src = regs.get(m.group(2))
        if src:
            regs[m.group(1)] = src
        return True

    # movsx (符号扩展) — 作为赋值传递
    m = re.match(
        r'movsx\s+(\w+)\s*,\s*(?:byte|word|dword)\s*(?:ptr\s*)?\[?(\w+)\]?', tl)
    if m:
        src = regs.get(m.group(2))
        if src:
            regs[m.group(1)] = src
        return True

    return False


def try_load_store_insn(tl: str, regs: Dict, locals_map: Dict) -> bool:
    """匹配局部变量加载/存储: mov [rbp-N], reg 和 mov reg, [rbp-N]."""
    # store to local: mov [rbp-N], reg
    m = re.match(
        r'mov\s*\[rbp\s*[-+]\s*(0x[0-9a-fA-F]+|\d+)\]\s*,\s*(\w+)', tl)
    if m:
        offset = int(m.group(1), 0)
        src = regs.get(m.group(2))
        if src:
            locals_map[f"local_{offset:x}"] = src
        return True

    # load from local: mov reg, [rbp-N]
    m = re.match(
        r'mov\s+(\w+)\s*,\s*\[rbp\s*[-+]\s*(0x[0-9a-fA-F]+|\d+)\]', tl)
    if m:
        offset = int(m.group(2), 0)
        src = locals_map.get(f"local_{offset:x}")
        if src:
            regs[m.group(1)] = src
        return True

    return False


# 条件分支匹配 (cmp + jcc)

_CMP_PAT = re.compile(r'cmp\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+|\w+)')
_JCC_MAP = {
    'jle': '<=', 'jbe': '<=', 'jge': '>=', 'jae': '>=',
    'jl': '<',  'jb': '<',  'jg': '>',  'ja': '>',
    'je': '==', 'jne': '!=',
}


def try_conditional_insn(insns, idx: int, regs: Dict,
                         symbols: Dict, constraints: list,
                         path_count_ref: list) -> bool:
    """匹配 cmp + jcc 对, 更新路径约束.

    Returns: True if a conditional was processed (consumes 2 insns).
    constraints 和 path_count_ref 通过引用修改.
    """
    if idx + 1 >= len(insns):
        return False
    _addr0, tl0 = insns[idx]
    _addr1, tl1 = insns[idx + 1]

    m = _CMP_PAT.match(tl0.strip())
    if not m:
        return False

    var = m.group(1)
    rhs_str = m.group(2)

    try:
        rhs_val = int(rhs_str, 0)
    except ValueError:
        rhs_expr = regs.get(rhs_str)
        if rhs_expr:
            lo, _ = rhs_expr.eval_bounds(symbols)
            rhs_val = lo
        else:
            return False

    jcc = tl1.strip().split()[0].lower()
    op = _JCC_MAP.get(jcc)
    if op is None:
        return False

    constraints.append((var, op, rhs_val))
    path_count_ref[0] += 1
    return True


def refine_range_by_constraints(rng: Tuple[int, int],
                                constraints) -> Tuple[int, int]:
    """用路径约束精化范围 [lo, hi]."""
    lo, hi = rng
    for _var, op, bound in constraints:
        if op == '<=':
            hi = min(hi, bound)
        elif op == '<':
            hi = min(hi, bound - 1)
        elif op == '>=':
            lo = max(lo, bound)
        elif op == '>':
            lo = max(lo, bound + 1)
    return (lo, max(lo, hi))


__all__ = [
    'SymExpr', 'sym_const',
    'try_arith_insn', 'try_load_store_insn',
    'try_conditional_insn', 'refine_range_by_constraints',
]
