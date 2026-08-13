"""ACPE 符号追踪指令处理器 — 无类自由函数 + 追踪状态.

创建: 2024-12-09
沿用 heap_analysis/_insn_handlers.py 的自由函数模式:
  所有 handler 接收 TrackerState, 仅更新状态, 不做控制流判断。

关键设计决策 (与 reg_tracker 的字符串标签不同):
  - and 掩码 / imul 倍率 / lea 缩放 / movzx 部分宽度扩展 均建立
    新符号节点, 破坏与原始参数的容量等价——截断分配→大拷贝
    必须保留为告警, 不得被 EQUIV 误滤。
  - rsp/rbp 派生地址标记为栈, 写入目标为栈时非堆溢出候选。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, extract_register, extract_constant, extract_mem_offset)

from modules.vuln.detection.heap_analysis.acpe.capacity_model import CapExpr
from modules.vuln.detection.heap_analysis.acpe.guard_dominance import parse_guard
from modules.vuln.detection.heap_analysis.acpe.sym_types import (
    _is_call_name, _extract_scale, _reg_width_bits, _CALLER_SAVED,
    SymAlloc, SymWrite, FuncSymResult)


@dataclass
class TrackerState:
    """单函数追踪状态 (寄存器/栈槽/符号偏移/栈地址)."""
    regs: Dict[str, CapExpr] = field(default_factory=dict)
    slots: Dict[int, CapExpr] = field(default_factory=dict)
    sym_off_regs: set = field(default_factory=set)
    stack_regs: set = field(default_factory=set)
    pending_cmp: Optional[Tuple[int, str]] = None
    cmp_sym_map: Optional[Dict[str, str]] = None


# 状态工具
def reset(st: TrackerState, arg_regs: List[str]) -> None:
    st.regs.clear()
    st.slots.clear()
    st.sym_off_regs.clear()
    st.stack_regs.clear()
    for i, reg in enumerate(arg_regs, 1):
        st.regs[reg] = CapExpr.sym(f'A:{i}')
    for reg in ('eax', 'ecx', 'edx', 'esi', 'edi', 'r8d', 'r9d'):
        st.regs[reg] = CapExpr.unknown()


def clobber(st: TrackerState) -> None:
    for r in _CALLER_SAVED:
        st.regs.pop(r, None)
    for r in _CALLER_SAVED:
        st.sym_off_regs.discard(r)
    for r in _CALLER_SAVED:
        st.stack_regs.discard(r)


def expr_of(st: TrackerState, operand: str) -> CapExpr:
    """操作数 → 容量表达式."""
    if '[' in operand:
        base, off = extract_mem_offset(operand)
        if base in ('rbp', 'rsp') and off is not None:
            return st.slots.get(off, CapExpr.unknown())
        if base:
            b = st.regs.get(base, CapExpr.unknown())
            if b.kind == 'SYM':
                return CapExpr.arith(b.base, off or 0)
            if b.kind == 'CONST':
                return CapExpr.const(b.value + (off or 0))
        return CapExpr.unknown()
    c = extract_constant(operand)
    if c is not None:
        return CapExpr.const(c)
    reg = extract_register(operand)
    if reg:
        return st.regs.get(reg, CapExpr.unknown())
    return CapExpr.unknown()


def dst_info(st: TrackerState, expr: CapExpr,
             reg: str = '') -> Tuple[str, int, bool]:
    """从目标表达式提取 (malloc标签, 常量偏移, 偏移是否符号化)."""
    if reg and reg in st.sym_off_regs:
        if expr.kind == 'SYM' and expr.base.startswith('alloc@'):
            return expr.base, 0, True
    if expr.kind == 'ARITH' and expr.base.startswith('alloc@'):
        return expr.base, expr.offset, False
    if expr.kind == 'SYM' and expr.base.startswith('alloc@'):
        return expr.base, 0, False
    return '', 0, True


def mul_expr(a: CapExpr, b: CapExpr) -> CapExpr:
    """calloc(nmemb,size) 容量近似: 常数×常数可折叠, 否则 UNKNOWN."""
    if a.kind == 'CONST' and b.kind == 'CONST':
        return CapExpr.const(a.value * b.value)
    return CapExpr.unknown()


def sym_map(st: TrackerState) -> Dict[str, str]:
    """寄存器/栈槽 → 规范符号, 供守卫解析使用."""
    out: Dict[str, str] = {}
    for reg, expr in st.regs.items():
        if expr.is_symbolic():
            out[reg] = expr.canonical()
    for off, expr in st.slots.items():
        if expr.is_symbolic():
            out[f'rbp:{off}'] = expr.canonical()
    return out


# 指令处理器
def on_mov(st: TrackerState, insn: Instruction) -> None:
    op = insn.operands
    dst = op.split(',')[0].strip()
    src = op.split(',')[-1].strip()
    if '[' in dst:
        base, off = extract_mem_offset(dst)
        if base in ('rbp', 'rsp') and off is not None:
            st.slots[off] = expr_of(st, src)
        return
    dst_reg = extract_register(dst)
    if not dst_reg:
        return
    if insn.mnemonic in ('movzx', 'movsx', 'movsxd'):
        src_bits = _reg_width_bits(src)
        if src_bits < 64:
            cur = st.regs.get(dst_reg, CapExpr.unknown())
            if cur.is_symbolic():
                mask = (1 << src_bits) - 1
                st.regs[dst_reg] = CapExpr.sym(
                    f'{cur.canonical()}&{mask}')
                return
    src_reg = extract_register(src)
    st.regs[dst_reg] = expr_of(st, src)
    if src_reg and src_reg in st.sym_off_regs:
        st.sym_off_regs.add(dst_reg)
    if src_reg and src_reg in st.stack_regs:
        st.stack_regs.add(dst_reg)


def on_lea(st: TrackerState, insn: Instruction) -> None:
    op = insn.operands
    dst = op.split(',')[0].strip()
    src = op.split(',')[-1].strip()
    dst_reg = extract_register(dst)
    if not dst_reg:
        return
    if '[' not in src:
        st.regs.pop(dst_reg, None)
        return
    base, off = extract_mem_offset(src)
    scale = _extract_scale(src)
    if base in st.sym_off_regs:
        st.sym_off_regs.add(dst_reg)
    if base in ('rsp', 'rbp'):
        st.stack_regs.add(dst_reg)
        st.regs[dst_reg] = CapExpr.sym('stack')
        return
    base_expr = st.regs.get(base, CapExpr.unknown()) if base else CapExpr.unknown()
    if scale and scale > 1 and base_expr.is_symbolic():
        sym = f'{base_expr.canonical()}*{scale}'
        if off:
            sym += f'{off:+d}'
        st.regs[dst_reg] = CapExpr.sym(sym)
        return
    if base_expr.kind == 'SYM':
        st.regs[dst_reg] = CapExpr.arith(base_expr.base, off or 0)
        return
    if base_expr.kind == 'ARITH':
        st.regs[dst_reg] = CapExpr.arith(
            base_expr.base, base_expr.offset + (off or 0))
        return
    if base_expr.kind == 'CONST':
        st.regs[dst_reg] = CapExpr.const(base_expr.value + (off or 0))
        return
    st.regs.pop(dst_reg, None)


def on_addsub(st: TrackerState, insn: Instruction, is_add: bool) -> None:
    op = insn.operands
    parts = [p.strip() for p in op.split(',')]
    dst_reg = extract_register(parts[0])
    if not dst_reg or len(parts) < 2:
        return
    c = extract_constant(parts[1])
    if c is None:
        src_reg = extract_register(parts[1])
        cur = st.regs.get(dst_reg)
        if src_reg and cur is not None \
                and cur.kind == 'SYM' and cur.base.startswith('alloc@'):
            st.sym_off_regs.add(dst_reg)
        return
    delta = c if is_add else -c
    cur = st.regs.get(dst_reg)
    if cur is None:
        return
    if cur.kind == 'CONST':
        st.regs[dst_reg] = CapExpr.const(cur.value + delta)
    elif cur.kind == 'SYM':
        st.regs[dst_reg] = CapExpr.arith(cur.base, delta)
    elif cur.kind == 'ARITH':
        st.regs[dst_reg] = CapExpr.arith(cur.base, cur.offset + delta)


def on_imul(st: TrackerState, insn: Instruction) -> None:
    op = insn.operands
    parts = [p.strip() for p in op.split(',')]
    if len(parts) < 3:
        return
    dst_reg = extract_register(parts[0])
    c = extract_constant(parts[2])
    if dst_reg and c is not None:
        cur = st.regs.get(dst_reg, CapExpr.unknown())
        if cur.kind == 'CONST':
            st.regs[dst_reg] = CapExpr.const(cur.value * c)
        elif cur.kind == 'SYM':
            st.regs[dst_reg] = CapExpr.sym(f'{cur.base}*{c}')
        elif cur.kind == 'ARITH':
            st.regs[dst_reg] = CapExpr.sym(
                f'{cur.base}*{c}{cur.offset:+d}')


def on_xor(st: TrackerState, insn: Instruction) -> None:
    op = insn.operands
    parts = [p.strip() for p in op.split(',')]
    r1 = extract_register(parts[0])
    r2 = extract_register(parts[1]) if len(parts) > 1 else None
    if r1 and r2 and r1 == r2:
        st.regs[r1] = CapExpr.const(0)


def on_bitop(st: TrackerState, insn: Instruction, mn: str) -> None:
    op = insn.operands
    parts = [p.strip() for p in op.split(',')]
    dst_reg = extract_register(parts[0])
    if not dst_reg or len(parts) < 2:
        return
    c = extract_constant(parts[1])
    if c is None:
        return
    cur = st.regs.get(dst_reg)
    if cur is None:
        return
    if mn == 'and':
        if cur.kind == 'CONST':
            st.regs[dst_reg] = CapExpr.const(cur.value & c)
        elif cur.is_symbolic():
            st.regs[dst_reg] = CapExpr.sym(f'{cur.canonical()}&{c}')


def on_cmp(st: TrackerState, insn: Instruction, result: FuncSymResult) -> None:
    st.pending_cmp = (insn.addr, insn.operands)
    st.cmp_sym_map = sym_map(st)


def on_jcc(st: TrackerState, insn: Instruction, result: FuncSymResult) -> None:
    if st.pending_cmp is None:
        return
    cmp_insn = Instruction(st.pending_cmp[0], 'cmp', st.pending_cmp[1], '')
    rec = parse_guard(cmp_insn, insn, st.cmp_sym_map or {})
    st.pending_cmp = None
    st.cmp_sym_map = None
    if rec is not None:
        result.guards.append(rec)


def on_call(st: TrackerState, insn: Instruction, result: FuncSymResult,
            func_name: str, arg_regs: List[str]) -> None:
    """call 处理: malloc/calloc/realloc + memcpy/strcpy/read 写入记录."""
    op = insn.operands.lower()
    if _is_call_name(insn, ('malloc', 'calloc', 'realloc')):
        kind = 'calloc' if 'calloc' in op else (
            'realloc' if 'realloc' in op else 'malloc')
        if 'calloc' in op:
            expr = mul_expr(st.regs.get(arg_regs[0], CapExpr.unknown()),
                            st.regs.get(arg_regs[1], CapExpr.unknown()))
        elif 'realloc' in op:
            expr = st.regs.get(arg_regs[1], CapExpr.unknown())
        else:
            expr = st.regs.get(arg_regs[0], CapExpr.unknown())
        label = f'alloc@{insn.addr:x}'
        result.allocs.append(SymAlloc(
            addr=insn.addr, func_name=func_name, alloc_func=kind,
            size_expr=expr, dst_label=label))
        clobber(st)
        st.regs['rax'] = CapExpr.sym(label)
        return

    if _is_call_name(insn, ('memcpy', 'memmove', 'memset')):
        _record_write(st, insn, result, func_name, arg_regs,
                      dst_reg=arg_regs[0], size_reg=arg_regs[2])
        return

    if _is_call_name(insn, ('strcpy', 'strcat', 'gets', 'sprintf')):
        _record_write(st, insn, result, func_name, arg_regs,
                      dst_reg=arg_regs[0], size_reg=None, unbounded=True)
        return

    if _is_call_name(insn, ('read', 'recv', 'fread')):
        _record_write(st, insn, result, func_name, arg_regs,
                      dst_reg=arg_regs[1], size_reg=arg_regs[2])
        return

    clobber(st)


def _record_write(st: TrackerState, insn: Instruction, result: FuncSymResult,
                  func_name: str, arg_regs: List[str],
                  dst_reg: str, size_reg: Optional[str],
                  unbounded: bool = False) -> None:
    """写入记录 (memcpy/strcpy/read 共用)."""
    dst = st.regs.get(dst_reg, CapExpr.unknown())
    size = (st.regs.get(size_reg, CapExpr.unknown())
            if size_reg else CapExpr.unknown())
    dst_label, dst_off, off_unk = dst_info(st, dst, dst_reg)
    result.writes.append(SymWrite(
        addr=insn.addr, func_name=func_name, write_func=insn.mnemonic,
        size_expr=size, dst_label=dst_label, dst_offset=dst_off,
        dst_offset_unknown=off_unk,
        dst_is_stack=dst_reg in st.stack_regs,
        unbounded=unbounded))
    clobber(st)
