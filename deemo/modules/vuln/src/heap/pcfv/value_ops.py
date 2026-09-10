"""值流操作解释器 — mov/lea/算术指令的 ValueInfo 语义.
"""
import re
from typing import Optional, Tuple

from .types import ValueInfo, Provenance

_REG_RE = re.compile(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
                     re.IGNORECASE)
_IMM_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')

_ENTRY_ARGS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
_INPUT_FUNCS = ('scanf', 'gets', 'read', 'recv', 'recvfrom', 'fgets',
                'fread', '__isoc99_scanf')


class ValueOpsMixin:
    """指令解释器 mixin — 由 ValueFlowTracer 继承."""

    def _interpret_def(self, insn, reg: str, def_idx: int,
                       depth: int) -> ValueInfo:
        mn = insn.mnemonic
        op = insn.operands
        dst, src = _split_pair(op)
        def_addr = insn.addr

        if mn in ('call', 'callq'):
            callee = src or ''
            if any(f in callee.lower() for f in _INPUT_FUNCS):
                return ValueInfo(interval_lo=0, interval_hi=None,
                                 tainted=True, taint_confidence=0.85,
                                 provenance=Provenance.INPUT_CALL,
                                 summary=f'input-call:{callee}')
            return ValueInfo(interval_lo=0, interval_hi=None,
                             tainted=None, provenance=Provenance.UNKNOWN,
                             summary='call-result')

        if mn in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd'):
            return self._handle_mov(src, def_addr, depth)

        if mn == 'lea':
            base_reg, disp, _ = self._parse_lea_src(src)
            if base_reg is None:
                base_info = ValueInfo(provenance=Provenance.UNKNOWN)
            else:
                base_info = self._trace_reg(base_reg, def_addr, depth)
            return _shift_value(base_info, 0, disp or 0, f'lea+{disp}')

        if mn == 'add':
            return self._binary_op(reg, src, def_addr, depth, op_is_add=True)
        if mn == 'sub':
            return self._binary_op(reg, src, def_addr, depth, op_is_add=False)
        if mn == 'imul':
            return self._handle_imul(reg, src, def_addr, depth)
        if mn in ('and', 'andq'):
            return self._handle_and(reg, src, def_addr, depth)
        if mn in ('shl', 'sal'):
            return self._handle_shift(reg, src, def_addr, depth, left=True)
        if mn in ('shr', 'sar'):
            return self._handle_shift(reg, src, def_addr, depth, left=False)
        if mn in ('xor', 'pxor'):
            if dst and src and dst.rstrip() == src.rstrip():
                return ValueInfo(interval_lo=0, interval_hi=0,
                                 is_constant=True, constant_value=0,
                                 tainted=False, taint_confidence=0.99,
                                 provenance=Provenance.CONSTANT,
                                 summary='xor-zero')
            return ValueInfo(provenance=Provenance.UNKNOWN, summary='xor')
        if mn == 'inc':
            cur = self._trace_reg(reg, def_addr, depth)
            return _shift_value(cur, 1, 0, 'inc')
        if mn == 'dec':
            cur = self._trace_reg(reg, def_addr, depth)
            return _shift_value(cur, -1, 0, 'dec')
        return ValueInfo(provenance=Provenance.UNKNOWN, summary=mn)

    def _handle_mov(self, src: str, def_addr: int, depth: int) -> ValueInfo:
        if '[' in src:
            base_reg, disp, _ = self.trace_mem_operand(src, def_addr, depth)
            slot = self._slot_key_of(src)
            return ValueInfo(interval_lo=0, interval_hi=None, tainted=None,
                             provenance=Provenance.MEMORY_LOAD,
                             summary=f'mem-load{slot}')
        src_reg = _REG_RE.search(src)
        if src_reg:
            inner = self._trace_reg(norm_reg(src_reg.group(1)),
                                    def_addr, depth - 1)
            inner.def_chain_len += 1
            inner.summary = f'mov<-{inner.summary}'
            return inner
        imm = _parse_imm(src)
        if imm is not None:
            return ValueInfo(interval_lo=imm, interval_hi=imm,
                             is_constant=True, constant_value=imm,
                             tainted=False, taint_confidence=0.98,
                             provenance=Provenance.CONSTANT,
                             summary=f'imm:{imm}')
        return ValueInfo(provenance=Provenance.UNKNOWN, summary='mov-unknown')

    def _parse_lea_src(self, src: str) -> Tuple[Optional[str], Optional[int], str]:
        m = re.search(r'\[([^\]]+)\]', src)
        if not m:
            return None, None, src
        inner = m.group(1)
        reg_m = _REG_RE.search(inner)
        reg = norm_reg(reg_m.group(1)) if reg_m else None
        disp = None
        im = re.search(r'[+]\s*(0x[0-9a-fA-F]+|\d+)', inner)
        if im:
            try:
                disp = int(im.group(1), 0)
            except ValueError:
                disp = None
        return reg, disp, inner

    def _binary_op(self, reg: str, src: str, addr: int, depth: int,
                   op_is_add: bool) -> ValueInfo:
        src_reg_m = _REG_RE.search(src)
        if src_reg_m:
            other = self._trace_reg(norm_reg(src_reg_m.group(1)), addr, depth)
        else:
            other = ValueInfo()
        imm = _parse_imm(src)
        if imm is None and not src_reg_m:
            return ValueInfo(provenance=Provenance.UNKNOWN,
                             summary='binop-unknown')
        if imm is not None:
            return _shift_value(other, imm if op_is_add else -imm, 0,
                                'add' if op_is_add else 'sub')
        return ValueInfo(interval_lo=other.interval_lo,
                         interval_hi=None, tainted=other.tainted,
                         taint_confidence=other.taint_confidence,
                         provenance=other.provenance,
                         summary=f'binop-regreg<{other.summary}')

    def _handle_imul(self, reg: str, src: str, addr: int,
                     depth: int) -> ValueInfo:
        imm = _parse_imm(src)
        if imm is None:
            return ValueInfo(provenance=Provenance.UNKNOWN, summary='imul-var')
        if imm == 0:
            return ValueInfo(interval_lo=0, interval_hi=0, is_constant=True,
                             constant_value=0, tainted=False,
                             taint_confidence=0.98,
                             provenance=Provenance.CONSTANT, summary='imul-0')
        other = self._trace_reg(reg, addr, depth)
        lo = other.interval_lo * imm if other.interval_lo is not None else None
        hi = other.interval_hi * imm if other.interval_hi is not None else None
        return ValueInfo(interval_lo=lo, interval_hi=hi,
                         tainted=other.tainted,
                         taint_confidence=other.taint_confidence,
                         provenance=other.provenance, summary='imul-imm')

    def _handle_and(self, reg: str, src: str, addr: int,
                    depth: int) -> ValueInfo:
        imm = _parse_imm(src)
        if imm is None:
            return ValueInfo(provenance=Provenance.UNKNOWN, summary='and-var')
        other = self._trace_reg(reg, addr, depth)
        hi = imm
        if other.interval_hi is not None and other.interval_hi >= 0:
            hi = min(imm, other.interval_hi)
        return ValueInfo(interval_lo=0, interval_hi=hi,
                         tainted=other.tainted,
                         taint_confidence=other.taint_confidence,
                         provenance=Provenance.GUARDED,
                         summary=f'and-mask:{imm}')

    def _handle_shift(self, reg: str, src: str, addr: int, depth: int,
                      left: bool) -> ValueInfo:
        imm = _parse_imm(src)
        if imm is None or imm > 63:
            return ValueInfo(provenance=Provenance.UNKNOWN,
                             summary='shift-var')
        other = self._trace_reg(reg, addr, depth)
        if left:
            lo = other.interval_lo << imm if other.interval_lo is not None else None
            hi = other.interval_hi << imm if other.interval_hi is not None else None
        else:
            lo = other.interval_lo >> imm if other.interval_lo is not None else 0
            hi = other.interval_hi >> imm if other.interval_hi is not None else None
        return ValueInfo(interval_lo=lo, interval_hi=hi,
                         tainted=other.tainted,
                         taint_confidence=other.taint_confidence,
                         provenance=other.provenance, summary='shift')

    @staticmethod
    def _slot_key_of(mem_operand: str) -> str:
        """内存槽规范化键: 'DWORD PTR [rbp-0x4]' → '[rbp-4]'."""
        m = re.search(r'\[([^\]]+)\]', mem_operand)
        if not m:
            return mem_operand
        inner = m.group(1).strip()
        reg_m = _REG_RE.search(inner)
        if reg_m is None:
            return inner
        reg = norm_reg(reg_m.group(1))
        disp_m = re.search(r'([+-])\s*(0x[0-9a-fA-F]+|\d+)', inner)
        disp = 0
        if disp_m:
            try:
                val = int(disp_m.group(2), 0)
            except ValueError:
                val = 0
            disp = val if disp_m.group(1) == '+' else -val
        return f'[{reg}{disp:+d}]'


def norm_reg(reg: str) -> str:
    return {'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
            'rbx': 'rbx', 'ebx': 'rbx', 'rcx': 'rcx', 'ecx': 'rcx',
            'rdx': 'rdx', 'edx': 'rdx', 'rsi': 'rsi', 'esi': 'rsi',
            'rdi': 'rdi', 'edi': 'rdi', 'r8': 'r8', 'r8d': 'r8',
            'r9': 'r9', 'r9d': 'r9', 'r10': 'r10', 'r10d': 'r10',
            'r11': 'r11', 'r11d': 'r11', 'r12': 'r12', 'r12d': 'r12',
            'r13': 'r13', 'r13d': 'r13', 'r14': 'r14', 'r14d': 'r14',
            'r15': 'r15', 'r15d': 'r15', 'rbp': 'rbp', 'rsp': 'rsp',
            }.get(reg.lower(), reg.lower())


def _split_pair(operands: str) -> Tuple[str, str]:
    parts = [p.strip() for p in operands.split(',')]
    while len(parts) < 2:
        parts.append('')
    return parts[0], parts[1]


def _parse_imm(op: str) -> Optional[int]:
    if not op:
        return None
    m = re.search(r'0x[0-9a-fA-F]+', op)
    if m:
        try:
            return int(m.group(0), 16)
        except ValueError:
            return None
    m = re.search(r'\b\d+\b', op)
    if m:
        val = int(m.group(0))
        return val if val < 0x1000000 else None
    return None


def _shift_value(base: ValueInfo, delta: int, _unused: int,
                 tag: str) -> ValueInfo:
    lo = base.interval_lo
    hi = base.interval_hi
    if lo is not None:
        lo = lo + delta
    if hi is not None:
        hi = hi + delta
    if base.is_constant and base.constant_value is not None:
        return ValueInfo(interval_lo=lo, interval_hi=hi,
                         is_constant=True,
                         constant_value=base.constant_value + delta,
                         tainted=base.tainted,
                         taint_confidence=base.taint_confidence,
                         provenance=Provenance.CONSTANT,
                         def_chain_len=base.def_chain_len + 1,
                         summary=f'{tag}:{delta}')
    return ValueInfo(interval_lo=lo, interval_hi=hi,
                     tainted=base.tainted,
                     taint_confidence=base.taint_confidence,
                     provenance=base.provenance,
                     def_chain_len=base.def_chain_len + 1,
                     summary=f'{tag}:{delta}')
