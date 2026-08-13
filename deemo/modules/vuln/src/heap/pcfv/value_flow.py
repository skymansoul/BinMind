"""需求驱动值流追踪 — 从访问点后向解析操作数的区间/常量/污点/来源.

创建: 2024-05-08
设计决策:
  - 与基线 func_analyzer 的前向抽象寄存器不同: 本模块按需后向解析表达式树,
    能精确处理 mov/lea/add/sub/and/imul/shl 组合, 输出 ValueInfo.
  - 污点三值: 入口参数与输入函数返回值为 True(弱置信), 内存加载为 None(未知),
    常量传播为 False. None 永远不构成"未污染"证据 — 防止未知即安全的漏报.
  - 递归时传入定义指令地址而非查询地址, 保证地址空间单调后退;
    visited 集合切断 (reg, addr) 环.
"""
import re
from typing import Dict, List, Optional, Set, Tuple

from .types import ValueInfo, Provenance
from .value_ops import ValueOpsMixin, norm_reg

_REG_RE = re.compile(
    r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
    re.IGNORECASE)
_IMM_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')

_ENTRY_ARGS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
_CLEARED_BY_CALL = ('rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')
_INPUT_FUNCS = ('scanf', 'gets', 'read', 'recv', 'recvfrom', 'fgets',
                'fread', '__isoc99_scanf')

_MAX_DEPTH = 25
_MAX_BUDGET = 256
# TODO: 窗口大小按函数规模自适应, 大函数中长定义链可能被截断
_DEF_WINDOW = 256  # 定义查找窗口: 真实场景定义距使用 <256 条指令


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


def _split_dst(operands: str) -> Optional[str]:
    if ',' not in operands:
        return None
    return operands.split(',')[0].strip()


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


class ValueFlowTracer:
    """函数内需求驱动值流解析器."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx: Dict[int, int] = {
            i.addr: n for n, i in enumerate(insns)}
        self._cache: Dict[Tuple[int, str], ValueInfo] = {}
        self._visited: Set[Tuple[int, str]] = set()

# 公开接口

    def trace(self, reg: str, addr: int,
              max_depth: int = _MAX_DEPTH) -> ValueInfo:
        """解析 reg 在 addr 处的值信息."""
        key = (addr, norm_reg(reg))
        if key in self._cache:
            return self._cache[key]
        self._visited.clear()
        info = self._trace_reg(norm_reg(reg), addr, max_depth)
        self._cache[key] = info
        return info

    def trace_mem_operand(self, operand: str, addr: int,
                          max_depth: int = _MAX_DEPTH) -> Tuple[
                              Optional[str], Optional[int], ValueInfo]:
        """解析 [reg+disp] 内存操作数 → (基寄存器, 常量disp, 寄存器值信息)."""
        m = re.search(r'\[([^\]]+)\]', operand)
        if not m:
            return None, None, ValueInfo(provenance=Provenance.UNKNOWN,
                                         summary='no-mem-operand')
        inner = m.group(1).strip()
        reg_m = _REG_RE.search(inner)
        reg = norm_reg(reg_m.group(1)) if reg_m else None
        disp = None
        im = re.search(r'[+]\s*(0x[0-9a-fA-F]+|\d+)', inner)
        if im:
            try:
                disp = int(im.group(1), 0)
            except ValueError:
                disp = None
        if reg is None:
            return None, disp, ValueInfo(provenance=Provenance.UNKNOWN,
                                         summary='no-base-reg')
        return reg, disp, self._trace_reg(reg, addr, max_depth)

# 内部实现

    def _trace_reg(self, reg: str, addr: int, depth: int) -> ValueInfo:
        if depth <= 0 or len(self._visited) > _MAX_BUDGET:
            return ValueInfo(provenance=Provenance.UNKNOWN,
                             summary=f'depth-exhausted:{reg}')
        key = (addr, reg)
        if key in self._visited:
            return ValueInfo(provenance=Provenance.UNKNOWN,
                             summary=f'cycle-cut:{reg}')
        self._visited.add(key)

        idx = self._addr_to_idx.get(addr)
        if idx is None:
            return ValueInfo(provenance=Provenance.UNKNOWN,
                             summary=f'no-insn:{reg}')
        def_idx = self._find_def(reg, idx)
        if def_idx is None:
            if reg in _ENTRY_ARGS:
                return ValueInfo(interval_lo=0, interval_hi=None,
                                 tainted=True, taint_confidence=0.5,
                                 provenance=Provenance.ENTRY_ARG,
                                 def_chain_len=0, summary=f'entry-arg:{reg}')
            return ValueInfo(provenance=Provenance.UNKNOWN,
                             summary=f'undef:{reg}')

        insn = self._insns[def_idx]
        return self._interpret_def(insn, reg, def_idx, depth)

    def _find_def(self, reg: str, from_idx: int) -> Optional[int]:
        """后向查找对 reg 的最后一次定义(不含 from_idx 处).

        窗口限制: 全函数扫描是大函数超线性耗时的主源,
        定义链超过窗口视为未定义 (入口参数/未知, 保守)."""
        lo = max(0, from_idx - 1 - _DEF_WINDOW)
        for j in range(from_idx - 1, lo - 1, -1):
            insn = self._insns[j]
            mn = insn.mnemonic
            if mn in ('call', 'callq'):
                if reg in _CLEARED_BY_CALL or reg == 'rax':
                    return j
                continue
            dst = _split_dst(insn.operands)
            if dst is None:
                continue
            if '[' in dst:
                continue
            dst_reg = _REG_RE.search(dst)
            if dst_reg and norm_reg(dst_reg.group(1)) == reg:
                return j
        return None

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
