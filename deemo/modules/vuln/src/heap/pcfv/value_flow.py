"""需求驱动值流追踪 — 从访问点后向解析操作数的区间/常量/污点/来源.

创建: 2026-08-05
设计决策:
  - 与基线 func_analyzer 的前向抽象寄存器不同: 本模块按需后向解析表达式树,
    能精确处理 mov/lea/add/sub/and/imul/shl 组合, 输出 ValueInfo.
  - 污点三值: 入口参数与输入函数返回值为 True(弱置信), 内存加载为 None(未知),
    常量传播为 False. None 永远不构成"未污染"证据 — 防止未知即安全的漏报.
  - 递归时传入定义指令地址而非查询地址, 保证地址空间单调后退;
    visited 集合切断 (reg, addr) 环.
"""
from typing import Dict, List, Optional, Set, Tuple

from .types import ValueInfo, Provenance
from .value_ops import ValueOpsMixin, norm_reg

_REG_RE = __import__('re').compile(
    r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
    __import__('re').IGNORECASE)

_ENTRY_ARGS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
_CLEARED_BY_CALL = ('rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')

_MAX_DEPTH = 25
_MAX_BUDGET = 256


class ValueFlowTracer(ValueOpsMixin):
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
        m = __import__('re').search(r'\[([^\]]+)\]', operand)
        if not m:
            return None, None, ValueInfo(provenance=Provenance.UNKNOWN,
                                         summary='no-mem-operand')
        inner = m.group(1).strip()
        reg_m = _REG_RE.search(inner)
        reg = norm_reg(reg_m.group(1)) if reg_m else None
        disp = None
        im = __import__('re').search(r'[+]\s*(0x[0-9a-fA-F]+|\d+)', inner)
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
        """后向查找对 reg 的最后一次定义(不含 from_idx 处)."""
        for j in range(from_idx - 1, -1, -1):
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


def _split_dst(operands: str) -> Optional[str]:
    if ',' not in operands:
        return None
    return operands.split(',')[0].strip()
