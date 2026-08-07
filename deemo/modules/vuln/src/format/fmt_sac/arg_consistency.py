"""实参一致性验证 — 说明符数量与调用点实参数对比.

创建: 2026-08-05
设计决策:
  - 调用点实参数: x86-64 前4参在 rcx/rdx/r8/r9, 其余在栈.
    格式化函数 fmt 参数索引: printf=1, sprintf=1, fprintf=2, snprintf=2.
    实参数 = 总可见参数 - fmt 索引.
  - 一致性判定仅作为增强证据, 不单独构成过滤: 常量+一致 → 过滤;
    常量+不一致 → POSSIBLE (参数错误, 保留).
"""
from typing import List, Optional

from .types import FmtCall

_FORMAT_ARITY = {
    'printf': (1, 1), 'vprintf': (1, 1),
    'sprintf': (1, 2), 'vsprintf': (1, 2),
    'snprintf': (2, 3), 'vsnprintf': (2, 3),
    'fprintf': (2, 2), 'vfprintf': (2, 2),
    'dprintf': (2, 2), 'syslog': (1, 2),
}
# 含 printf 前缀的包装函数按 printf 语义
_VARIADIC_WRAP = ('printf', 'log', 'msg', 'fmt')


class ArgConsistency:
    """调用点实参数量解析."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {i.addr: n for n, i in enumerate(insns)}

    def count_args(self, call: FmtCall) -> int:
        """统计调用点可见实参数 (不含 fmt 本身)."""
        idx = self._addr_to_idx.get(call.addr)
        if idx is None:
            return 0
        name = _norm_name(call.function)
        arity = _FORMAT_ARITY.get(name)
        if arity is None:
            arity = (1, 1)
        fmt_pos, min_pos = arity
        # 实参寄存器: rcx,rdx,r8,r9 中位于 fmt_pos 之后的
        arg_regs = ('rcx', 'rdx', 'r8', 'r9')
        set_before = self._regs_set_before(idx, arg_regs)
        visible = 0
        for i in range(fmt_pos, 4):
            if arg_regs[i] in set_before:
                visible += 1
        return visible

    def _regs_set_before(self, idx: int, regs: tuple) -> set:
        """调用点前最近一次设置过的参数寄存器集合."""
        import re
        result = set()
        pat = re.compile(
            r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i)\b')
        for j in range(idx - 1, max(0, idx - 16) - 1, -1):
            insn = self._insns[j]
            mn = insn.mnemonic
            if mn.startswith('call'):
                break
            if ',' not in insn.operands:
                continue
            dst = insn.operands.split(',')[0].strip()
            m = pat.search(dst)
            if m:
                reg = _norm_arg_reg(m.group(1))
                if reg in regs:
                    result.add(reg)
        return result


def _norm_name(fn: str) -> str:
    fn = fn.split('@')[0].split('<')[-1].split('>')[0]
    for cand in ('snprintf', 'sprintf', 'fprintf', 'vsnprintf', 'vsprintf',
                 'vfprintf', 'dprintf', 'vprintf', 'printf', 'syslog'):
        if cand in fn:
            return cand
    if any(w in fn for w in _VARIADIC_WRAP):
        return 'printf'
    return fn


def _norm_arg_reg(reg: str) -> str:
    """edx→rdx, r8d→r8 归一化."""
    reg = reg.lower()
    return {'eax': 'rcx', 'edx': 'rdx', 'ecx': 'rcx', 'ebx': 'rbx',
            'esi': 'rsi', 'edi': 'rdi',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
            }.get(reg, reg)
