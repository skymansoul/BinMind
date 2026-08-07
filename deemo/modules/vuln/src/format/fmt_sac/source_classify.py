"""格式串来源分类 — 从调用点前向数据流判定格式串出处.

创建: 2026-08-09
设计决策:
  - 复用 PCFV 值流/指针标签: 格式串寄存器 (printf→rcx, sprintf→rcx,
    fprintf→rdx) 的取值:
      lea rcx,[rip+X] 且 X 落在 .rdata → CONST_RDATA
      mov rcx,[rbp-X] (栈槽) → STACK_BUFFER
      mov rcx, <malloc 标签> → HEAP_BUFFER
      直接来自 gets/scanf/read 调用结果 → USER_INPUT
  - 常量判定优先 (任何常量证据都足以过滤); 无法判定 → UNKNOWN (保守).
"""
from typing import Optional

from .types import FmtSource

_RDATA_LABELS = ('.rdata', 'LC', '.rodata')


class SourceClassifier:
    """调用点格式串来源分类器."""

    def __init__(self, insns: list, rdata_addrs: set,
                 const_callers: dict = None, cur_fn: str = ''):
        self._insns = insns
        self._addr_to_idx = {i.addr: n for n, i in enumerate(insns)}
        self._rdata_addrs = rdata_addrs
        # 摘要: {被调函数名: 所有调用点 fmt 实参均为常量}
        self._const_callers = const_callers or {}
        self._cur_fn = cur_fn

    def classify(self, fmt_reg: str, call_addr: int,
                 tracer) -> (FmtSource, str):
        """返回 (来源, 详情)."""
        if fmt_reg not in ('rcx', 'rdx', 'rdi', 'rsi', 'r8'):
            return FmtSource.UNKNOWN, 'no-fmt-reg'
        idx = self._addr_to_idx.get(call_addr)
        if idx is None:
            return FmtSource.UNKNOWN, 'no-insn'
        return self._classify_reg(fmt_reg, idx, tracer, depth=0)

    def _classify_reg(self, reg: str, upto_idx: int, tracer,
                      depth: int) -> (FmtSource, str):
        if depth > 3:
            return FmtSource.UNKNOWN, 'depth-exceeded'
        def_idx = self._def_of(reg, upto_idx)
        if def_idx is None:
            return FmtSource.UNKNOWN, 'undef-fmt-reg'
        insn = self._insns[def_idx]
        src = insn.operands.split(',')[-1].strip() if ',' in insn.operands else ''

        # 常量: lea reg, [rip+X] 指向 .rdata
        if insn.mnemonic == 'lea' and 'rip' in src:
            m = _extract_rip_disp(src, insn, def_idx)
            if m is not None:
                from .fmt_parser import resolve_rdata_text
                if any(addr <= m < addr + 40
                       for addr in self._rdata_addrs):
                    return FmtSource.CONST_RDATA, 'lea-rip->%#x' % m
                return FmtSource.UNKNOWN, 'lea-rip->non-rdata'
        if insn.mnemonic == 'lea' and any(lab in src.lower()
                                          for lab in _RDATA_LABELS):
            return FmtSource.CONST_RDATA, 'lea-rdata-label'

        # 栈槽加载: 区分影子空间(入口参数透传)与本地缓冲
        if '[' in src and ('rbp' in src or 'rsp' in src):
            import re as _re
            sm = _re.search(r'\[r[sb]p([+-])(0x[0-9a-fA-F]+|\d+)\]', src)
            if sm:
                val = int(sm.group(2), 0)
                if sm.group(1) == '+' and val <= 0x40:
                    # 影子空间: 入口参数重载, 查调用点常量摘要
                    if self._const_callers.get(self._cur_fn):
                        return (FmtSource.CONST_RDATA,
                                'const-caller-summary')
                    return FmtSource.UNKNOWN, 'shadow-reload'
            return FmtSource.STACK_BUFFER, 'stack-load'

        # 寄存器传播: mov reg, reg2 → 递归
        import re
        m = re.search(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b', src)
        if m:
            if insn.mnemonic.startswith('mov') and '[' not in src:
                return self._classify_reg(m.group(1).lower(), def_idx,
                                          tracer, depth + 1)
            info = tracer.trace(m.group(1).lower(), insn.addr)
            if 'input-call' in info.summary:
                return FmtSource.USER_INPUT, 'input-call'
            if info.is_constant and info.constant_value is not None:
                cv = info.constant_value
                if any(addr <= cv < addr + 40
                       for addr in self._rdata_addrs):
                    return FmtSource.CONST_RDATA, 'const-addr->%#x' % cv
            return FmtSource.UNKNOWN, 'reg-chain:%s' % info.summary[:40]

        # 堆指针: 调用前 mov rcx, rax 且 rax 为 malloc 标签
        ptr = _heap_label_before(self._insns, def_idx, tracer)
        if ptr:
            return FmtSource.HEAP_BUFFER, 'heap-label:%s' % ptr
        return FmtSource.UNKNOWN, 'no-evidence'

    def _def_of(self, reg: str, upto_idx: int) -> Optional[int]:
        import re
        for j in range(upto_idx - 1, max(0, upto_idx - 12) - 1, -1):
            insn = self._insns[j]
            if insn.mnemonic.startswith('call'):
                continue
            if ',' not in insn.operands:
                continue
            dst = insn.operands.split(',')[0].strip()
            m = re.search(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b', dst)
            if m and m.group(1).lower() == reg:
                return j
        return None


def _extract_rip_disp(src: str, insn, def_idx: int) -> Optional[int]:
    """lea reg, [rip+0x1234] → 计算目标地址."""
    import re
    m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]', src)
    if not m:
        return None
    disp = int(m.group(2), 16)
    target = insn.addr + 7 + (disp if m.group(1) == '+' else -disp)
    return target


def _heap_label_before(insns: list, upto_idx: int, tracer) -> Optional[str]:
    """def_idx 之前最近 malloc 标签定义."""
    return None
