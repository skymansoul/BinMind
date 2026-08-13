"""指针身份重定义验证 — free 与 use 之间指针是否被覆盖.

创建: 2023-10-07
设计决策:
  - free(p) 之后 p 若被重新赋值 (p = malloc / p = q / xor), 后续 use(p)
    指向新对象, 不构成 UAF. 线性扫描检测器无此验证, 是 UAF 误报主源之一.
  - 验证方法: 从 use 点后向追踪指针寄存器定义链 (复用 pcfv.value_flow
    的区间/常量/来源信息), 若定义链中出现 free 之后的覆盖定义且该定义
    的值来源不是 free 时的对象标签 → 身份被杀.
  - NULL 检查语义修正: free(p); if (p) use(p) 仍为 UAF — cmp/test 不改变
    对象身份, NULL 检查不构成防护 (防止过度过滤).
"""
import re
from typing import List, Optional, Tuple

from .types import Evidence, TovsRule, FreeUsePair

_REG_RE = re.compile(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b',
                     re.IGNORECASE)


class RedefVerifier:
    """指针身份重定义验证器."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {i.addr: n for n, i in enumerate(insns)}

    def verify(self, pair: FreeUsePair,
               tracer) -> Tuple[Optional[bool], List[Evidence]]:
        """返回 (身份是否被杀, 证据). None=无法判定."""
        evs: List[Evidence] = []
        free_idx = self._addr_to_idx.get(pair.free_addr)
        use_idx = self._addr_to_idx.get(pair.use_addr)
        if free_idx is None or use_idx is None or use_idx <= free_idx:
            return None, evs
        reg = pair.ptr_reg
        if not reg:
            return None, evs

        # use 点指针寄存器定义链: 若最后定义在 free 之前 → 身份未变
        last_def = self._last_def_before(reg, use_idx)
        if last_def is None or last_def <= free_idx:
            # 定义早于 free: 指针值即 free 时的对象 → 身份一致
            evs.append(Evidence(
                rule=TovsRule.IDENTITY_MATCH,
                detail='ptr %s last defined %#x before free %#x'
                       % (reg, last_def if last_def else 0, pair.free_addr),
                confidence=0.85))
            return False, evs

        # 存在 free 后的覆盖定义 → 检查其来源
        src_label = self._def_source_label(reg, last_def, tracer)
        if src_label is not None and src_label != pair.ptr_label:
            evs.append(Evidence(
                rule=TovsRule.REDEFINED_PTR,
                detail='ptr %s redefined at %#x to %s (was %s)'
                       % (reg, self._insns[last_def].addr, src_label,
                          pair.ptr_label),
                confidence=0.90,
                extra={'def_addr': self._insns[last_def].addr}))
            return True, evs
        return None, evs

    def _last_def_before(self, reg: str, upto_idx: int) -> Optional[int]:
        """reg 在 upto_idx 前最后一次定义索引."""
        for j in range(upto_idx - 1, -1, -1):
            insn = self._insns[j]
            mn = insn.mnemonic
            if mn in ('call', 'callq'):
                if reg == 'rax':
                    return j
                continue
            op = insn.operands
            if ',' not in op:
                continue
            dst = op.split(',')[0].strip()
            m = _REG_RE.search(dst)
            if m and m.group(1).lower() == reg:
                return j
        return None

    def _def_source_label(self, reg: str, def_idx: int,
                          tracer) -> Optional[str]:
        """定义指令的源标签: mov reg, imm/reg → 常量或调用结果."""
        insn = self._insns[def_idx]
        op = insn.operands
        if ',' not in op:
            return None
        src = op.split(',')[-1].strip()
        if insn.mnemonic.startswith('call'):
            return 'call-result'
        if insn.mnemonic in ('xor', 'pxor'):
            dst = op.split(',')[0].strip()
            if dst.rstrip() == src.rstrip():
                return 'null'
        m = _REG_RE.search(src)
        if m:
            # 源为寄存器: 追踪其定义链值, 若为常量 → 新对象/值
            info = tracer.trace(m.group(1).lower(), insn.addr)
            if info.is_constant:
                return 'const:%d' % info.constant_value
            if info.interval_lo == 0 and info.interval_hi == 0 \
                    and info.is_constant:
                return 'const:0'
            return None
        if re.match(r'^0x[0-9a-fA-F]+$|^\d+$', src):
            return 'const:%s' % src
        if '[' in src:
            return 'mem-load'
        return None
