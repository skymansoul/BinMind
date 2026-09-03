"""跨函数 free/use 事件提取 — 调用点指针标签驱动的候选对.

创建: 2024-09-18
设计决策:
  - 复用 PCFV AccessExtractor 的前向指针标签追踪: 函数内 call 的
    参数寄存器 (rcx/rdi) 若持有 malloc@ 标签, 该调用即一个潜在
    free/use 事件.
  - 被调函数分类: 名字含 free/cleanup/release/destroy/close → free 事件;
    其余含指针参数调用 → use 事件 (保守). 无符号名时归入 use.
  - 事件地址=调用点地址, 使跨函数候选可在调用方函数内做时序验证.
"""
import re
from typing import Dict, List, Optional

from .types import FreeUsePair

_FREE_HINTS = ('free', 'cleanup', 'release', 'destroy', 'close',
               'deinit', 'unref')

# 直接调用/尾调用释放函数的指令模式 (含 C++ operator delete)
# O2 优化常将 wrapper 尾调用转为 jmp, 覆盖 call 和 jmp 两种形式
_FREE_DIRECT = re.compile(
    r'\b(?:call|jmp)\s+(?:[0-9a-f]+\s+)?'
    r'<(?:free|kfree|vfree|_ZdlPv|_ZdaPv)(?:@plt)?>'
)


def extract_cross_fn_pairs(insns: list, fn_name: str,
                           malloc_summary: dict = None) -> List[FreeUsePair]:
    """从调用方函数指令流提取跨函数 (free, use) 候选对."""
    from pcfv.access_extractor import AccessExtractor

    ex = AccessExtractor(fn_name, insns, malloc_ret_summary=malloc_summary)
    pairs: List[FreeUsePair] = []
    free_events: List[dict] = []
    use_events: List[dict] = []

    # 从 AccessExtractor 的调用点快照提取事件
    for addr, reg, label in ex.call_arg_labels:
        insn = next((i for i in insns if i.addr == addr), None)
        if insn is None:
            continue
        callee = insn.operands.lower()
        if '<' in callee:
            name = callee.split('<')[-1].split('>')[0].split('@')[0]
            if any(h in name for h in _FREE_HINTS):
                free_events.append({'addr': addr, 'label': label,
                                    'reg': reg})
                continue
        # 间接调用 (call rax) 或非 free 名 → use 事件
        use_events.append({'addr': addr, 'label': label, 'reg': reg})

    # 内联展开检测: O2 消除调用边界后函数体内直接出现 call/jmp free
    # 此时 AccessExtractor 可能未追踪到参数标签, 需独立扫描指令流
    seen_addrs = {e['addr'] for e in free_events}
    for insn in insns:
        raw = insn.raw.lower() if hasattr(insn, 'raw') else ''
        if not raw:
            # 无 raw 字段时用助记符+操作数拼接近似
            raw = (getattr(insn, 'mnemonic', '') + ' ' +
                   getattr(insn, 'operands', '')).lower()
        if _FREE_DIRECT.search(raw):
            if insn.addr in seen_addrs:
                continue
            # 内联 free 的参数寄存器优先取 rdi (x86-64 调用约定)
            free_events.append({'addr': insn.addr, 'label': label,
                                'reg': 'rdi'})
            seen_addrs.add(insn.addr)

    for fe in free_events:
        for ue in use_events:
            if ue['label'] == fe['label'] and ue['addr'] > fe['addr']:
                pairs.append(FreeUsePair(
                    function=fn_name, free_addr=fe['addr'],
                    use_addr=ue['addr'], ptr_reg=fe['reg'],
                    ptr_label=fe['label'], use_type='call_via',
                    gap=ue['addr'] - fe['addr']))
    return pairs
