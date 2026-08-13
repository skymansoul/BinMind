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
from typing import Dict, List, Optional

from .types import FreeUsePair

_FREE_HINTS = ('free', 'cleanup', 'release', 'destroy', 'close',
               'deinit', 'unref')


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

    for fe in free_events:
        for ue in use_events:
            if ue['label'] == fe['label'] and ue['addr'] > fe['addr']:
                pairs.append(FreeUsePair(
                    function=fn_name, free_addr=fe['addr'],
                    use_addr=ue['addr'], ptr_reg=fe['reg'],
                    ptr_label=fe['label'], use_type='call_via',
                    gap=ue['addr'] - fe['addr']))
    return pairs
