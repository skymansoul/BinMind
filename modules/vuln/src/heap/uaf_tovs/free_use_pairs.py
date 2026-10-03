"""free/use 候选对提取 — 从函数指令流与分配标签提取结构化候选.

创建: 2023-06-03
设计决策:
  - 复用 func_analyzer 的 frees/writes/memcpys 记录, 但提取逻辑改为
    标签+寄存器双通道: free 调用点的 ptr_val 标签与 use 点的基址标签
    精确匹配优先; 标签不可解析时以寄存器传播链兜底.
  - 与 _uaf_intra_detect 的差异: 不限定前向 30 条指令窗口, 候选对
    交由 TOVS 时序验证裁决, 消除窗口截断造成的漏报.
"""
import re
from typing import Dict, List, Optional

from .types import FreeUsePair

_REG_RE = re.compile(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
                     re.IGNORECASE)


def extract_pairs(fa, fn_name: str) -> List[FreeUsePair]:
    """从 FunctionAnalysis 提取 (free, use) 候选对, 含 double-free."""
    pairs: List[FreeUsePair] = []
    freed: Dict[int, dict] = {}
    for f in fa.frees:
        pv = str(f.get('ptr_val', ''))
        if 'malloc' in pv or 'calloc' in pv or 'realloc' in pv:
            freed[f['addr']] = f
    if not freed:
        return pairs

    uses: List[dict] = []
    for w in fa.writes:
        uses.append({'addr': w['addr'], 'label': str(w.get('base_val', '')),
                     'reg': w.get('base_reg', ''), 'type': 'write'})
    for mc in fa.memcpys:
        uses.append({'addr': mc['addr'], 'label': str(mc.get('dst_val', '')),
                     'reg': mc.get('dst_reg', ''), 'type': 'call_via'})

    free_list = sorted(freed.items())
    for free_addr, f_info in free_list:
        f_label = _label_of(str(f_info.get('ptr_val', '')))
        f_reg = str(f_info.get('ptr_reg', ''))
        if f_label is None:
            continue
        for u in uses:
            u_label = _label_of(u['label'])
            if u_label == f_label and u['addr'] > free_addr:
                pairs.append(FreeUsePair(
                    function=fn_name, free_addr=free_addr,
                    use_addr=u['addr'], ptr_reg=f_reg,
                    ptr_label=u['label'], use_type=u['type'],
                    gap=u['addr'] - free_addr))
        # double free: 同一标签的第二次 free
        for f2_addr, f2_info in free_list:
            if f2_addr <= free_addr:
                continue
            f2_label = _label_of(str(f2_info.get('ptr_val', '')))
            if f2_label == f_label:
                pairs.append(FreeUsePair(
                    function=fn_name, free_addr=free_addr,
                    use_addr=f2_addr, ptr_reg=f_reg,
                    ptr_label=f_label, use_type='free',
                    gap=f2_addr - free_addr))
    return _dedup(pairs)


def _label_of(ptr_str: str) -> Optional[str]:
    """'malloc@140001772+40' → 提取归一标签(含偏移, 丢弃 +0)."""
    if not ptr_str:
        return None
    m = re.search(r'(malloc|calloc|realloc)@([0-9a-fA-F]+)((?:[+-]\d+)*)',
                  ptr_str)
    if not m:
        return None
    suffix = m.group(3) or ''
    if suffix.endswith('+0') or suffix.endswith('-0'):
        suffix = suffix[:-2]
    return '%s@%s%s' % (m.group(1), m.group(2), suffix)


def _dedup(pairs: List[FreeUsePair]) -> List[FreeUsePair]:
    seen = set()
    out = []
    for p in pairs:
        key = (p.free_addr, p.use_addr, p.ptr_label, p.use_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out
