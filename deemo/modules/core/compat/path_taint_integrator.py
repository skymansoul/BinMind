# coding: utf-8
"""
路径敏感的污点集成 — 在 IR 级别归一化漏洞检测特征, 消除对 API 名称的依赖.

问题:
  heap_analyzer/uaf_detector 依赖精确 API 名称 (malloc/HeapAlloc 等).
  加壳后符号表不可用 → 无法识别分配/释放操作 → 检测完全失效.

方案:
  在 IR 级别提取归一化特征, 不依赖符号名:
    alloc_site = (size_expression, return_value_use, call_type)
    free_site   = (argument_pattern, call_type)
    use_site    = (pointer_deref_pattern, access_size)

  这些特征在跨编译器/跨优化级别的场景中保持稳定,
  因为编译器生成的 IR 模式受 ABI 约束而具有一致性.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class NormalizedAllocSite:
    """归一化的分配点描述 — 不依赖 API 名称."""
    addr: int
    size_expr: str           # 大小表达式 (IR 表示)
    retval_use: str          # 返回值使用模式: 'stored_to_mem' | 'passed_to_func' | 'compared'
    has_size_check: bool     # 分配前是否检查了大小 (size > 0?)
    ir_pattern: str          # IR 操作序列的哈希 (用于跨二进制匹配)


@dataclass
class NormalizedFreeSite:
    addr: int
    arg_pattern: str         # 被释放指针的来源模式
    ir_pattern: str


@dataclass
class NormalizedUseSite:
    addr: int
    deref_pattern: str       # 解引用模式: 'load' | 'store' | 'call_indirect'
    access_size: int


# alloc 的 IR 模式特征 (x86-64, LLVM IR, Ghidra PCode 均可映射):
#   call alloc_func(size) → test rax, rax → jz error_path → store rax to mem
_ALLOC_IR_PATTERN = re.compile(
    r'(?:call|invoke).*?\((?:i32|i64)\s+(\d+|%\w+)\).*?'
    r'(?:icmp|test|cmp).*?(?:jz|je|jne|br).*?'
    r'(?:store|mov).*?(?:%\w+|r\w+)',
    re.I | re.DOTALL)

# free 的 IR 模式:
#   load ptr from mem → call free_func(ptr)
_FREE_IR_PATTERN = re.compile(
    r'(?:load|mov).*?(?:%\w+|r\w+).*?'
    r'(?:call|invoke).*?\((?:i8\*|ptr|%\w+|r\w+)\)',
    re.I | re.DOTALL)

# use 的 IR 模式 (解引用):
#   load/store through pointer → [ptr + offset]
_USE_IR_PATTERN = re.compile(
    r'(?:load|store).*?\[.*?(?:%\w+|r\w+).*?[+\-]\s*\d+\]',
    re.I)


def extract_normalized_alloc_sites(
    ir_text: str,
    ir_ops: Optional[Dict[int, Dict]] = None,
) -> List[NormalizedAllocSite]:
    """从 IR 文本中提取归一化的分配点."""
    sites = []
    for m in _ALLOC_IR_PATTERN.finditer(ir_text):
        matched = m.group()
        size_expr = 'unknown'
        size_match = re.search(r'\((?:i32|i64)\s+(\d+|%\w+)\)', matched)
        if size_match:
            size_expr = size_match.group(1)
        has_check = 'icmp' in matched or 'cmp' in matched or 'test' in matched
        retval = 'stored_to_mem' if 'store' in matched.lower() else 'unknown'
        sites.append(NormalizedAllocSite(
            addr=m.start(), size_expr=size_expr, retval_use=retval,
            has_size_check=has_check, ir_pattern=matched[:80],
        ))
    return sites


def extract_normalized_free_sites(ir_text: str) -> List[NormalizedFreeSite]:
    sites = []
    for m in _FREE_IR_PATTERN.finditer(ir_text):
        matched = m.group()
        arg = 'unknown'
        arg_match = re.search(r'\((?:i8\*|ptr|%\w+|r\w+)\)', matched)
        if arg_match:
            arg = arg_match.group().strip('()')
        sites.append(NormalizedFreeSite(
            addr=m.start(), arg_pattern=arg, ir_pattern=matched[:80],
        ))
    return sites


def extract_normalized_use_sites(ir_text: str) -> List[NormalizedUseSite]:
    sites = []
    for m in _USE_IR_PATTERN.finditer(ir_text):
        matched = m.group()
        deref = 'load' if matched.startswith('load') else 'store'
        size = 4  # 默认
        size_match = re.search(r'(?:i8|i16|i32|i64)\b', matched)
        if size_match:
            size = {'i8': 1, 'i16': 2, 'i32': 4, 'i64': 8}.get(size_match.group(), 4)
        sites.append(NormalizedUseSite(
            addr=m.start(), deref_pattern=deref, access_size=size,
        ))
    return sites


def build_def_use_chains(
    alloc_sites: List[NormalizedAllocSite],
    free_sites: List[NormalizedFreeSite],
    use_sites: List[NormalizedUseSite],
) -> Dict[int, List[int]]:
    """构建简化的 def-use 链: 每个 use_site → 其数据来源的 alloc_site.

    启发式: 按地址顺序, 将每个 use 关联到最近的尚未被 free 的 alloc.
    这是保守的过近似 — 实际 def-use 需要完整的指针分析.
    """
    chains: Dict[int, List[int]] = defaultdict(list)
    alloc_stack: List[int] = []

    # 合并所有事件并按地址排序
    events = (
        [('alloc', a.addr) for a in alloc_sites]
        + [('free', f.addr) for f in free_sites]
        + [('use', u.addr) for u in use_sites]
    )
    events.sort(key=lambda e: e[1])

    for evt_type, addr in events:
        if evt_type == 'alloc':
            alloc_stack.append(addr)
        elif evt_type == 'free' and alloc_stack:
            alloc_stack.pop()  # 最近分配被释放
        elif evt_type == 'use' and alloc_stack:
            chains[addr].append(alloc_stack[-1])

    return dict(chains)


def normalize_detection_features(
    alloc_sites: List[NormalizedAllocSite],
    free_sites: List[NormalizedFreeSite],
    use_sites: List[NormalizedUseSite],
) -> Dict[str, Any]:
    """汇总归一化特征统计."""
    chains = build_def_use_chains(alloc_sites, free_sites, use_sites)
    return {
        'alloc_count': len(alloc_sites),
        'free_count': len(free_sites),
        'use_count': len(use_sites),
        'matched_def_use': len(chains),
        'alloc_with_size_check': sum(1 for a in alloc_sites if a.has_size_check),
        'alloc_without_check': sum(1 for a in alloc_sites if not a.has_size_check),
        'summary': (f'{len(alloc_sites)} allocs, {len(free_sites)} frees, '
                   f'{len(use_sites)} uses → {len(chains)} def-use chains'),
    }
