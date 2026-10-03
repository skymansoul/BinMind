# coding: utf-8
"""
未初始化内存检测 — CWE-457 (Use of Uninitialized Variable), 堆栈感知.
L1: alloc→use 间隔追踪 L2: 初始化写入路径验证 L3: 跨函数传播分析.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class InitStatus(Enum):
    UNINIT = auto()       # 分配后无写入
    PARTIAL = auto()       # 部分初始化 (某些字节未写)
    FULL = auto()          # 完全初始化
    UNKNOWN = auto()


@dataclass
class InitAnalysis:
    """单次初始化分析结果."""
    alloc_site: int
    alloc_size: int
    ptr_name: str
    status: InitStatus
    initialized_bytes: int
    uninitialized_ranges: List[Tuple[int, int]]  # [(start, end)]
    use_site: int
    use_offset: int
    use_size: int
    is_dangerous: bool
    confidence: float
    description: str


class InitTracker:
    """初始化状态追踪器 — 追踪分配的每个字节的初始化状态.

    方法: byte-level bitmap — 对 alloc(N) 维护一个 N 位的位图,
    每个 store 操作标记对应偏移为已初始化.
    在 load/use 点检查对应偏移是否已初始化.
    """

    def __init__(self, max_alloc_size: int = 4096):
        self._max = max_alloc_size
        self._allocations: Dict[int, Dict] = {}  # alloc_addr → {size, ptr, bitmap}

    def record_alloc(self, addr: int, size: int, ptr: str):
        """记录分配事件."""
        if size > self._max:
            size = self._max  # 截断大分配以节省内存
        self._allocations[addr] = {
            'size': size, 'ptr': ptr,
            # bitmap: 字节 bitmap, 0=未初始化, 1=已初始化
            'bitmap': bytearray((size + 7) // 8),
        }

    def record_write(self, alloc_addr: int, offset: int, size: int):
        """记录对分配的写入."""
        if alloc_addr not in self._allocations:
            return
        alloc = self._allocations[alloc_addr]
        alloc_sz = alloc['size']
        if offset >= alloc_sz:
            return  # 越界写入 → 由 heap overflow 管线处理

        bitmap = alloc['bitmap']
        end = min(offset + size, alloc_sz)
        for byte_idx in range(offset, end):
            byte_offset = byte_idx // 8
            bit_mask = 1 << (byte_idx % 8)
            bitmap[byte_offset] |= bit_mask

    def check_use(self, alloc_addr: int, offset: int, size: int,
                  use_site: int) -> Optional[InitAnalysis]:
        """检查在 use_site 处的读取是否使用了未初始化内存.

        返回 InitAnalysis 若有未初始化使用, 否则 None.
        """
        if alloc_addr not in self._allocations:
            return None
        alloc = self._allocations[alloc_addr]
        alloc_sz = alloc['size']
        bitmap = alloc['bitmap']

        if offset >= alloc_sz:
            return None

        end = min(offset + size, alloc_sz)
        uninit_ranges = []
        cur_start = -1

        for byte_idx in range(offset, end):
            byte_offset = byte_idx // 8
            bit_mask = 1 << (byte_idx % 8)
            is_init = bool(bitmap[byte_offset] & bit_mask)
            if not is_init:
                if cur_start < 0:
                    cur_start = byte_idx
            else:
                if cur_start >= 0:
                    uninit_ranges.append((cur_start, byte_idx))
                    cur_start = -1
        if cur_start >= 0:
            uninit_ranges.append((cur_start, end))

        if not uninit_ranges:
            return None

        total_uninit = sum(e - s for s, e in uninit_ranges)
        init_bytes = (end - offset) - total_uninit

        # 判定状态
        if total_uninit == (end - offset):
            status = InitStatus.UNINIT
            conf = 0.90
        elif total_uninit > 0:
            status = InitStatus.PARTIAL
            conf = 0.70
        else:
            status = InitStatus.FULL
            conf = 0.0

        return InitAnalysis(
            alloc_site=alloc_addr, alloc_size=alloc_sz,
            ptr_name=alloc['ptr'], status=status,
            initialized_bytes=init_bytes,
            uninitialized_ranges=uninit_ranges,
            use_site=use_site, use_offset=offset, use_size=size,
            is_dangerous=(status in (InitStatus.UNINIT, InitStatus.PARTIAL)),
            confidence=conf,
            description=(
                f'{"完全未初始化" if status == InitStatus.UNINIT else "部分未初始化"}: '
                f'{total_uninit}/{end-offset} 字节未初始化, '
                f'范围={uninit_ranges}'),
        )


def detect_uninitialized_use(
    instructions: List[Dict],
    ir_ops: Dict[int, Dict],
    callee_names: Dict[int, str] = None,
) -> Tuple[List[InitAnalysis], Dict]:
    """从未初始化使用检测 — 从指令序列中追踪 alloc→write→use 模式."""
    if callee_names is None:
        callee_names = {}
    tracker = InitTracker()
    results = []
    stats = {'allocs': 0, 'writes': 0, 'uses': 0, 'uninit_uses': 0}

    for inst in instructions:
        addr = inst['addr']
        op = ir_ops.get(addr, {})
        callee = callee_names.get(addr, '').lower()

        # 检测 alloc 调用
        alloc_keywords = ('malloc', 'calloc', 'realloc', '_Znwm', '_Znam', 'alloca')
        if any(a in callee for a in alloc_keywords):
            size = op.get('alloc_size', op.get('size', 0))
            ptr = op.get('dest', op.get('return_reg', 'rax'))
            if size > 0:
                tracker.record_alloc(addr, size, ptr)
                stats['allocs'] += 1

        # 检测 store/write 操作
        elif op.get('op_type') in ('store', 'write', 'memcpy', 'memset'):
            # 找到对应的 alloc
            dest = op.get('dest', op.get('base', ''))
            offset = op.get('offset', 0)
            size = op.get('size', op.get('write_size', 8))
            for alloc_addr, alloc_info in tracker._allocations.items():
                if alloc_info['ptr'] in dest or dest in alloc_info['ptr']:
                    tracker.record_write(alloc_addr, offset, size)
                    stats['writes'] += 1

        # 检测 load/read 操作
        elif op.get('op_type') in ('load', 'read', 'call'):
            src = op.get('src', op.get('base', ''))
            offset = op.get('offset', 0)
            size = op.get('size', 8)
            stats['uses'] += 1
            for alloc_addr in tracker._allocations:
                alloc_info = tracker._allocations[alloc_addr]
                if alloc_info['ptr'] in src or src in alloc_info['ptr']:
                    analysis = tracker.check_use(alloc_addr, offset, size, addr)
                    if analysis:
                        results.append(analysis)
                        stats['uninit_uses'] += 1

    return results, stats


def batch_detect_uninit(
    candidates: List[Dict],
    instructions: List[Dict],
    ir_ops: Dict[int, Dict],
    callee_names: Dict[int, str] = None,
) -> Tuple[List[Dict], Dict]:
    """批量未初始化使用检测 — 从候选列表."""
    analyses, stats = detect_uninitialized_use(
        instructions, ir_ops, callee_names)

    result_dicts = [{
        'alloc_site': a.alloc_site, 'use_site': a.use_site,
        'vuln_type': 'uninitialized_memory',
        'cwe': 'CWE-457',
        'confidence': a.confidence,
        'is_dangerous': a.is_dangerous,
        'uninit_ranges': a.uninitialized_ranges,
        'description': a.description,
    } for a in analyses]

    return result_dicts, stats


# L3: 跨函数传播分析

class CrossFunctionInitTracker:
    """L3: 跨函数未初始化传播 — 追踪参数是否未初始化.

    场景: func_A alloc 但不初始化, 传递给 func_B 使用.
    """

    def __init__(self):
        self._interproc_graph: Dict[int, List[int]] = {}  # caller → [callees]

    def add_call_edge(self, caller: int, callee: int):
        self._interproc_graph.setdefault(caller, []).append(callee)

    def trace_uninit_across_calls(
        self, init_analyses: List[InitAnalysis],
        call_graph: Dict[int, List[int]] = None,
    ) -> List[Dict]:
        """追踪未初始化变量的跨函数传播."""
        if call_graph is None:
            call_graph = {}

        propagated = []
        for a in init_analyses:
            if a.use_site in call_graph:
                callees = call_graph[a.use_site]
                for callee in callees:
                    propagated.append({
                        'source_alloc': a.alloc_site,
                        'propagation_site': a.use_site,
                        'target_callee': callee,
                        'original_confidence': a.confidence,
                        # 跨函数传播降低置信度 (间接使用)
                        'propagated_confidence': round(a.confidence * 0.80, 4),
                        'uninit_ranges': a.uninitialized_ranges,
                    })
        return propagated
