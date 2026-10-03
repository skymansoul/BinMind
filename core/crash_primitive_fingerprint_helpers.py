"""崩溃原语指纹的核心数据类型、常量与分析辅助函数。"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

import logging

_log = logging.getLogger(__name__)


class RegisterControl(Enum):
    CONTROLLED = auto()
    PARTIALLY = auto()
    UNCONTROLLED = auto()
    ZERO = auto()
    UNKNOWN = auto()


class PrimitiveType(Enum):
    RIP_CONTROL = "rip_control"
    PARTIAL_RIP = "partial_rip"
    ARBITRARY_READ = "arbitrary_read"
    ARBITRARY_WRITE = "arbitrary_write"
    STACK_PIVOT = "stack_pivot"
    HEAP_CORRUPTION = "heap_corruption"
    UAF = "use_after_free"
    DOUBLE_FREE = "double_free"
    INFO_LEAK = "info_leak"
    NULL_DEREF = "null_deref"
    UNKNOWN = "unknown"


@dataclass
class RegisterAnalysis:
    """单个寄存器的可控性分析。"""
    name: str
    value: int = 0
    control: RegisterControl = RegisterControl.UNKNOWN
    is_writable_address: bool = False
    points_to_stack: bool = False
    points_to_heap: bool = False
    contains_pattern: Optional[str] = None


@dataclass
class HeapOperationSequence:
    """从崩溃上下文中提取的堆操作序列，用于 UAF/double-free 检测。"""
    operations: List[str] = field(default_factory=list)
    freed_chunks: List[int] = field(default_factory=list)
    alloc_sizes: List[int] = field(default_factory=list)
    glibc_version_hint: str = ""
    tcache_bin_hint: Optional[int] = None


@dataclass
class CrashFingerprint:
    """完整的崩溃指纹，含多维可利用性信号。"""
    crash_type: str
    registers: Dict[str, RegisterAnalysis] = field(default_factory=dict)
    heap_ops: Optional[HeapOperationSequence] = None
    faulting_instruction: str = ""
    faulting_address: int = 0
    stack_trace: List[str] = field(default_factory=list)
    rip_control_score: float = 0.0
    stack_control_score: float = 0.0
    heap_control_score: float = 0.0
    info_leak_score: float = 0.0
    overall_exploitability: float = 0.0
    recommended_primitives: List[PrimitiveType] = field(default_factory=list)
    recommended_strategy: str = ""


# 寄存器值模式 → 利用策略提示
_VALUE_PATTERNS = {
    r'^0x41{4,}': ('user_controlled', 'pattern fill, RIP likely controllable'),
    r'^0x0+$': ('null_deref', 'NULL deref, usually not exploitable unless mmap_min_addr=0'),
    r'^0x7f[0-9a-f]{10,}': ('libc_range', 'address in libc range, potential info leak'),
    r'^0x7e[0-9a-f]{10,}': ('stack_probable', 'likely stack address'),
}


def _analyze_register(
    reg_name: str,
    reg_value: int,
    stack_bounds: Optional[Tuple[int, int]] = None,
    heap_bounds: Optional[List[Tuple[int, int]]] = None,
) -> RegisterAnalysis:
    """分析寄存器可控性与内存区域归属。"""
    analysis = RegisterAnalysis(name=reg_name, value=reg_value)

    hex_val = f"0x{reg_value:x}"
    for pattern, (control_hint, _) in _VALUE_PATTERNS.items():
        if re.match(pattern, hex_val, re.IGNORECASE):
            if control_hint == 'user_controlled':
                analysis.control = RegisterControl.CONTROLLED
                analysis.contains_pattern = hex_val[:12]
            elif control_hint == 'null_deref':
                analysis.control = RegisterControl.ZERO
            elif control_hint == 'libc_range':
                analysis.control = RegisterControl.PARTIALLY
            elif control_hint == 'stack_probable':
                analysis.points_to_stack = True
            break

    if stack_bounds and stack_bounds[0] <= reg_value <= stack_bounds[1]:
        analysis.points_to_stack = True
    if heap_bounds:
        for lo, hi in heap_bounds:
            if lo <= reg_value <= hi:
                analysis.points_to_heap = True
                break

    return analysis


def _extract_heap_ops_from_text(crash_text: str) -> Optional[HeapOperationSequence]:
    """从 ASAN/glibc 崩溃日志中提取堆操作序列。"""
    seq = HeapOperationSequence()

    re.findall(
        r'(allocated by thread|freed by thread|previously allocated)',
        crash_text, re.IGNORECASE,
    )

    sizes = re.findall(
        r'(?:alloc|malloc|calloc|realloc)[\w\s]*?(?:size|of)\s*(\d+)',
        crash_text, re.IGNORECASE,
    )
    seq.alloc_sizes = [int(s) for s in sizes[:10]]

    freed = re.findall(
        r'(?:freed|freeing|attempt to free).*?(0x[0-9a-fA-F]{6,16})',
        crash_text, re.IGNORECASE,
    )
    seq.freed_chunks = [int(a, 16) for a in freed[:5]]

    low = crash_text.lower()
    if 'allocated' in low and 'freed' in low:
        seq.operations.append("alloc_free_interleave")
    if 'double free' in low:
        seq.operations.append("double_free")
        seq.glibc_version_hint = "2.31+"
    if 'use after free' in low or 'heap-use-after-free' in crash_text:
        seq.operations.append("use_after_free")
    if 'tcache' in low:
        seq.tcache_bin_hint = 0

    if not seq.operations and not seq.alloc_sizes and not seq.freed_chunks:
        return None

    return seq


def _compute_exploitability_scores(
    reg_analysis: Dict[str, RegisterAnalysis],
    heap_ops: Optional[HeapOperationSequence],
    crash_type: str,
    fault_addr: int,
) -> Dict[str, float]:
    """计算多轴可利用性评分 (0.0~1.0)。"""
    scores = {
        'rip_control': 0.0,
        'stack_control': 0.0,
        'heap_control': 0.0,
        'info_leak': 0.0,
    }

    for r in ['rip', 'pc', 'eip', 'r15']:
        if r in reg_analysis:
            ra = reg_analysis[r]
            if ra.control == RegisterControl.CONTROLLED:
                scores['rip_control'] = 0.95
            elif ra.control == RegisterControl.PARTIALLY:
                scores['rip_control'] = 0.50
            elif ra.control == RegisterControl.ZERO:
                scores['rip_control'] = 0.05
            break

    for r in ['rsp', 'sp', 'esp']:
        if r in reg_analysis:
            ra = reg_analysis[r]
            if ra.control == RegisterControl.CONTROLLED:
                scores['stack_control'] = 0.90
            elif ra.points_to_stack:
                scores['stack_control'] = 0.40
            break

    if heap_ops:
        if 'use_after_free' in heap_ops.operations:
            scores['heap_control'] = 0.85
        elif 'double_free' in heap_ops.operations:
            scores['heap_control'] = 0.80
        elif 'alloc_free_interleave' in heap_ops.operations:
            scores['heap_control'] = 0.55

    for ra in reg_analysis.values():
        if ra.contains_pattern and 'libc_range' in str(ra.control):
            scores['info_leak'] = max(scores['info_leak'], 0.60)
        if ra.points_to_heap and ra.control != RegisterControl.CONTROLLED:
            scores['info_leak'] = max(scores['info_leak'], 0.30)

    weights = {'rip_control': 0.40, 'stack_control': 0.20,
               'heap_control': 0.30, 'info_leak': 0.10}
    overall = sum(scores[k] * weights[k] for k in scores)
    scores['overall'] = min(1.0, overall)

    return scores


def _recommend_strategy(
    scores: Dict[str, float], crash_type: str,
) -> Tuple[List[PrimitiveType], str]:
    """基于评分推荐利用原语与策略。"""
    primitives: List[PrimitiveType] = []
    strategies: List[str] = []

    if scores['rip_control'] > 0.8:
        primitives.append(PrimitiveType.RIP_CONTROL)
        strategies.append("direct RIP hijack, target GOT/PLT or one_gadget")
    elif scores['rip_control'] > 0.3:
        primitives.append(PrimitiveType.PARTIAL_RIP)

    if scores['stack_control'] > 0.7:
        primitives.append(PrimitiveType.STACK_PIVOT)
        strategies.append("stack pivot to controlled region, need gadget: xchg rsp, rax")

    if scores['heap_control'] > 0.7:
        low = crash_type.lower()
        if 'use_after_free' in low:
            primitives.append(PrimitiveType.UAF)
            strategies.append("UAF exploitation via tcache poisoning or overlapping allocation")
        elif 'double' in low:
            primitives.append(PrimitiveType.DOUBLE_FREE)
            strategies.append("double-free via fastbin dup or tcache key bypass (glibc 2.32+)")
        else:
            primitives.append(PrimitiveType.HEAP_CORRUPTION)
            strategies.append("heap corruption, analyze allocator state for concrete primitive")

    if scores['info_leak'] > 0.4:
        primitives.append(PrimitiveType.INFO_LEAK)

    if not primitives:
        primitives.append(PrimitiveType.UNKNOWN)
        strategies.append("insufficient data, deterministic replay recommended for more context")

    return primitives, "; ".join(strategies) if strategies else "further analysis needed"


def infer_heap_layout(
    regs: Dict[str, str], crash_type: str,
) -> Dict[str, Any]:
    """从崩溃寄存器状态推断堆 chunk 布局。"""
    ctx: Dict[str, Any] = {}

    for reg_name, val in regs.items():
        if not val or len(val) < 4:
            continue
        try:
            addr = int(val, 16)
        except ValueError:
            continue
        if addr % 16 == 8 and crash_type == 'heap_corruption':
            ctx['likely_overwritten'] = 'fd_pointer'
            ctx['estimated_chunk_offset'] = 16
        elif addr % 16 == 0 and crash_type == 'heap_corruption':
            ctx['likely_overwritten'] = 'prev_size_or_size_field'

    if crash_type in ('uaf', 'double_free'):
        ctx['in_free_list'] = True
        ctx['note'] = 'crash during free, chunk may already be in free-list'

    return ctx
