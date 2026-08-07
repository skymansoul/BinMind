"""Crash primitive fingerprinting: analysis functions."""

import re
from typing import Any, Dict, List, Optional, Tuple

from .crash_primitive_fingerprint_types import (
    HeapOperationSequence,
    PrimitiveType,
    RegisterAnalysis,
    RegisterControl,
    _VALUE_PATTERNS,
)


# 分析函数

def _analyze_register(
    reg_name: str,
    reg_value: int,
    stack_bounds: Optional[Tuple[int, int]] = None,
    heap_bounds: Optional[List[Tuple[int, int]]] = None,
) -> RegisterAnalysis:
    """Analyze register controllability and memory region membership."""
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

    # Check address region membership
    if stack_bounds and stack_bounds[0] <= reg_value <= stack_bounds[1]:
        analysis.points_to_stack = True
    if heap_bounds:
        for lo, hi in heap_bounds:
            if lo <= reg_value <= hi:
                analysis.points_to_heap = True
                break

    return analysis


def _extract_heap_ops_from_text(crash_text: str) -> Optional[HeapOperationSequence]:
    """Extract heap operation sequences from ASAN or glibc crash logs.

    ASAN format: "allocated by thread T0 here:" followed by allocation stack.
    glibc format: "free(): invalid pointer" / "double free or corruption"
    """
    seq = HeapOperationSequence()

    # ASAN heap operation patterns
    alloc_pattern = re.findall(
        r'(allocated by thread|freed by thread|previously allocated)',
        crash_text, re.IGNORECASE
    )

    # Extract allocation sizes
    sizes = re.findall(
        r'(?:alloc|malloc|calloc|realloc)[\w\s]*?(?:size|of)\s*(\d+)',
        crash_text, re.IGNORECASE
    )
    seq.alloc_sizes = [int(s) for s in sizes[:10]]

    # Freed chunk addresses
    freed = re.findall(
        r'(?:freed|freeing|attempt to free).*?(0x[0-9a-fA-F]{6,16})',
        crash_text, re.IGNORECASE
    )
    seq.freed_chunks = [int(a, 16) for a in freed[:5]]

    # Build operation sequence
    if 'allocated' in crash_text.lower() and 'freed' in crash_text.lower():
        seq.operations.append("alloc_free_interleave")
    if 'double free' in crash_text.lower():
        seq.operations.append("double_free")
        seq.glibc_version_hint = "2.31+"
    if 'use after free' in crash_text.lower() or 'heap-use-after-free' in crash_text:
        seq.operations.append("use_after_free")
    if 'tcache' in crash_text.lower():
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
    """Compute multi-axis exploitability scores (0.0 to 1.0)."""

    scores = {
        'rip_control': 0.0,
        'stack_control': 0.0,
        'heap_control': 0.0,
        'info_leak': 0.0,
    }

    # RIP control scoring based on rip/r15(ARM:pc) controllability
    rip_regs = ['rip', 'pc', 'eip', 'r15']
    for r in rip_regs:
        if r in reg_analysis:
            ra = reg_analysis[r]
            if ra.control == RegisterControl.CONTROLLED:
                scores['rip_control'] = 0.95
            elif ra.control == RegisterControl.PARTIALLY:
                scores['rip_control'] = 0.50
            elif ra.control == RegisterControl.ZERO:
                scores['rip_control'] = 0.05
            break

    # Stack control scoring based on rsp controllability
    sp_regs = ['rsp', 'sp', 'esp']
    for r in sp_regs:
        if r in reg_analysis:
            ra = reg_analysis[r]
            if ra.control == RegisterControl.CONTROLLED:
                scores['stack_control'] = 0.90
            elif ra.points_to_stack:
                scores['stack_control'] = 0.40
            break

    # Heap control scoring based on heap operation sequence
    if heap_ops:
        if 'use_after_free' in heap_ops.operations:
            scores['heap_control'] = 0.85
        elif 'double_free' in heap_ops.operations:
            scores['heap_control'] = 0.80
        elif 'alloc_free_interleave' in heap_ops.operations:
            scores['heap_control'] = 0.55

    # Info leak scoring
    # Check if any register points to a known library address range
    for ra in reg_analysis.values():
        if ra.contains_pattern and 'libc_range' in str(ra.control):
            scores['info_leak'] = max(scores['info_leak'], 0.60)
        if ra.points_to_heap and ra.control != RegisterControl.CONTROLLED:
            # 堆地址本身可能泄露布局信息
            scores['info_leak'] = max(scores['info_leak'], 0.30)

    # 综合可利用性: 加权平均，最大维度权重大
    weights = {'rip_control': 0.40, 'stack_control': 0.20,
               'heap_control': 0.30, 'info_leak': 0.10}
    overall = sum(scores[k] * weights[k] for k in scores)
    scores['overall'] = min(1.0, overall)

    return scores


def _recommend_strategy(
    scores: Dict[str, float], crash_type: str
) -> Tuple[List[PrimitiveType], str]:
    """Recommend exploit primitives and strategies based on scores."""
    primitives = []
    strategies = []

    if scores['rip_control'] > 0.8:
        primitives.append(PrimitiveType.RIP_CONTROL)
        strategies.append("direct RIP hijack, target GOT/PLT or one_gadget")
    elif scores['rip_control'] > 0.3:
        primitives.append(PrimitiveType.PARTIAL_RIP)

    if scores['stack_control'] > 0.7:
        primitives.append(PrimitiveType.STACK_PIVOT)
        strategies.append("stack pivot to controlled region, need gadget: xchg rsp, rax")

    if scores['heap_control'] > 0.7:
        if 'use_after_free' in crash_type.lower():
            primitives.append(PrimitiveType.UAF)
            strategies.append("UAF exploitation via tcache poisoning or overlapping allocation")
        elif 'double' in crash_type.lower():
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
