"""
Crash primitive fingerprinting for multi-dimensional exploitability assessment.

Instead of a binary "exploitable/not" verdict, this module scores a crash
along several axes: register control, stack/head layout clues, heap operation
patterns, and crash reachability. The composite score feeds exploit strategy
recommendations.

References:
  - Lancet (USENIX Security 2025): crash pathology formalization with ownership semantics
  - HEXP (IEEE 2025): automatic heap layout constraint exploit generation
  - AutoPwn (IEEE TIFS 2024): exploit pattern mining from historical exploits
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class RegisterControl(Enum):
    CONTROLLED = auto()       # attacker can directly control register value
    PARTIALLY = auto()        # attacker can partially influence (via offset)
    UNCONTROLLED = auto()     # register value not controllable
    ZERO = auto()             # register is NULL/0
    UNKNOWN = auto()          # insufficient information


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
    is_writable_address: bool = False     # 值是否指向可写内存区域
    points_to_stack: bool = False         # 值是否落在栈范围内
    points_to_heap: bool = False          # 值是否落在堆范围内
    contains_pattern: Optional[str] = None  # 如 "0x41414141" (AAAA pattern)


@dataclass
class HeapOperationSequence:
    """Heap operation sequence extracted from crash context, useful for UAF/double-free detection."""
    operations: List[str] = field(default_factory=list)  # ["alloc(0x40)", "free", "use", ...]
    freed_chunks: List[int] = field(default_factory=list)  # 已释放的内存地址
    alloc_sizes: List[int] = field(default_factory=list)   # 分配大小序列
    glibc_version_hint: str = ""        # 从crash输出中猜测的glibc版本
    tcache_bin_hint: Optional[int] = None  # 涉及tcache的bin编号


@dataclass
class CrashFingerprint:
    """Complete crash fingerprint with multi-dimensional exploitability signals."""
    crash_type: str
    registers: Dict[str, RegisterAnalysis] = field(default_factory=dict)
    heap_ops: Optional[HeapOperationSequence] = None
    faulting_instruction: str = ""
    faulting_address: int = 0
    stack_trace: List[str] = field(default_factory=list)
    # 多维评分 (0.0~1.0)
    rip_control_score: float = 0.0
    stack_control_score: float = 0.0
    heap_control_score: float = 0.0
    info_leak_score: float = 0.0
    overall_exploitability: float = 0.0
    # 推荐的利用策略
    recommended_primitives: List[PrimitiveType] = field(default_factory=list)
    recommended_strategy: str = ""


# Known register-value patterns mapped to exploit strategy hints.
# Derived from AutoPwn (2024) artifact analysis.
_VALUE_PATTERNS = {
    r'^0x41{4,}': ('user_controlled', 'pattern fill, RIP likely controllable'),
    r'^0x0+$': ('null_deref', 'NULL deref, usually not exploitable unless mmap_min_addr=0'),
    r'^0x7f[0-9a-f]{10,}': ('libc_range', 'address in libc range, potential info leak'),
    r'^0x7e[0-9a-f]{10,}': ('stack_probable', 'likely stack address'),
}


# ---- 分析函数 ----

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


# ---- 主接口 ----

def fingerprint_crash(
    crash_data: Dict[str, Any],
    stack_bounds: Optional[Tuple[int, int]] = None,
    heap_bounds: Optional[List[Tuple[int, int]]] = None,
) -> CrashFingerprint:
    """Multi-axis crash primitive fingerprinting.

    Args:
        crash_data: structured crash data from parse_crash()
        stack_bounds: (stack_low, stack_high)
        heap_bounds: [(heap_start, heap_end), ...]

    Returns:
        CrashFingerprint with scores and recommended strategy
    """
    raw_text = crash_data.get('raw', '')
    crash_type = crash_data.get('crash_type', 'unknown')
    addresses = crash_data.get('addresses', [])

    fingerprint = CrashFingerprint(crash_type=crash_type)

    # 1. Register analysis from crash data
    registers_raw = crash_data.get('registers', {})
    for reg_name, reg_val_str in registers_raw.items():
        try:
            reg_val = int(reg_val_str, 16) if isinstance(reg_val_str, str) else int(reg_val_str)
        except (ValueError, TypeError):
            continue
        fingerprint.registers[reg_name] = _analyze_register(
            reg_name, reg_val, stack_bounds, heap_bounds,
        )

    # 2. Heap operation sequence extraction
    fingerprint.heap_ops = _extract_heap_ops_from_text(raw_text)

    # 3. Faulting instruction and address
    fingerprint.faulting_instruction = crash_data.get('fault_instruction', '')
    if addresses:
        fingerprint.faulting_address = int(addresses[0], 16) if addresses[0].startswith('0x') else 0

    # 4. Stack trace
    fingerprint.stack_trace = crash_data.get('stack_trace', [])

    # 5. Multi-axis scoring
    fault_addr = fingerprint.faulting_address
    scores = _compute_exploitability_scores(
        fingerprint.registers, fingerprint.heap_ops, crash_type, fault_addr,
    )
    fingerprint.rip_control_score = scores['rip_control']
    fingerprint.stack_control_score = scores['stack_control']
    fingerprint.heap_control_score = scores['heap_control']
    fingerprint.info_leak_score = scores['info_leak']
    fingerprint.overall_exploitability = scores['overall']

    # 6. Strategy recommendation
    primitives, strategy = _recommend_strategy(scores, crash_type)
    fingerprint.recommended_primitives = primitives
    fingerprint.recommended_strategy = strategy

    # 7. Heap layout inference for heap-corruption crashes
    if crash_type in ('heap_corruption', 'uaf', 'double_free'):
        heap_ctx = infer_heap_layout(regs, crash_type)
        fingerprint.metadata['heap_context'] = heap_ctx

    return fingerprint


def infer_heap_layout(regs: Dict[str, str],
                       crash_type: str) -> Dict[str, Any]:
    """Infer heap chunk layout from crash register state.

    Determines whether the fault address lies in a known heap region, whether
    corrupted bytes overlap heap metadata (fd/bk pointers), and estimates chunk size.
    """
    ctx: Dict[str, Any] = {}
    rip = regs.get('rip', '')
    rsp = regs.get('rsp', '')
    rax = regs.get('rax', '')

    # Infer chunk size from crash address offset.
    # If crash address is 0x?8 aligned and next 8 bytes match a pattern,
    # the fd/bk pointers may have been overwritten.
    for reg_name, val in regs.items():
        if not val or len(val) < 4:
            continue
        try:
            addr = int(val, 16)
        except ValueError:
            continue
        # glibc chunk header: prev_size(8B) + size(8B, LSB=flags)
        # addr % 16 == 8 suggests writing the chunk's fd pointer
        if addr % 16 == 8 and crash_type == 'heap_corruption':
            ctx['likely_overwritten'] = 'fd_pointer'
            ctx['estimated_chunk_offset'] = 16  # skip prev_size + size header
        elif addr % 16 == 0 and crash_type == 'heap_corruption':
            ctx['likely_overwritten'] = 'prev_size_or_size_field'

    # Infer free-list state: if crash happens inside free(), chunk may already be in a bin
    if crash_type in ('uaf', 'double_free'):
        ctx['in_free_list'] = True
        ctx['note'] = 'crash during free, chunk may already be in free-list'

    return ctx
