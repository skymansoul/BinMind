# 崩溃原语多维指纹识别 — 替代简单的二值 exploitable 判定。

"""
崩溃原语指纹识别 —— 从crash dump中提取多维度的可利用性信号，
替代简单的二值"是否可利用"判定。

设计动机:
  现有 crash_analysis.py 的 analyze_crash_for_exploit() 将可利用性
  简化为二值判定（type==SIGSEGV→exploitable=True），丢失大量信息。
  实际场景中，同样是SIGSEGV:
    - RIP=0x41414141 → 直接的rip控制 → 高可利用性
    - RIP=0x00000000 → NULL deref → 通常不可利用
    - RIP=合法代码地址但RSP指向攻击者控制区域 → 需要stack pivot → 中等

  本模块提供多维评分: 寄存器可控性 + 内存布局线索 + 堆操作模式 +
  崩溃可达性，综合判定可利用性和推荐利用策略。

参考:
  - Lancet (USENIX Security 2025): 崩溃病理形式化框架，用所有权语义
    区分漏洞类型和利用原语。本模块借鉴其"原语指纹"概念，用寄存器
    状态替代所有权追踪——更轻量但覆盖范围不如其全面。
  - HEXP (IEEE 2025): 堆布局约束自动利用生成。本模块借鉴其堆操作
    序列提取思路，但只做指纹识别不做利用生成。
  - AutoPwn (IEEE TIFS 2024): 从历史利用中总结利用模式。本模块的
    原语→策略映射借鉴了此思路，但模式库以规则形式硬编码。
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class RegisterControl(Enum):
    CONTROLLED = auto()       # 攻击者可直接控制寄存器值
    PARTIALLY = auto()        # 攻击者可部分影响（如通过偏移）
    UNCONTROLLED = auto()     # 寄存器值不可控
    ZERO = auto()             # 寄存器为NULL/0
    UNKNOWN = auto()          # 信息不足


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
    """从crash上下文提取的堆操作序列——有助于识别UAF/double-free。"""
    operations: List[str] = field(default_factory=list)  # ["alloc(0x40)", "free", "use", ...]
    freed_chunks: List[int] = field(default_factory=list)  # 已释放的内存地址
    alloc_sizes: List[int] = field(default_factory=list)   # 分配大小序列
    glibc_version_hint: str = ""        # 从crash输出中猜测的glibc版本
    tcache_bin_hint: Optional[int] = None  # 涉及tcache的bin编号


@dataclass
class CrashFingerprint:
    """完整的崩溃指纹——多维可利用性信号。"""
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


# ---- 已知模式库 ----

# 从历史利用中总结的寄存器值模式→利用策略映射
# 参考: AutoPwn (2024) 的 artifact 总结思路
_VALUE_PATTERNS = {
    r'^0x41{4,}': ('user_controlled', 'pattern填充 — RIP可能可控'),
    r'^0x0+$': ('null_deref', 'NULL解引用 — 通常不可利用，除非mmap_min_addr=0'),
    r'^0x7f[0-9a-f]{10,}': ('libc_range', '地址落在libc范围 — 信息泄露可能'),
    r'^0x7e[0-9a-f]{10,}': ('stack_probable', '疑似栈地址'),
}


# ---- 分析函数 ----

def _analyze_register(
    reg_name: str,
    reg_value: int,
    stack_bounds: Optional[Tuple[int, int]] = None,
    heap_bounds: Optional[List[Tuple[int, int]]] = None,
) -> RegisterAnalysis:
    """分析单个寄存器的可控性和内存区域归属。"""
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

    # 检查地址归属
    if stack_bounds and stack_bounds[0] <= reg_value <= stack_bounds[1]:
        analysis.points_to_stack = True
    if heap_bounds:
        for lo, hi in heap_bounds:
            if lo <= reg_value <= hi:
                analysis.points_to_heap = True
                break

    return analysis


def _extract_heap_ops_from_text(crash_text: str) -> Optional[HeapOperationSequence]:
    """从ASAN或glibc崩溃日志中提取堆操作序列。

    ASAN格式: "allocated by thread T0 here:" 后跟分配栈
    glibc格式: "free(): invalid pointer" / "double free or corruption"
    """
    seq = HeapOperationSequence()

    # ASAN堆操作模式
    alloc_pattern = re.findall(
        r'(allocated by thread|freed by thread|previously allocated)',
        crash_text, re.IGNORECASE
    )

    # 提取分配大小
    sizes = re.findall(
        r'(?:alloc|malloc|calloc|realloc)[\w\s]*?(?:size|of)\s*(\d+)',
        crash_text, re.IGNORECASE
    )
    seq.alloc_sizes = [int(s) for s in sizes[:10]]

    # 释放的chunk地址
    freed = re.findall(
        r'(?:freed|freeing|attempt to free).*?(0x[0-9a-fA-F]{6,16})',
        crash_text, re.IGNORECASE
    )
    seq.freed_chunks = [int(a, 16) for a in freed[:5]]

    # 构建操作序列
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
    """多维可利用性评分——0.0到1.0。"""

    scores = {
        'rip_control': 0.0,
        'stack_control': 0.0,
        'heap_control': 0.0,
        'info_leak': 0.0,
    }

    # RIP控制评分: 基于rip/r15(ARM:pc)的可控性
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

    # 栈控制评分: 基于rsp的可控性或其指向区域
    sp_regs = ['rsp', 'sp', 'esp']
    for r in sp_regs:
        if r in reg_analysis:
            ra = reg_analysis[r]
            if ra.control == RegisterControl.CONTROLLED:
                scores['stack_control'] = 0.90
            elif ra.points_to_stack:
                scores['stack_control'] = 0.40
            break

    # 堆控制评分: 基于堆操作序列
    if heap_ops:
        if 'use_after_free' in heap_ops.operations:
            scores['heap_control'] = 0.85
        elif 'double_free' in heap_ops.operations:
            scores['heap_control'] = 0.80
        elif 'alloc_free_interleave' in heap_ops.operations:
            scores['heap_control'] = 0.55

    # 信息泄露评分: 基于是否有寄存器指向已知库地址
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
    """基于评分推荐利用原语和策略。"""
    primitives = []
    strategies = []

    if scores['rip_control'] > 0.8:
        primitives.append(PrimitiveType.RIP_CONTROL)
        strategies.append("direct RIP hijack — 需要GOT/PLT或one_gadget目标")
    elif scores['rip_control'] > 0.3:
        primitives.append(PrimitiveType.PARTIAL_RIP)

    if scores['stack_control'] > 0.7:
        primitives.append(PrimitiveType.STACK_PIVOT)
        strategies.append("stack pivot to controlled region — 需gadget: xchg rsp, rax")

    if scores['heap_control'] > 0.7:
        if 'use_after_free' in crash_type.lower():
            primitives.append(PrimitiveType.UAF)
            strategies.append("UAF exploitation — tcache poisoning或overlapping allocation")
        elif 'double' in crash_type.lower():
            primitives.append(PrimitiveType.DOUBLE_FREE)
            strategies.append("double-free — fastbin dup或tcache key bypass (glibc 2.32+)")
        else:
            primitives.append(PrimitiveType.HEAP_CORRUPTION)
            strategies.append("heap corruption — 需分析allocator状态以确定具体原语")

    if scores['info_leak'] > 0.4:
        primitives.append(PrimitiveType.INFO_LEAK)

    if not primitives:
        primitives.append(PrimitiveType.UNKNOWN)
        strategies.append("信息不足，建议进行确定性重放以收集更多crash上下文")

    return primitives, "; ".join(strategies) if strategies else "需进一步分析"


# ---- 主接口 ----

def fingerprint_crash(
    crash_data: Dict[str, Any],
    stack_bounds: Optional[Tuple[int, int]] = None,
    heap_bounds: Optional[List[Tuple[int, int]]] = None,
) -> CrashFingerprint:
    """对crash dump进行多维原语指纹识别。

    Args:
        crash_data: 来自 parse_crash() 的结构化crash数据
        stack_bounds: (stack_low, stack_high)
        heap_bounds: [(heap_start, heap_end), ...]

    Returns:
        包含多维评分和推荐策略的 CrashFingerprint
    """
    raw_text = crash_data.get('raw', '')
    crash_type = crash_data.get('crash_type', 'unknown')
    addresses = crash_data.get('addresses', [])

    fingerprint = CrashFingerprint(crash_type=crash_type)

    # 1. 寄存器分析——从crash数据中提取
    registers_raw = crash_data.get('registers', {})
    for reg_name, reg_val_str in registers_raw.items():
        try:
            reg_val = int(reg_val_str, 16) if isinstance(reg_val_str, str) else int(reg_val_str)
        except (ValueError, TypeError):
            continue
        fingerprint.registers[reg_name] = _analyze_register(
            reg_name, reg_val, stack_bounds, heap_bounds,
        )

    # 2. 堆操作序列提取
    fingerprint.heap_ops = _extract_heap_ops_from_text(raw_text)

    # 3. 故障指令和地址
    fingerprint.faulting_instruction = crash_data.get('fault_instruction', '')
    if addresses:
        fingerprint.faulting_address = int(addresses[0], 16) if addresses[0].startswith('0x') else 0

    # 4. 栈回溯
    fingerprint.stack_trace = crash_data.get('stack_trace', [])

    # 5. 多维评分
    fault_addr = fingerprint.faulting_address
    scores = _compute_exploitability_scores(
        fingerprint.registers, fingerprint.heap_ops, crash_type, fault_addr,
    )
    fingerprint.rip_control_score = scores['rip_control']
    fingerprint.stack_control_score = scores['stack_control']
    fingerprint.heap_control_score = scores['heap_control']
    fingerprint.info_leak_score = scores['info_leak']
    fingerprint.overall_exploitability = scores['overall']

    # 6. 推荐策略
    primitives, strategy = _recommend_strategy(scores, crash_type)
    fingerprint.recommended_primitives = primitives
    fingerprint.recommended_strategy = strategy

    return fingerprint
