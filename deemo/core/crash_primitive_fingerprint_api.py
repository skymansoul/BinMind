"""崩溃原语指纹: 主 API 入口。"""

from typing import Any, Dict, List, Optional, Tuple

from .crash_primitive_fingerprint_types import CrashFingerprint
from .crash_primitive_fingerprint_analyzers import (
    _analyze_register,
    _compute_exploitability_scores,
    _extract_heap_ops_from_text,
    _recommend_strategy,
)


def fingerprint_crash(
    crash_data: Dict[str, Any],
    stack_bounds: Optional[Tuple[int, int]] = None,
    heap_bounds: Optional[List[Tuple[int, int]]] = None,
) -> CrashFingerprint:
    """多轴崩溃原语指纹。

    crash_data 为 parse_crash() 输出的结构化崩溃数据;
    stack_bounds/heap_bounds 可选, 供寄存器可控性判定使用。
    返回含各轴评分与推荐策略的 CrashFingerprint。
    """
    raw_text = crash_data.get('raw', '')
    crash_type = crash_data.get('crash_type', 'unknown')
    addresses = crash_data.get('addresses', [])

    fingerprint = CrashFingerprint(crash_type=crash_type)

    # 1. 崩溃数据寄存器分析
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

    # 3. 崩溃指令与地址
    fingerprint.faulting_instruction = crash_data.get('fault_instruction', '')
    if addresses:
        fingerprint.faulting_address = int(addresses[0], 16) if addresses[0].startswith('0x') else 0

    # 4. 栈回溯
    fingerprint.stack_trace = crash_data.get('stack_trace', [])

    # 5. 多轴评分
    fault_addr = fingerprint.faulting_address
    scores = _compute_exploitability_scores(
        fingerprint.registers, fingerprint.heap_ops, crash_type, fault_addr,
    )
    fingerprint.rip_control_score = scores['rip_control']
    fingerprint.stack_control_score = scores['stack_control']
    fingerprint.heap_control_score = scores['heap_control']
    fingerprint.info_leak_score = scores['info_leak']
    fingerprint.overall_exploitability = scores['overall']

    # 6. 策略推荐
    primitives, strategy = _recommend_strategy(scores, crash_type)
    fingerprint.recommended_primitives = primitives
    fingerprint.recommended_strategy = strategy

    # 7. 堆破坏类崩溃的堆布局推断
    if crash_type in ('heap_corruption', 'uaf', 'double_free'):
        heap_ctx = infer_heap_layout(registers_raw, crash_type)
        fingerprint.metadata['heap_context'] = heap_ctx

    return fingerprint


def infer_heap_layout(regs: Dict[str, str],
                       crash_type: str) -> Dict[str, Any]:
    """从崩溃寄存器状态推断堆块布局。

    判定崩溃地址是否落在已知堆区域、被破坏字节是否覆盖堆元数据 (fd/bk 指针), 并估计块大小。
    """
    ctx: Dict[str, Any] = {}
    rip = regs.get('rip', '')
    rsp = regs.get('rsp', '')
    rax = regs.get('rax', '')

    # 从崩溃地址偏移推断块大小: 地址 0x?8 对齐且后续 8 字节匹配某模式时, fd/bk 指针可能已被覆盖。
    for reg_name, val in regs.items():
        if not val or len(val) < 4:
            continue
        try:
            addr = int(val, 16)
        except ValueError:
            continue
        # glibc chunk 头: prev_size(8B) + size(8B, LSB=flags)
        # addr % 16 == 8 表示写入的是 chunk 的 fd 指针
        if addr % 16 == 8 and crash_type == 'heap_corruption':
            ctx['likely_overwritten'] = 'fd_pointer'
            ctx['estimated_chunk_offset'] = 16  # skip prev_size + size header
        elif addr % 16 == 0 and crash_type == 'heap_corruption':
            ctx['likely_overwritten'] = 'prev_size_or_size_field'

    # 推断空闲链表状态: 崩溃发生在 free() 内时, chunk 可能已入 bin
    if crash_type in ('uaf', 'double_free'):
        ctx['in_free_list'] = True
        ctx['note'] = 'crash during free, chunk may already be in free-list'

    return ctx
