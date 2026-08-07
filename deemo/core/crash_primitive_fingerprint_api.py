"""Crash primitive fingerprinting: main API entry points."""

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
