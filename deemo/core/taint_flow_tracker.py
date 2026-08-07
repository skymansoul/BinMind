# Lightweight value-flow tracking: back-traces register/variable origin
# along def-use chains without symbolic execution.
#
# Full symbolic execution (angr) times out on >100KB binaries due to path
# explosion. This module does conservative def-use analysis from disassembly
# text, tracing a register's value back to its nearest function call/param.
#
# Strategy:
#   1. Scan backward from target instruction (e.g., call printf) for the
#      target register's definition point
#   2. Immediate mov/lea -> stop (constant/string)
#   3. Register mov -> continue tracing source register
#   4. Memory load -> "from memory" (possibly global/heap variable)
#   5. Function return (rax after call) -> "from function call"
#
# Used by format_string_detector to determine if printf format args derive
# from user-controlled input (recv/read/fgets return values).
#
# erences:
# VSA: abstract domain value-set tracking
# BAP (CMU): full IR-level dataflow analysis; this module stays at asm level


from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class TaintSource:
    """Taint source descriptor: the ultimate origin of a value."""
    source_type: str   # "constant" / "memory" / "function_return" / "input_function"
    detail: str        # e.g., "from recv() return value" or "constant 0x400"
    confidence: float  # 0.0-1.0, trace reliability
    trace_depth: int   # back-trace steps


# Common user input functions whose return values carry external input
_INPUT_FUNCTIONS = {
    'read', 'recv', 'recvfrom', 'recvmsg', 'fread', 'fgets',
    'gets', 'scanf', 'getchar', 'getline', 'readline',
    'SSL_read', 'BIO_read',
}


def trace_register_source(
    disasm_lines: List[str],
    target_line_idx: int,
    target_register: str,
    max_depth: int = 20,
) -> TaintSource:
    """Back-trace a register's value origin from a target instruction.

    Args:
        disasm_lines: disassembly text lines (e.g., radare2 'pdf' output)
        target_line_idx: line index of the target instruction
        target_register: register name to trace (e.g., 'rdi', 'eax')
        max_depth: max back-trace steps

    Returns:
        TaintSource describing the value's ultimate origin.
    """
    depth = 0
    current_reg = target_register.lower()
    visited_regs: Set[str] = set()

    for idx in range(target_line_idx, max(-1, target_line_idx - 200), -1):
        if depth >= max_depth:
            return TaintSource("function_return", f"max depth {max_depth} exceeded",
                             0.2, depth)
        line = disasm_lines[idx].strip()
        if not line or line.startswith(';') or line.startswith("|"):
            continue

        depth += 1
        lower = line.lower()

        # Check if current line defines current_reg
        if not _defines_register(lower, current_reg):
            continue

        visited_regs.add(current_reg)

        # Case 1: mov reg, imm -> constant value
        imm = _extract_immediate(lower)
        if imm is not None:
            return TaintSource("constant", f"immediate {hex(imm)}", 0.95, depth)

        # Case 2: mov reg, reg2 -> continue tracing reg2
        src_reg = _extract_source_register(lower, current_reg)
        if src_reg and src_reg not in visited_regs:
            current_reg = src_reg
            continue

        # Case 3: lea reg, [mem] -> memory address (not user-controlled)
        if 'lea' in lower and current_reg in lower:
            return TaintSource("constant", "stack/global address", 0.7, depth)

        # Case 4: call xxx; mov result -> function return value
        if 'call' in lower:
            callee = _extract_call_target(line)
            if callee and callee in _INPUT_FUNCTIONS:
                return TaintSource("input_function",
                                  f"from {callee}() return value", 0.85, depth)
            return TaintSource("function_return",
                              f"from {callee or 'unknown'}() return value", 0.5, depth)

        # Case 5: load from memory
        if any(kw in lower for kw in ('mov', 'ldr')) and '[' in lower:
            return TaintSource("memory", "from memory load", 0.3, depth)

        # Case 6: xor reg,reg / sub reg,reg -> zeroing
        if any(kw in lower for kw in ('xor', 'sub')) and current_reg in lower:
            if lower.count(current_reg) >= 2 or '0x0' in lower:
                return TaintSource("constant", "zeroing op", 0.95, depth)

        break

    return TaintSource("function_return", "cannot trace origin", 0.1, depth)


def _defines_register(line_lower: str, reg: str) -> bool:
    """Check if the line defines the given register as a destination operand.

    For x86-64 assembly syntax: mov DST, SRC or lea DST, [SRC].
    """
    parts = line_lower.split(',')[0] if ',' in line_lower else line_lower
    tokens = parts.replace('[', ' ').replace(']', ' ').replace(':', ' ').split()
    if not tokens:
        return False
    return reg in parts.split()


def _extract_immediate(line_lower: str) -> Optional[int]:
    """Extract immediate value from instruction line, returns int or None."""
    import re
    m = re.search(r'(?:^|[,\s])(0x[0-9a-fA-F]+|\d+)\s*(?:$|[,\s\]])', line_lower)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    return None


def _extract_source_register(line_lower: str, dest_reg: str) -> Optional[str]:
    """Extract SRC register from 'mov DST, SRC' instruction."""
    parts = line_lower.split(',')
    if len(parts) < 2:
        return None
    src_part = parts[1].strip()
    tokens = src_part.replace('[', ' ').replace(']', ' ').split()
    for tok in tokens[:2]:
        if tok in {'rax', 'eax', 'ax', 'al', 'rbx', 'ebx', 'bx', 'bl',
                    'rcx', 'ecx', 'cx', 'cl', 'rdx', 'edx', 'dx', 'dl',
                    'rsi', 'esi', 'si', 'sil', 'rdi', 'edi', 'di', 'dil',
                    'r8', 'r8d', 'r9', 'r9d', 'r10', 'r11', 'r12', 'r13',
                    'r14', 'r15', 'rbp', 'rsp', 'xmm0', 'xmm1', 'ymm0'}:
            return tok
    return None


def _extract_call_target(line: str) -> Optional[str]:
    """Extract callee function name from a call instruction line."""
    import re
    m = re.search(r'call\s+(\S+)', line, re.IGNORECASE)
    if m:
        target = m.group(1)
        target = target.split('@')[0].split('+')[0]
        for prefix in ('sym.imp.', 'imp.', 'plt.'):
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target
    return None


def is_format_arg_user_controlled(
    disasm_lines: List[str],
    call_line_idx: int,
    format_arg_reg: str = 'rdi',
) -> Tuple[bool, TaintSource]:
    """Convenience entry point: check if a printf format argument is user-controlled.

    Args:
        disasm_lines: disassembly line list
        call_line_idx: line index of call printf
        format_arg_reg: format argument register (x86-64 calling convention: rdi)

    Returns:
        (is_user_controlled, taint_source)
    """
    source = trace_register_source(disasm_lines, call_line_idx,
                                    format_arg_reg, max_depth=30)
    controlled = source.source_type in ('input_function', 'memory')
    return controlled, source


def interprocedural_trace(
    disasm_lines: List[str],
    call_line_idx: int,
    target_register: str,
    callee_disasm: List[str] = None,
) -> TaintSource:
    """Cross-function taint tracing: when back-slicing hits a call, enter the
    callee's disassembly to analyze the return value's origin.

    x86-64 calling convention: rax = return value.
    """
    if callee_disasm is None:
        return TaintSource("function_return", "no callee disassembly available", 0.3, 1)

    for i, line in enumerate(callee_disasm):
        lower = line.strip().lower()
        for input_func in _INPUT_FUNCTIONS:
            if input_func in lower and 'call' in lower:
                return TaintSource("input_function",
                                  f"interproc: callee calls {input_func}() -> {target_register}",
                                  0.75, 2)
    return TaintSource("function_return", "callee has no user input call", 0.2, 2)


__all__ = [
    "TaintSource", "trace_register_source",
    "is_format_arg_user_controlled", "interprocedural_trace",
]
