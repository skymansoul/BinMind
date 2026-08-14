# 轻量值流追踪: 沿def-use链回溯寄存器/变量来源, 不依赖符号执行。
# 大型二进制上angr符号执行因路径爆炸超时, 本模块在反汇编文本上做保守
# def-use分析。供format_string_detector判断printf格式参数是否来自用户输入。


from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class TaintSource:
    """污点源描述: 值的最终来源。"""
    source_type: str   # "constant" / "memory" / "function_return" / "input_function"
    detail: str        # e.g., "from recv() return value" or "constant 0x400"
    confidence: float  # 0.0-1.0, trace reliability
    trace_depth: int   # back-trace steps


# 返回值携带外部输入的常见用户输入函数
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
    """从目标指令回溯寄存器的值来源。

    参数: disasm_lines 反汇编文本行 (如 radare2 'pdf' 输出),
    target_line_idx 目标指令行号, target_register 待追踪寄存器名 (如 'rdi'),
    max_depth 最大回溯步数。
    返回描述值最终来源的 TaintSource。
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

        # 检查当前行是否定义了 current_reg
        if not _defines_register(lower, current_reg):
            continue

        visited_regs.add(current_reg)

        # 情形1: mov reg, imm → 常量值
        imm = _extract_immediate(lower)
        if imm is not None:
            return TaintSource("constant", f"immediate {hex(imm)}", 0.95, depth)

        # 情形2: mov reg, reg2 → 继续追踪 reg2
        src_reg = _extract_source_register(lower, current_reg)
        if src_reg and src_reg not in visited_regs:
            current_reg = src_reg
            continue

        # 情形3: lea reg, [mem] → 内存地址 (非用户控制)
        if 'lea' in lower and current_reg in lower:
            return TaintSource("constant", "stack/global address", 0.7, depth)

        # 情形4: call 后取返回值 → 函数返回值
        if 'call' in lower:
            callee = _extract_call_target(line)
            if callee and callee in _INPUT_FUNCTIONS:
                return TaintSource("input_function",
                                  f"from {callee}() return value", 0.85, depth)
            return TaintSource("function_return",
                              f"from {callee or 'unknown'}() return value", 0.5, depth)

        # 情形5: 从内存加载
        if any(kw in lower for kw in ('mov', 'ldr')) and '[' in lower:
            return TaintSource("memory", "from memory load", 0.3, depth)

        # 情形6: xor/sub 清零操作
        if any(kw in lower for kw in ('xor', 'sub')) and current_reg in lower:
            if lower.count(current_reg) >= 2 or '0x0' in lower:
                return TaintSource("constant", "zeroing op", 0.95, depth)

        break

    return TaintSource("function_return", "cannot trace origin", 0.1, depth)


def _defines_register(line_lower: str, reg: str) -> bool:
    """检查行是否将给定寄存器作为目标操作数定义。

    x86-64 汇编语法: mov DST, SRC 或 lea DST, [SRC]。
    """
    parts = line_lower.split(',')[0] if ',' in line_lower else line_lower
    tokens = parts.replace('[', ' ').replace(']', ' ').replace(':', ' ').split()
    if not tokens:
        return False
    return reg in parts.split()


def _extract_immediate(line_lower: str) -> Optional[int]:
    """从指令行提取立即数, 返回 int 或 None。"""
    import re
    m = re.search(r'(?:^|[,\s])(0x[0-9a-fA-F]+|\d+)\s*(?:$|[,\s\]])', line_lower)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    return None


def _extract_source_register(line_lower: str, dest_reg: str) -> Optional[str]:
    """从 'mov DST, SRC' 指令提取源寄存器。"""
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
    """从 call 指令行提取被调函数名。"""
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
    """便捷入口: 检查 printf 格式参数是否受用户控制。

    参数: disasm_lines 反汇编行列表, call_line_idx call printf 行号,
    format_arg_reg 格式参数寄存器 (x86-64 调用约定: rdi)。
    返回 (is_user_controlled, taint_source)。
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
    """跨函数污点追踪: 回溯切片遇到 call 时, 进入被调函数反汇编,
    分析返回值的来源。x86-64 调用约定: rax 为返回值。
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
