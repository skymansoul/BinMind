"""
堆分配参数污点过滤器 —— 反向追踪 malloc size 参数的 def-use 链,
若追溯到 recv/read 等输入源则判定分配大小为攻击者可控(动态大小)。
"""


import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


# 用户可控的输入源 —— 这些函数的返回值或输出参数直接来自外部
_INPUT_SOURCES = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread', 'fgets',
    'gets', 'scanf', '__isoc99_scanf', 'getline', 'readline',
    'SSL_read', 'BIO_read', 'getchar', 'fgetc',
}

# 间接输入源 —— 这些函数的参数可能来自输入
_INDIRECT_SOURCES = {
    'strtoul', 'strtol', 'atoi', 'atol', 'strtol_l',
    'memcpy', 'memmove', 'strncpy', 'strcpy',
}


@dataclass
class AllocTaint:
    """单次malloc调用的污点分析结果"""
    alloc_addr: int
    func_name: str
    alloc_func: str           # 'malloc'/'calloc'/'realloc'
    size_arg_tainted: bool    # size参数是否来自用户输入
    taint_source: str = ""    # 污点来源描述
    trace_depth: int = 0      # 追溯到输入源的步数
    confidence: float = 0.0   # 污点判定置信度


def analyze_alloc_taint(
    disasm_lines: List[str],
    alloc_line_idx: int,
    max_depth: int = 50,
) -> AllocTaint:
    """分析 malloc 调用点的 size 参数是否来自用户输入, 返回含污点判定的 AllocTaint。"""
    if alloc_line_idx < 0 or alloc_line_idx >= len(disasm_lines):
        return AllocTaint(0, "", "malloc", False, "", 0, 0.0)

    # x86_64: size 经 rdi 传入; i386 经栈传参
    target_regs = {'rdi', 'edi', 'rsi', 'esi'}  # rsi = calloc 的第二参数

    for depth in range(1, max_depth + 1):
        idx = alloc_line_idx - depth
        if idx < 0:
            break
        line = disasm_lines[idx].strip()
        if not line or line.startswith(';'):
            continue
        lower = line.lower()

        for reg in target_regs:
            if not _is_def(line, reg):
                continue

            imm = _extract_imm(lower)
            if imm is not None and imm > 0:
                return AllocTaint(0, "", "malloc", False,
                                 f"size={imm}(常量)", depth, 0.95)

            called = _extract_call_target(line)
            if called:
                if called in _INPUT_SOURCES:
                    return AllocTaint(0, "", "malloc", True,
                                     f"size来自{called}()返回值",
                                     depth, 0.85)
                if called in _INDIRECT_SOURCES:
                    return AllocTaint(0, "", "malloc", True,
                                     f"size间接来自{called}()",
                                     depth, 0.55)

            # size来自内存加载 → 可能用户可控
            if _has_memory_load(lower):
                return AllocTaint(0, "", "malloc", True,
                                 "size来自内存加载(可能用户可控)",
                                 depth, 0.40)

            src_reg = _extract_src_reg(lower, reg)
            if src_reg and src_reg not in target_regs:
                target_regs = {src_reg}  # 切换追踪目标
                break

    return AllocTaint(0, "", "malloc", False, "未追溯到明确输入源", max_depth, 0.1)


def _is_def(line: str, reg: str) -> bool:
    """检查该行是否定义了指定寄存器。"""
    parts = line.split(',')[0] if ',' in line else line
    tokens = parts.replace('[',' ').replace(']',' ').split()
    return reg in tokens and not line.strip().startswith(';')


def _extract_imm(line_lower: str) -> Optional[int]:
    m = re.search(r'(?:^|[,\s])(0x[0-9a-fA-F]+|\d+)\s*(?:$|[,\s\]])', line_lower)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    return None


def _extract_call_target(line: str) -> Optional[str]:
    m = re.search(r'call\s+(\S+)', line, re.IGNORECASE)
    if not m:
        return None
    target = m.group(1).split('@')[0].split('+')[0]
    for prefix in ('sym.imp.', 'imp.', 'plt.', '<'):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.rstrip('>')


def _has_memory_load(line_lower: str) -> bool:
    return '[' in line_lower and any(kw in line_lower for kw in ('mov', 'ldr'))


def _extract_src_reg(line_lower: str, dest_reg: str) -> Optional[str]:
    parts = line_lower.split(',')
    if len(parts) < 2:
        return None
    src = parts[1].strip().split()[0].replace('[','').replace(']','')
    if src in {'rax','eax','rbx','ebx','rcx','ecx','rdx','edx',
               'rsi','esi','rdi','edi','r8','r9','r10','r12','r13','r14','r15'}:
        return src
    return None


__all__ = ["AllocTaint", "analyze_alloc_taint"]
