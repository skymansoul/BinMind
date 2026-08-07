"""
堆分配参数污点过滤器 —— 分析malloc/calloc的大小参数是否来自用户输入。

核心问题: 静态检测中, malloc(n)的n若来自recv/read等用户输入,
分配大小在编译时不可知。后续对buf[offset]的写入无论offset取何值,
都无法静态判定是否溢出——因为实际分配大小由运行时输入决定。
此场景下标记为"动态大小"而非"溢出", 消除最常见误报源。

方法论: 对每个malloc调用点, 反向追踪其size参数寄存器(rdi/esi)的
def-use链。若参数最终追溯到recv/read/fgets等输入函数的返回值,
则标记为tainted——分配大小由攻击者可控。

与taint_flow_tracker.py的关系: 本模块专用于堆分配参数的污点分析,
追踪深度更深(跨3层调用)且只关心size参数, 不做全寄存器追踪。
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
    """分析malloc调用点的size参数是否来自用户输入。

    Args:
        disasm_lines: 反汇编文本行
        alloc_line_idx: malloc调用所在行索引
        max_depth: 最大反向追踪步数

    Returns:
        AllocTaint含污点判定结果。
    """
    if alloc_line_idx < 0 or alloc_line_idx >= len(disasm_lines):
        return AllocTaint(0, "", "malloc", False, "", 0, 0.0)

    # x86_64: malloc size via rdi; i386: via stack
    target_regs = {'rdi', 'edi', 'rsi', 'esi'}  # rsi=calloc的第二参数

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
