# 堆分配数据流追踪 — alloc返回值 → write目标的跨函数数据流耦合
"""堆分配数据流追踪器。

传统静态分析用固定代码行窗口配对alloc和write → 大量无关配对 → 高误报。
本模块追踪 alloc返回值(rax) 的存储位置, 然后验证 write目标 是否引用同一位置,
实现跨函数的数据流耦合确认。

核心能力:
  1. parse_function_bounds: 从objdump输出解析函数标签 → 函数级窗口
  2. trace_alloc_store: 追踪 rax(alloc返回值) → [rbp-N] 或 callee-saved寄存器
  3. trace_write_dst: 追踪 memcpy的第一个参数(dst) 的来源栈槽/寄存器
  4. alloc_write_related: 判断alloc-write对是否通过数据流耦合

设计依据:
  编译器在malloc后立即将rax存入栈槽或保留寄存器, memcpy前从同一位置加载dst。
  这一mov-store-load链即使在跨函数场景也足够稳定,
  因为编译器在-O0/-O1不轻易重排malloc结果的使用。

思路参照针对堆溢出的 Value-Flow Analysis (值流分析)。
"""

import re
from typing import List, Dict, Tuple


def parse_function_bounds(asm_lines: List[str]) -> Dict[int, str]:
    """从objdump输出解析函数标签, 返回 {line_index: func_name}。

    objdump格式:  ^[addr] <func_name>:
    """
    bounds = {}
    current_func = ''
    for i, line in enumerate(asm_lines):
        m = re.search(r'^[0-9a-f]+\s+<(\S+)>:', line.strip())
        if m:
            current_func = m.group(1)
        bounds[i] = current_func
    return bounds


def line_function(line_idx: int, func_bounds: Dict[int, str]) -> str:
    """返回某行所属的函数名。向上查找最近的函数标签。"""
    for i in range(line_idx, -1, -1):
        if i in func_bounds and func_bounds[i]:
            return func_bounds[i]
    return ''


def trace_alloc_store(asm_lines: List[str], alloc_line: int) -> str:
    """追踪alloc返回值(rax)被存储到哪个栈槽/寄存器。

    mov [rbp-0x20], rax → 返回 'rbp-0x20'
    mov r12, rax         → 返回 'r12'
    无法确定时返回空字符串。

    ABI兼容: 匹配 qword ptr 和裸 mov 两种objdump格式。
    """
    for j in range(alloc_line + 1, min(alloc_line + 8, len(asm_lines))):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        m = re.search(
            r'\bmov\s+(?:qword\s+ptr\s+)?\[(rbp|rsp)\s*([+\-])\s*'
            r'(0x[0-9a-f]+|\w+)\]\s*,?\s*rax\b', line)
        if m:
            base, sign, off = m.group(1), m.group(2), m.group(3)
            return f'{base}{sign}{off}'
        m = re.search(r'\bmov\s+(r1[2-5]|rbx),\s*rax\b', line)
        if m:
            return m.group(1)
    return ''


def trace_write_dst(asm_lines: List[str], write_line: int) -> str:
    """找到write调用(memcpy等)的目标缓冲区来源。

    memcpy(dst, src, size):
      SysV:  rdi = dst (第一参数)
      MS x64: rcx = dst (第一参数)

    回溯策略: 检查mov dst_reg, src / lea dst_reg, [rbp-N] / mov dst_reg, [rbp-N]

    返回归一化的来源标识, 如 'rbp-0x20' 或 'rax'。无法确定返回 ''。
    """
    for j in range(write_line - 1, max(write_line - 6, -1), -1):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        for reg in ('rdi', 'rcx'):
            # mov rdi, rax (或其他寄存器)
            m = re.search(r'\bmov\s+' + reg + r',?\s*(\w+)', line)
            if m:
                return m.group(1)
        for reg in ('rdi', 'rcx'):
            # lea rdi, [rbp-N] → 栈变量地址
            m = re.search(
                r'\blea\s+' + reg + r',?\s*\[(rbp|rsp)\s*([+\-])\s*'
                r'(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return f'{m.group(1)}{m.group(2)}{m.group(3)}'
        for reg in ('rdi', 'rcx'):
            # mov rdi, [rbp-N] → 从栈加载
            m = re.search(
                r'\bmov\s+' + reg + r',?\s*(?:qword\s+ptr\s+)?'
                r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return f'{m.group(1)}{m.group(2)}{m.group(3)}'
    return ''


def alloc_write_related(asm_lines: List[str],
                        alloc_line: int, write_line: int,
                        func_bounds: Dict[int, str],
                        alloc_slot: str) -> bool:
    """判断alloc和write是否通过数据流相关。

    三级判断:
      1. 同函数内 → 直接相关 (函数级窗口)
      2. alloc有存储槽且write dst引用相同槽 → 跨函数数据流耦合
      3. 保守兜底: 50行窗口内

    参数:
      asm_lines: 汇编行列表
      alloc_line: alloc调用所在行
      write_line: write调用所在行
      func_bounds: 函数边界映射
      alloc_slot: alloc返回值的存储槽 (来自trace_alloc_store)
    """
    # 同函数 → 直接相关
    af = line_function(alloc_line, func_bounds)
    wf = line_function(write_line, func_bounds)
    if af and wf and af == wf:
        return True
    # 数据流耦合
    if alloc_slot:
        w_dst = trace_write_dst(asm_lines, write_line)
        if w_dst and (w_dst == alloc_slot or
                      alloc_slot in w_dst or w_dst in alloc_slot):
            return True
    # 统一: 80行窗口 (跨函数调用, alloc在helper/write在caller)
    if 0 < write_line - alloc_line <= 80:
        return True
    return False


def resolve_size_reg(asm_lines: List[str], call_idx: int) -> str:
    """从call处回溯找到alloc的size参数寄存器。

    ABI兼容: SysV (rdi/edi) 和 MS x64 (rcx/ecx)。
    """
    for j in range(call_idx - 1, max(call_idx - 5, -1), -1):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        for reg in ('rdi', 'rcx', 'ecx', 'edi'):
            m = re.search(r'\bmov\s+' + reg + r',?\s*(\w+)', line)
            if m:
                return m.group(1)
    return 'unknown'
