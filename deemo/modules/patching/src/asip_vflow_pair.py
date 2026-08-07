"""
ASIP值流精确配对 — 替代80行窗口兜底的alloc-write关联判定.

根因: heap_dataflow.py的alloc_write_related在跨函数场景下
使用80行窗口兜底, 导致无关alloc+write被配对产生误报.
同函数内的malloc和memcpy即使操作不同缓冲区也被配对.

本模块实现must-alias分析判定alloc-write关联:
  1. alloc返回值→存储位置追踪(复用trace_alloc_store)
  2. write目标→来源追踪(复用trace_write_dst)
  3. 跨函数: 检查alloc存储槽与write dst是否must-alias
  4. 同函数内: 检查alloc的result_var是否在write的dst链中
  5. 无关: 必须拒绝, 不再使用行窗口兜底

设计决策: 宁可漏报也不误报. must-alias比may-alias更严格,
但对堆溢出检测, 误报的代价远高于漏报(误报数>>漏报数).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


def precise_alloc_write_related(
    asm_lines: List[str],
    alloc_line: int,
    write_line: int,
    func_bounds: Dict[int, str],
    alloc_slot: str,
    alloc_result_reg: str = '',
) -> Tuple[bool, str]:
    """精确判定alloc-write是否真正关联.

    返回 (is_related, reason):
      is_related=True: alloc和write操作同一缓冲区
      is_related=False: alloc和write无关, 不可配对

    替代原alloc_write_related的80行窗口兜底.
    """
    af = _line_function(alloc_line, func_bounds)
    wf = _line_function(write_line, func_bounds)

    # 同函数: 必须有数据流证据
    if af and wf and af == wf:
        return _same_func_related(
            asm_lines, alloc_line, write_line, alloc_slot, alloc_result_reg)

    # 跨函数: 必须有must-alias证据
    if alloc_slot:
        w_dst = _trace_write_dst(asm_lines, write_line)
        if w_dst and _must_alias(alloc_slot, w_dst):
            return True, f'cross-func must-alias: {alloc_slot}={w_dst}'

    return False, 'no must-alias evidence'


def _same_func_related(
    asm_lines: List[str],
    alloc_line: int,
    write_line: int,
    alloc_slot: str,
    alloc_result_reg: str,
) -> Tuple[bool, str]:
    """同函数内: 检查alloc result是否到达write dst."""
    if not alloc_slot:
        return False, 'same-func but no alloc slot'

    w_dst = _trace_write_dst(asm_lines, write_line)
    if not w_dst:
        return False, 'same-func but no write dst'

    if _must_alias(alloc_slot, w_dst):
        return True, f'same-func must-alias: {alloc_slot}={w_dst}'

    # 检查间接通过寄存器中转: mov r12, rax; ...; mov rdi, r12
    if alloc_result_reg:
        alloc_reg_dst = _trace_reg_to_slot(
            asm_lines, alloc_line, alloc_result_reg)
        if alloc_reg_dst and _must_alias(alloc_reg_dst, w_dst):
            return True, f'reg-mediated alias: {alloc_reg_dst}={w_dst}'

    return False, 'same-func but different buffers'


def _must_alias(slot_a: str, slot_b: str) -> bool:
    """判定两个存储标识是否must-alias.

    must-alias条件: 标识完全匹配, 或一个包含另一个.
    """
    if not slot_a or not slot_b:
        return False
    a = slot_a.lower().replace(' ', '')
    b = slot_b.lower().replace(' ', '')
    return a == b or a in b or b in a


def _trace_write_dst(
    asm_lines: List[str], write_line: int,
) -> str:
    """回溯write的dst参数来源(复用heap_dataflow逻辑)."""
    for j in range(write_line - 1, max(write_line - 8, -1), -1):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        for reg in ('rdi', 'rcx'):
            m = re.search(r'\bmov\s+' + reg + r',?\s*(\w+)', line)
            if m:
                src = m.group(1)
                # 若来源是寄存器, 继续追踪到栈槽
                slot = _reg_to_slot(asm_lines, j, src)
                return slot if slot else src
            m = re.search(
                r'\blea\s+' + reg + r',?\s*\[(rbp|rsp)\s*([+\-])\s*'
                r'(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return f'{m.group(1)}{m.group(2)}{m.group(3)}'
            m = re.search(
                r'\bmov\s+' + reg + r',?\s*(?:qword\s+ptr\s+)?'
                r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return f'{m.group(1)}{m.group(2)}{m.group(3)}'
    return ''


def _reg_to_slot(
    asm_lines: List[str], before_line: int, reg: str,
) -> str:
    """追踪寄存器值来源的栈槽."""
    if reg in ('rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'):
        return ''  # 这些是调用约定寄存器, 不是栈槽中转
    for j in range(before_line - 1, max(before_line - 12, -1), -1):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        m = re.search(
            r'\bmov\s+' + re.escape(reg) +
            r',?\s*(?:qword\s+ptr\s+)?\[(rbp|rsp)\s*([+\-])\s*'
            r'(0x[0-9a-f]+|\w+)\]', line)
        if m:
            return f'{m.group(1)}{m.group(2)}{m.group(3)}'
    return ''


def _trace_reg_to_slot(
    asm_lines: List[str], alloc_line: int, result_reg: str,
) -> str:
    """追踪alloc结果寄存器→栈槽存储."""
    for j in range(alloc_line + 1, min(alloc_line + 8, len(asm_lines))):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        m = re.search(
            r'\bmov\s+(?:qword\s+ptr\s+)?\[(rbp|rsp)\s*([+\-])\s*'
            r'(0x[0-9a-f]+|\w+)\],\s*' + re.escape(result_reg),
            line)
        if m:
            return f'{m.group(1)}{m.group(2)}{m.group(3)}'
    return ''


def _line_function(line_idx: int, func_bounds: Dict[int, str]) -> str:
    for i in range(line_idx, -1, -1):
        if i in func_bounds and func_bounds[i]:
            return func_bounds[i]
    return ''


__all__ = ['precise_alloc_write_related']
