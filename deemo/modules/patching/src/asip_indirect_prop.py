"""
ASIP间接约束传播器 — 需求驱动的栈槽→寄存器约束传播.

根因: heap_guard_collector仅处理cmp reg,N的直接模式,
编译器-O1以上常用栈变量中转:
  mov [rbp-8], target_reg   ; 先存到栈
  cmp [rbp-8], N            ; 再从栈比较
  ja guard_label
此时target_reg的约束被遗漏, 导致区间过宽无法证明安全.

本模块对guard收集器遗漏的间接约束执行一跳传播:
  1. 扫描mov [rbp-N], reg → 建立{slot: reg}映射
  2. 遇到cmp [rbp-N], imm → 从映射恢复reg → 注入约束

设计决策: 仅一跳, 不做传递闭包. 传递闭包在循环/间接调用
场景下可能发散. 一跳覆盖-O1/-O2最常见模式, 足以消除主要误报.

与heap_guard_collector的关系: 正交补充, 不修改原有收集器.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class IndirectGuard:
    """通过栈槽间接传播的guard约束."""
    reg: str
    slot: str
    bound: int
    jcc: str
    line: int


def build_slot_map(asm_lines: List[str], start: int, end: int) -> Dict[str, str]:
    """扫描mov [rbp-N], reg模式, 建立{栈槽: 寄存器}映射.

    仅匹配寄存器→栈槽方向(写入), 不匹配栈槽→寄存器(读取).
    """
    slot_map: Dict[str, str] = {}
    pat = re.compile(
        r'\bmov\s+(?:qword\s+ptr\s+)?\[(rbp|rsp)\s*([+\-])\s*'
        r'(0x[0-9a-f]+|\w+)\],\s*(\w+)',
        re.IGNORECASE,
    )
    for i in range(max(0, start), min(end, len(asm_lines))):
        m = pat.search(asm_lines[i].strip().lower().replace(',', ' '))
        if m:
            slot = f'{m.group(1)}{m.group(2)}{m.group(3)}'
            reg = m.group(4)
            if reg not in _NON_SIZE_REGS:
                slot_map[slot] = reg
    return slot_map


def resolve_indirect_guards(
    asm_lines: List[str],
    target_reg: str,
    start: int,
    end: int,
) -> List[IndirectGuard]:
    """需求驱动: 对target_reg查找被遗漏的间接约束.

    流程:
      1. build_slot_map: 找到写入target_reg的栈槽
      2. 扫描cmp [slot], imm: 若slot的来源是target_reg → 恢复约束
      3. 扫描cmp [slot], imm后跟的jcc → 构造IndirectGuard
    """
    slot_map = build_slot_map(asm_lines, start, end)

    # 反向映射: target_reg → 哪些slot保存了它的值
    reg_slots = [s for s, r in slot_map.items() if _reg_aliases(r, target_reg)]
    if not reg_slots:
        return []

    guards = []
    cmp_slot_pat = re.compile(
        r'\bcmp\s+(?:qword\s+ptr\s+)?\[(rbp|rsp)\s*([+\-])\s*'
        r'(0x[0-9a-f]+|\w+)\],?\s*(0x[0-9a-f]+|\d+)',
        re.IGNORECASE,
    )
    jcc_pat = re.compile(r'\b(j[a-z]+)\s+', re.IGNORECASE)

    for i in range(max(0, start), min(end, len(asm_lines))):
        m = cmp_slot_pat.search(
            asm_lines[i].strip().lower().replace(',', ' '))
        if not m:
            continue
        slot_key = f'{m.group(1)}{m.group(2)}{m.group(3)}'
        if slot_key not in reg_slots:
            continue

        bound = _parse_imm(m.group(4))
        if bound is None:
            continue

        jcc = _find_jcc(asm_lines, i)
        if jcc:
            guards.append(IndirectGuard(
                reg=target_reg, slot=slot_key,
                bound=bound, jcc=jcc, line=i,
            ))

    return guards


def _find_jcc(asm_lines: List[str], cmp_idx: int) -> Optional[str]:
    """cmp后5行内查找条件跳转."""
    pat = re.compile(r'\b(j[a-z]+)\s+', re.IGNORECASE)
    for j in range(cmp_idx + 1, min(cmp_idx + 5, len(asm_lines))):
        m = pat.search(asm_lines[j].strip().lower())
        if m:
            return m.group(1).lower()
        if re.search(r'\b(call|jmp|ret)\b', asm_lines[j].strip().lower()):
            break
    return None


def _parse_imm(s: str) -> Optional[int]:
    try:
        return int(s, 0) if s.lower().startswith('0x') else int(s)
    except (ValueError, TypeError):
        return None


_REG_ALIAS_MAP = {
    'al': 'rax', 'ah': 'rax', 'ax': 'rax', 'eax': 'rax',
    'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi',
    'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi',
    'dl': 'rdx', 'dh': 'rdx', 'dx': 'rdx', 'edx': 'rdx',
    'cl': 'rcx', 'ch': 'rcx', 'cx': 'rcx', 'ecx': 'rcx',
    'r8b': 'r8', 'r8w': 'r8', 'r8d': 'r8',
    'r9b': 'r9', 'r9w': 'r9', 'r9d': 'r9',
}

_NON_SIZE_REGS = frozenset({
    'rbp', 'rsp', 'rip', 'cs', 'ds', 'es', 'fs', 'gs', 'ss',
})


def _reg_aliases(r1: str, r2: str) -> bool:
    a1 = _REG_ALIAS_MAP.get(r1.lower(), r1.lower())
    a2 = _REG_ALIAS_MAP.get(r2.lower(), r2.lower())
    return a1 == a2


__all__ = [
    'IndirectGuard', 'build_slot_map',
    'resolve_indirect_guards',
]
