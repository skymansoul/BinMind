# -*- coding: utf-8 -*-
"""二进制级 UAF 生命周期检测 — 基于 binir 前端的事件与指针谱系.

误报根源: 静态分析把"释放后对同变量的复用"当作正常重新初始化, 或把
"存储指针值"误判为解引用. 本模块在释放点解析被释放指针的谱系 (经
寄存器/栈槽的 def-site 链), 释放后在同函数内前向扫描:

  - 经 freed 槽装载 → 寄存器进入 freed 别名集 (指针重入寄存器)
  - 内存操作数基址 ∈ freed 别名集 → 解引用 → UAF 候选
  - 调用参数 ∈ freed 别名集 → 传参使用 → UAF 候选
  - 同谱系再次 free → double-free
  - realloc 旧指针参数在调用后被使用 → realloc-UAF
  - 槽被重新 store (指针重新初始化) → 停止追踪该谱系

判定保守: 仅把"通过该指针访存"或"传入调用"视为使用; 单纯的指针值搬移
(寄存器间 mov / 存槽) 不算使用, 消除 CRT 启动噪音.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.core.compat.binir_common import (
    _MEM_TOKEN, is_imm, regs_in, slot_in, split_operands)
from modules.core.compat.binir_disasm import BinIR

_FREE_FUNCS = {'free', '_zdl', '_zda', 'kfree'}
_REALLOC_FUNCS = {'realloc'}

_MEM_BASE = re.compile(r'\[([a-z]+[0-9a-z]*)(?:\s*[+\-])', re.I)


@dataclass
class UafFinding:
    """单个 UAF 候选."""
    kind: str                # 'use_after_free' | 'double_free' | 'realloc_use'
    free_site: int           # free/realloc 调用地址
    use_site: int            # 违规使用地址
    func: str
    detail: str = ''


def analyze_uaf_binary(ir: BinIR) -> List[UafFinding]:
    """对单个二进制的 IR 执行 UAF 生命周期检测."""
    findings: List[UafFinding] = []
    func_insns: Dict[str, List[Dict]] = {}
    for insn in ir.instructions:
        fname = ir.func_of.get(insn['addr'], '')
        if fname:
            func_insns.setdefault(fname, []).append(insn)

    for fname, insns in func_insns.items():
        for site in insns:
            if site['mnemonic'] != 'call':
                continue
            callee = ir.callee_names.get(site['addr'], '')
            if callee in _FREE_FUNCS:
                findings.extend(_scan_free(fname, insns, ir, site['addr'],
                                           'use_after_free', 'double_free'))
            elif callee in _REALLOC_FUNCS:
                findings.extend(_scan_free(fname, insns, ir, site['addr'],
                                           'realloc_use', 'realloc_use'))
    return findings


def _slot_of(insn: Dict) -> str:
    """指令的内存槽标识: rip 相对全局归一化为绝对目标地址 (g@target)."""
    op_str = insn.get('op_str', '')
    s = slot_in(op_str)
    if s is None:
        return ''
    if s.startswith('rip'):
        m = re.search(r'#\s*([0-9a-fA-F]+)\b', insn.get('comment', ''))
        if m:
            return f'g@{int(m.group(1), 16):x}'
    return s


def _scan_free(fname: str, insns: List[Dict], ir: BinIR,
               free_addr: int, use_kind: str,
               dbl_kind: str) -> List[UafFinding]:
    """在 free/realloc 调用点后扫描 UAF 候选."""
    lineage = _pointer_lineage(insns, ir.arg_regs[0], free_addr)
    if not lineage:
        return []

    freed_slots: Set[str] = {s for s, _ in lineage}
    # 别名槽: 释放前把该指针值拷入的其他槽 (如 old = buf), 同属失效谱系
    for s in {slot for slot, _ in lineage}:
        freed_slots |= _alias_slots(insns, s, free_addr)
    freed_regs: Set[str] = set()
    findings: List[UafFinding] = []

    for insn in insns:
        addr = insn['addr']
        if addr <= free_addr:
            continue
        if ir.func_of.get(addr) != fname:
            break
        mn = insn['mnemonic']
        op_str = insn['op_str']
        ops = split_operands(op_str)
        if not ops:
            continue

        dest_slot = _slot_of(insn) if _MEM_TOKEN.search(ops[0]) else ''
        src_slot = _slot_of(insn)
        mem_base = _mem_base(op_str)
        dst_regs = regs_in(ops[0]) if ops and '[' not in ops[0] else []
        src_regs = [r for r in regs_in(op_str)
                    if r not in dst_regs and r != mem_base]

        # 指针重新初始化: 对谱系槽的 store → 停止追踪
        if dest_slot in freed_slots:
            freed_slots.discard(dest_slot)
            if not freed_slots and not freed_regs:
                break
            continue

        # 寄存器定义: 来自 freed 谱系 → 进入别名; 来自非 freed 源 → 别名失效
        if dst_regs:
            d = dst_regs[0]
            if src_slot in freed_slots:
                freed_regs.add(d)
                continue
            if src_regs and src_regs[0] in freed_regs:
                freed_regs.add(d)
                continue
            freed_regs.discard(d)
            if mn.startswith('mov'):
                continue

        # 存储指令: 保存 freed 指针值 → 非使用; 经 freed 基址访存 → 使用
        if _MEM_TOKEN.search(ops[0]) if ops else False:
            if mem_base in freed_regs:
                findings.append(UafFinding(
                    use_kind, free_addr, addr, fname,
                    f'释放后经指针存储 @0x{addr:x} ({mn})'))
            continue

        # 调用: 实参寄存器命中 freed 别名 → 使用
        if mn == 'call':
            callee = ir.callee_names.get(addr, '')
            if callee in _FREE_FUNCS:
                if _pointer_lineage(insns, ir.arg_regs[0], addr) & lineage:
                    findings.append(UafFinding(
                        dbl_kind, free_addr, addr, fname,
                        f'同谱系二次释放 @0x{addr:x}'))
                    continue
            if mem_base in freed_regs or any(
                    a in freed_regs for a in ir.arg_regs):
                findings.append(UafFinding(
                    use_kind, free_addr, addr, fname,
                    f'释放后经指针传参 {callee or "调用"} @0x{addr:x}'))
            continue

        # 内存操作数基址 ∈ freed 别名 → 解引用使用
        if mem_base in freed_regs:
            findings.append(UafFinding(
                use_kind, free_addr, addr, fname,
                f'释放后解引用 @0x{addr:x} ({mn} {op_str[:36]})'))
            continue

        # 算术/比较消费 freed 指针值 → 使用
        if src_regs and any(r in freed_regs for r in src_regs):
            findings.append(UafFinding(
                use_kind, free_addr, addr, fname,
                f'释放后消费指针值 @0x{addr:x} ({mn})'))
    return findings


def _pointer_lineage(insns: List[Dict], reg: str,
                     boundary: int) -> Set[Tuple[str, str]]:
    """解析 boundary 之前 reg 的指针谱系: {(槽名, 'slot')}."""
    target = reg
    limit = boundary
    for _ in range(8):
        found = None
        for insn in insns:
            if insn['addr'] >= limit:
                break
            ops = split_operands(insn['op_str'])
            if not ops:
                continue
            dst = regs_in(ops[0]) if not _MEM_TOKEN.search(ops[0]) else []
            if target in dst:
                found = insn
        if found is None:
            return set()
        mn = found['mnemonic']
        ops = split_operands(found['op_str'])
        if not mn.startswith('mov') or len(ops) < 2:
            return set()
        src_op = ops[-1]
        if is_imm(src_op) is not None:
            return set()
        src_slot = _slot_of(found)
        src_reg = regs_in(src_op)
        if src_slot:
            return {(src_slot, 'slot')}
        if src_reg:
            target = src_reg[0]
            limit = found['addr']
            continue
        return set()
    return set()


def _alias_slots(insns: List[Dict], slot: str,
                 boundary: int) -> Set[str]:
    """boundary 之前把 slot 指针值拷贝到的其他栈槽."""
    aliases: Set[str] = set()
    for insn in insns:
        if insn['addr'] >= boundary:
            break
        ops = split_operands(insn['op_str'])
        if not ops or len(ops) < 2:
            continue
        if not _MEM_TOKEN.search(ops[0]):
            continue
        dst = _slot_of(insn)
        if not dst or dst == slot:
            continue
        for r in regs_in(ops[1]):
            if _reg_loaded_from(insns, r, insn['addr'], slot):
                aliases.add(dst)
                break
    return aliases


def _reg_loaded_from(insns: List[Dict], reg: str, limit: int,
                     slot: str) -> bool:
    """limit 之前 reg 的值链是否由 slot 装载而来."""
    target = reg
    l = limit
    for _ in range(6):
        found = None
        for insn in insns:
            if insn['addr'] >= l:
                break
            ops = split_operands(insn['op_str'])
            if not ops:
                continue
            dst = regs_in(ops[0]) if not _MEM_TOKEN.search(ops[0]) else []
            if target in dst:
                found = insn
        if found is None:
            return False
        if _slot_of(found) == slot:
            return True
        ops = split_operands(found['op_str'])
        if len(ops) >= 2:
            src = regs_in(ops[-1])
            if src and src[0] != target:
                target = src[0]
                l = found['addr']
                continue
        return False
    return False


def _mem_base(op_str: str) -> str:
    """内存操作数的基址寄存器 (含裸 [reg] 与 [reg+off] 形式)."""
    m = _MEM_BASE.search(op_str)
    if m:
        return m.group(1).lower()
    m = re.search(r'\[([a-z]+[0-9a-z]*)(?:\s*\)|\s*$|\])', op_str)
    if m and m.group(1).lower() in _GPR_NAMES:
        return m.group(1).lower()
    return ''


_GPR_NAMES = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
}


def summarize(findings: List[UafFinding]) -> Dict[str, Any]:
    """汇总统计."""
    by_kind: Dict[str, int] = {}
    for f in findings:
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
    return {
        'total': len(findings),
        'by_kind': by_kind,
        'detail': [
            {'kind': f.kind, 'free': hex(f.free_site), 'use': hex(f.use_site),
             'func': f.func, 'detail': f.detail}
            for f in findings
        ],
    }
