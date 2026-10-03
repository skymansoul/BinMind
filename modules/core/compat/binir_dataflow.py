# -*- coding: utf-8 -*-
"""逐函数寄存器/栈槽级数据流 — 构建 ir_ops 与 def-use 链."""

import re
from typing import Any, Dict, List, Optional

from modules.core.compat.binir_common import (
    ARG_REGS_SYSV, CALLER_SAVED, ALLOC_FUNCS, WRITE_FUNCS, FREE_FUNCS,
    is_imm, imm_of_tail, norm_name, regs_in, slot_in, split_operands,
    _MEM_TOKEN)
from modules.core.compat.binir_disasm import BinIR

class RegFlow:
    """单函数数据流 — 追踪寄存器(族)与栈槽的最近定义."""
    def __init__(self):
        self.reg_def: Dict[str, int] = {}
        self.slot_def: Dict[str, int] = {}
        self.def_use: Dict[int, List[int]] = {}
        self.reg_callee: Dict[str, str] = {}   # reg → 装载的函数符号
        self.slot_callee: Dict[str, str] = {}  # slot → 存储的函数符号

    def add_edge(self, use_addr: int, def_addr: Optional[int]):
        if def_addr is not None and def_addr != use_addr:
            self.def_use.setdefault(use_addr, []).append(def_addr)

    def resolve_reg(self, reg: str, addr: int) -> Optional[int]:
        return self.reg_def.get(reg)

    def resolve_slot(self, slot: str, addr: int) -> Optional[int]:
        return self.slot_def.get(slot)

    def kill_caller_saved(self):
        for r in CALLER_SAVED:
            self.reg_def.pop(r, None)
            self.reg_callee.pop(r, None)


def build_ir(funcs: List[Dict], import_map: Optional[Dict[int, str]] = None
             ) -> BinIR:
    """从反汇编函数构建 BinIR (含逐函数数据流)."""
    ir = BinIR(sample_id='')
    import_map = import_map or {}
    if funcs:
        ir.arg_regs = funcs[0].get('arg_regs', ARG_REGS_SYSV)
    for func in funcs:
        flow = RegFlow()
        insns = func['insns']
        arg_regs = func.get('arg_regs', ARG_REGS_SYSV)
        for insn in insns:
            addr = insn['addr']
            mn = insn['mnemonic']
            op_str = insn['op_str']
            ir.instructions.append(insn)
            ir.func_of[addr] = func['name']
            op: Dict[str, Any] = {'op_type': mn, 'mnemonic': mn}
            ops = split_operands(op_str)
            dest_op = ops[0] if ops else ''
            src_ops = ops[1:] if len(ops) > 1 else []
            dest_reg = regs_in(dest_op) if not _MEM_TOKEN.search(dest_op) else []
            dest_slot = slot_in(dest_op)
            src_slot = slot_in(op_str)
            if dest_slot is not None:
                src_regs = []
                for so in src_ops:
                    src_regs.extend(regs_in(so))
            else:
                src_regs = regs_in(op_str)
                if dest_reg and not mn.startswith('cmov'):
                    src_regs = [r for r in src_regs if r != dest_reg[0]]

            if mn.startswith('call'):
                callee = _resolve_callee(insn, flow, import_map, op_str)
                op['callee'] = callee
                ir.callee_names[addr] = callee
                for j, arg_reg in enumerate(arg_regs):
                    d = flow.resolve_reg(arg_reg, addr)
                    if d is not None:
                        flow.add_edge(addr, d)
                        op[f'arg{j}_def'] = d
                if callee in ALLOC_FUNCS:
                    ir.trace_events.append({'event': 'alloc', 'address': addr,
                                            'ptr_id': f'{func["name"]}@{addr:x}'})
                elif callee in WRITE_FUNCS or callee in FREE_FUNCS:
                    ir.trace_events.append({'event': 'write', 'address': addr,
                                            'ptr_id': f'{func["name"]}@{addr:x}'})
                flow.kill_caller_saved()
            elif mn in ('ret', 'jmp'):
                flow.kill_caller_saved()
            elif mn in ('cmp', 'test'):
                src_regs_all = regs_in(op_str)
                op['src'] = src_regs_all[0] if src_regs_all else ''
                op['src2'] = src_regs_all[1] if len(src_regs_all) > 1 else (
                    imm_of_tail(src_ops))
                for s in src_regs_all:
                    flow.add_edge(addr, flow.resolve_reg(s, addr))
            else:
                _build_alu(op, insn, flow, import_map,
                           dest_slot, dest_reg, src_slot, src_regs, src_ops)
            ir.ir_ops[addr] = op
        for addr, lst in flow.def_use.items():
            ir.def_use[addr] = list(dict.fromkeys(lst))
    return ir


def _resolve_callee(insn: Dict, flow: RegFlow, import_map: Dict[int, str],
                    op_str: str) -> str:
    """调用目标解析: <符号> 注释 → 间接 call reg → stripped 导入桩."""
    cm = re.search(r'<([^>]+)>', insn.get('comment', ''))
    if cm:
        return norm_name(cm.group(1))
    ireg = regs_in(op_str)
    if ireg and flow.reg_callee.get(ireg[0]):
        return flow.reg_callee[ireg[0]]
    tm = re.search(r'(0x[0-9a-fA-F]+)$', insn.get('comment', ''))
    if tm:
        return import_map.get(int(tm.group(1), 16), '')
    return ''


def _build_alu(op, insn, flow, import_map, dest_slot, dest_reg,
               src_slot, src_regs, src_ops):
    """非控制流指令: store/load/算术, 更新 def-use 与 callee 传播."""
    addr = insn['addr']
    mn = insn['mnemonic']
    if dest_slot is not None:
        for s in src_regs:
            flow.add_edge(addr, flow.resolve_reg(s, addr))
        if src_regs and flow.reg_callee.get(src_regs[0]):
            flow.slot_callee[dest_slot] = flow.reg_callee[src_regs[0]]
        flow.slot_def[dest_slot] = addr
        op['dest'] = dest_slot
        op['src'] = src_regs[0] if src_regs else ''
        op['is_store'] = True
        return
    if dest_reg:
        dreg = dest_reg[0]
        sym = re.search(r'<([^>]+)>', insn.get('comment', ''))
        if sym and mn in ('lea', 'mov'):
            flow.reg_callee[dreg] = norm_name(sym.group(1))
        elif mn in ('lea', 'mov') and import_map:
            tm = re.search(r'#\s*(0x[0-9a-fA-F]+)', insn.get('comment', ''))
            if tm and int(tm.group(1), 16) in import_map:
                flow.reg_callee[dreg] = import_map[int(tm.group(1), 16)]
        op['dest'] = dreg
        if src_slot is not None:
            flow.add_edge(addr, flow.resolve_slot(src_slot, addr))
            if flow.slot_callee.get(src_slot):
                flow.reg_callee[dreg] = flow.slot_callee[src_slot]
            op['src'] = src_slot
        elif src_regs:
            for s in src_regs:
                flow.add_edge(addr, flow.resolve_reg(s, addr))
            op['src'] = src_regs[0]
            op['src2'] = src_regs[1] if len(src_regs) > 1 else ''
        imm = None
        for so in src_ops:
            imm = is_imm(so)
            if imm is not None:
                break
        if imm is not None:
            op['imm'] = imm
            if not src_regs and not src_slot:
                op['src'] = hex(imm)
        flow.reg_def[dreg] = addr


# alloc→write 候选提取 — 值链大小解析 + dest 别名配对.

import re
from typing import Dict, List, Optional, Tuple
