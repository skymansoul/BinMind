# -*- coding: utf-8 -*-
"""alloc→write 候选提取 — 值链大小解析 + dest 别名配对."""

import re
from typing import Dict, List, Optional, Tuple

from modules.core.compat.binir_common import (
    ALLOC_SIGS, WRITE_SIGS, ALLOC_FUNCS, is_imm, norm_name, regs_in,
    slot_in, split_operands, _MEM_TOKEN)
from modules.core.compat.binir_disasm import BinIR

def extract_candidates(ir: BinIR) -> BinIR:
    """在同一函数内按 dest 别名配对 alloc -> write, 提取 size 变量."""
    func_insns: Dict[str, List[Dict]] = {}
    for insn in ir.instructions:
        fname = ir.func_of.get(insn['addr'], '')
        if fname:
            func_insns.setdefault(fname, []).append(insn)

    for fname, insns in func_insns.items():
        calls = [i for i in insns if i['mnemonic'] == 'call'
                 and i['addr'] in ir.callee_names]
        allocs = [c for c in calls
                  if ir.callee_names.get(c['addr'], '') in ALLOC_FUNCS]
        writes = [c for c in calls
                  if ir.callee_names.get(c['addr'], '') in WRITE_SIGS]

        write_alloc: Dict[int, Optional[int]] = {}
        for w in writes:
            dest_reg = ir.arg_regs[0]
            src_alloc = _ptr_source(insns, dest_reg, w['addr'])
            if src_alloc is not None:
                write_alloc[w['addr']] = src_alloc
            else:
                earlier = [a for a in allocs if a['addr'] < w['addr']]
                write_alloc[w['addr']] = earlier[-1]['addr'] if earlier else None

        for a in allocs:
            acallee = ir.callee_names.get(a['addr'], '')
            size_idx, _prod = ALLOC_SIGS.get(acallee, (0, False))
            size_reg = ir.arg_regs[size_idx]
            ainfo = _size_info(insns, size_reg, a['addr'])
            for w in writes:
                if w['addr'] <= a['addr']:
                    continue
                if write_alloc.get(w['addr']) != a['addr']:
                    continue
                wcallee = ir.callee_names.get(w['addr'], '')
                sig = WRITE_SIGS.get(wcallee)
                if sig is None:
                    # 无显式长度写入: 长度取决于源, 保守候选
                    winfo = (0, '', None)
                    wid = f'unknown@{w["addr"]:x}'
                    same_src = False
                else:
                    wsize_reg = ir.arg_regs[sig[0]]
                    winfo = _size_info(insns, wsize_reg, w['addr'])
                    wid = _size_id(winfo[1], winfo[2], w['addr'])
                    same_src = _same_source(
                        ainfo[1], ainfo[2], winfo[1], winfo[2], insns)
                aid = _size_id(ainfo[1], ainfo[2], a['addr'])
                ir.candidates.append({
                    'alloc_site': a['addr'], 'write_site': w['addr'],
                    'alloc_callee': acallee, 'write_callee': wcallee,
                    'alloc_size': ainfo[0], 'write_size': winfo[0],
                    'alloc_size_var': ainfo[1], 'write_size_var': winfo[1],
                    'alloc_def': ainfo[2], 'write_def': winfo[2],
                    'alloc_id': aid, 'write_id': wid,
                    'same_source': same_src,
                    'vuln_type': 'heap_overflow',
                    'func': fname,
                    'confidence': 0.5, 'exploitable': False,
                    'source_layer': 'L0_frontend',
                })
    return ir


def _size_info(insns: List[Dict], reg: str,
               call_addr: int) -> Tuple[int, str, Optional[int]]:
    """沿值链向后解析 call 前 reg 的大小: (常量, 变量名, 值定义地址)."""
    target = reg
    limit = call_addr
    const_val = 0
    var_name = reg
    value_def: Optional[int] = None

    while True:
        found: Optional[Dict] = None
        for insn in insns:
            if insn['addr'] >= limit:
                break
            ops = split_operands(insn['op_str'])
            if not ops:
                continue
            dst_regs = regs_in(ops[0]) if not _MEM_TOKEN.search(ops[0]) else []
            if target in dst_regs:
                found = insn
        if found is None:
            break
        value_def = found['addr']
        mn = found['mnemonic']
        ops = split_operands(found['op_str'])
        if not mn.startswith('mov') or len(ops) < 2:
            var_name = target
            break
        src_op = ops[-1]
        imm = is_imm(src_op)
        if imm is not None:
            const_val = imm
            var_name = target
            break
        src_slot = slot_in(src_op)
        src_reg = regs_in(src_op)
        if src_slot:
            var_name = src_slot
            store_imm = _slot_store_imm(insns, src_slot, found['addr'])
            if store_imm is not None:
                const_val = store_imm
            break
        if src_reg:
            target = src_reg[0]
            var_name = target
            limit = found['addr']
            continue
        var_name = target
        break
    return const_val, var_name, value_def


def _ptr_source(insns: List[Dict], reg: str, boundary: int) -> Optional[int]:
    """沿指针值链回溯, 若链终止于 alloc 调用则返回其地址."""
    target = reg
    limit = boundary
    for _ in range(8):
        found = _last_reg_def(insns, target, limit)
        if found is None:
            return None
        mn = found['mnemonic']
        ops = split_operands(found['op_str'])
        if mn.startswith('call'):
            cm = re.search(r'<([^>]+)>', found.get('comment', ''))
            if cm and norm_name(cm.group(1)) in ALLOC_FUNCS:
                return found['addr']
            return None
        if not mn.startswith('mov') or len(ops) < 2:
            return None
        src_op = ops[-1]
        if is_imm(src_op) is not None:
            return None
        src_slot = slot_in(src_op)
        if src_slot:
            store = _slot_last_store(insns, src_slot, found['addr'])
            if store is None:
                return None
            store_insn = next((i for i in insns if i['addr'] == store), None)
            if store_insn is None:
                return None
            sregs = regs_in(store_insn['op_str'])
            if not sregs:
                return None
            target = sregs[-1]
            limit = store
            continue
        src_regs = regs_in(src_op)
        if src_regs:
            target = src_regs[0]
            limit = found['addr']
            continue
        return None
    return None


def _same_source(a_var: str, a_def: Optional[int],
                 w_var: str, w_def: Optional[int],
                 insns: List[Dict]) -> bool:
    """判定 alloc/write 的大小值是否来自同一源 (同一槽的同一 store)."""
    if a_var == w_var and a_def == w_def and a_def is not None:
        return True
    if a_var != w_var or a_def is None or w_def is None:
        return False
    a_store = _slot_last_store(insns, a_var, a_def)
    w_store = _slot_last_store(insns, w_var, w_def)
    return a_store is not None and a_store == w_store


def _slot_last_store(insns: List[Dict], slot: str,
                     boundary: int) -> Optional[int]:
    store_addr: Optional[int] = None
    for insn in insns:
        if insn['addr'] >= boundary:
            break
        ops = split_operands(insn['op_str'])
        if not ops:
            continue
        if slot_in(ops[0]) == slot:
            store_addr = insn['addr']
    return store_addr


def _slot_store_imm(insns: List[Dict], slot: str,
                    boundary: int) -> Optional[int]:
    store = _slot_last_store(insns, slot, boundary)
    if store is None:
        return None
    for insn in insns:
        if insn['addr'] == store:
            ops = split_operands(insn['op_str'])
            if len(ops) >= 2:
                return is_imm(ops[-1])
            break
    return None


def _size_id(var: str, def_addr: Optional[int], call_addr: int) -> str:
    addr = def_addr if def_addr else call_addr
    return f'{var}@{addr:x}'


def _last_reg_def(insns: List[Dict], reg: str, limit: int) -> Optional[Dict]:
    found: Optional[Dict] = None
    for insn in insns:
        if insn['addr'] >= limit:
            break
        ops = split_operands(insn['op_str'])
        if not ops:
            continue
        dst_regs = regs_in(ops[0]) if not _MEM_TOKEN.search(ops[0]) else []
        if reg in dst_regs:
            found = insn
    return found
