# UAF函数内检测 — 从uaf_orchestrator.py拆分.
# 包含三路策略: ptr_val精确匹配 / 源寄存器追踪 / 栈重载追踪.

import re
from typing import Dict, List, Optional

from .insn_parser import Instruction, extract_register
from func_analyzer import FunctionAnalysis

_DEREF_MNEMONICS = {'mov', 'movzx', 'movsx', 'movsxd', 'add', 'sub',
                     'cmp', 'test', 'and', 'or', 'xor', 'lea'}


def detect_intra_uaf(fa: FunctionAnalysis,
                     insns: List[Instruction],
                     fn_name: str, UAFCandidate) -> List:
    """free 后前向扫描 ≤30 指令, 通过 malloc地址匹配 + 数据流追踪检测 UAF.

    三路策略 (按优先级):
      1) malloc地址匹配: free后同一ptr_val的write → UAF
      2) 源寄存器追踪: free前 mov arg_reg,<src> → post-free [src] 解引用
      3) 栈重载追踪: free前 mov [rbp-XX],reg → post-free [reload_reg] 解引用
    """
    candidates = []
    freed_at: Dict[int, dict] = {}
    for f in fa.frees:
        pv = str(f.get('ptr_val', ''))
        if 'malloc' in pv or 'calloc' in pv or 'realloc' in pv:
            freed_at[f['addr']] = f
    if not freed_at:
        return candidates

    writes_by_ptr: Dict[str, List[dict]] = {}
    for w in fa.writes:
        bv = str(w.get('base_val', ''))
        if bv:
            writes_by_ptr.setdefault(bv, []).append(w)

    for free_addr in sorted(freed_at.keys()):
        f_info = freed_at[free_addr]
        ptr_val = str(f_info.get('ptr_val', ''))
        ptr_reg = f_info.get('ptr_reg', 'rcx')
        free_idx = next((idx for idx, insn in enumerate(insns)
                         if insn.addr == free_addr), None)
        if free_idx is None:
            continue

        found = _try_ptrval_match(candidates, free_addr, ptr_val, ptr_reg,
                                  fn_name, free_idx, writes_by_ptr, insns,
                                  UAFCandidate)
        if found:
            continue
        _try_dataflow_match(candidates, free_addr, ptr_val, ptr_reg,
                            fn_name, free_idx, insns, fa, UAFCandidate)
    return candidates


def _try_ptrval_match(candidates, free_addr, ptr_val, ptr_reg,
                       fn_name, free_idx, writes_by_ptr, insns,
                       UAFCandidate) -> bool:
    """策略1: 通过 ptr_val 精确匹配 post-free 的 write."""
    if ptr_val not in writes_by_ptr:
        return False
    for w in writes_by_ptr[ptr_val]:
        if w['addr'] > free_addr:
            w_idx = next((idx for idx, insn in enumerate(insns)
                          if insn.addr == w['addr']), None)
            gap = (w_idx - free_idx) if w_idx is not None else 0
            if 0 < gap <= 30:
                candidates.append(UAFCandidate(
                    ptr_name=ptr_reg, ptr_value=ptr_val,
                    free_insn_addr=free_addr, use_insn_addr=w['addr'],
                    use_type='write', function_name=fn_name,
                    instruction_gap=gap))
                return True
    return False


def _try_dataflow_match(candidates, free_addr, ptr_val, ptr_reg,
                         fn_name, free_idx, insns, fa, UAFCandidate) -> None:
    """策略2+3: 数据流追踪 — 源寄存器 + 栈重载 → post-free deref."""
    src_reg = None
    stack_slot = None
    stack_src_reg = None

    for j2 in range(free_idx - 1, max(0, free_idx - 11) - 1, -1):
        insn = insns[j2]
        if insn.mnemonic not in ('mov', 'movsxd'):
            continue
        op = insn.operands.strip(); parts = op.split(',')
        dst = parts[0].strip(); src = parts[-1].strip() if ',' in op else ''
        dst_r = extract_register(dst)
        src_r = extract_register(src)
        if dst_r == ptr_reg and src_r and src_reg is None:
            src_reg = src_r
        off = _stack_offset(dst)
        if off and src_r and stack_slot is None:
            stack_slot = off
            stack_src_reg = src_r
        off2 = _stack_offset(src)
        if off2 and dst_r and stack_slot is None:
            stack_slot = off2
            stack_src_reg = dst_r
        if src_reg and stack_slot:
            break

    tracked_regs = {r for r in (src_reg, ptr_reg, stack_src_reg) if r}
    reloaded_from_stack: Dict[str, str] = {}

    for j in range(free_idx + 1, min(free_idx + 31, len(insns))):
        insn = insns[j]; op_str = insn.operands
        op_lower = op_str.lower()
        mn = insn.mnemonic

        if mn in ('mov', 'movsxd'):
            op = op_str.strip(); parts = op.split(',')
            dst2 = parts[0].strip()
            src2 = parts[-1].strip() if ',' in op else ''
            dst_r2 = extract_register(dst2)
            src_off = _stack_offset(src2)
            if src_off and dst_r2:
                tracked_regs.add(dst_r2)
                reloaded_from_stack[dst_r2] = src_off
                continue

        if mn not in _DEREF_MNEMONICS and mn != 'call':
            continue

        if '[' in op_lower:
            for tr in list(tracked_regs):
                if _is_base_reg(tr, op_str):
                    if _is_safe_reuse(insn.addr, ptr_val, fa):
                        return
                    candidates.append(UAFCandidate(
                        ptr_name=tr, ptr_value=ptr_val,
                        free_insn_addr=free_addr, use_insn_addr=insn.addr,
                        use_type='write' if _is_write(insn) else 'read',
                        function_name=fn_name,
                        instruction_gap=j - free_idx))
                    return

        if mn == 'call':
            target = op_str.strip().lower()
            for tr in tracked_regs:
                if target == tr or ('[' in target and _is_base_reg(tr, target)):
                    if _is_safe_reuse(insn.addr, ptr_val, fa):
                        return
                    candidates.append(UAFCandidate(
                        ptr_name=tr, ptr_value=ptr_val,
                        free_insn_addr=free_addr, use_insn_addr=insn.addr,
                        use_type='call_via', function_name=fn_name,
                        instruction_gap=j - free_idx))
                    return


def _is_base_reg(reg: str, op_str: str) -> bool:
    """检查 reg 是否是内存操作数中的基址寄存器 (在 [] 内)."""
    m = re.search(r'\[([^\]]*)\]', op_str)
    if not m:
        return False
    inner = m.group(1).lower()
    for token in re.split(r'[+\-*]', inner):
        if token.strip() == reg:
            return True
    return False


def _is_write(insn: Instruction) -> bool:
    op = insn.operands
    return ',' in op and '[' in op.split(',')[0]


def _stack_offset(operand: str) -> Optional[str]:
    """提取栈偏移规范表示. 'qword ptr [rbp-0x20]' → 'rbp-0x20'."""
    m = re.search(r'\[(r[sb]p[+-]0x[0-9a-fA-F]+)\]', operand)
    return m.group(1) if m else None


def _is_safe_reuse(use_addr: int, freed_ptr_val: str,
                   fa: FunctionAnalysis) -> bool:
    """检查 use_addr 处的写是否指向与 freed_ptr_val 不同的 malloc."""
    for w in fa.writes:
        if w['addr'] == use_addr:
            w_base = str(w.get('base_val', ''))
            if w_base and freed_ptr_val and w_base != freed_ptr_val:
                if 'malloc' in w_base or 'calloc' in w_base:
                    return True
    return False
