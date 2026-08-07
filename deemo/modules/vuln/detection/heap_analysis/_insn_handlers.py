"""指令处理器 — mov/lea/add/sub/xor的寄存器值标签传播.

设计决策:
  每个handler只做寄存器/栈槽的状态更新, 不做控制流判断。
  栈槽追踪逻辑内嵌在_handle_mov中,
  因为mov [rbp-N], reg 和 mov reg, [rbp-N] 是同一枚指令的两面。
"""
from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis._types import WriteRecord, FuncAnalysis
from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, extract_register, extract_constant,
    extract_mem_offset, infer_access_size)


def handle_mov(insn: Instruction, reg_val: Dict[str, object],
               stack_slots: Dict[int, object],
               fa: FuncAnalysis, fn_name: str) -> None:
    """mov及变体, 含栈槽读写和堆内联写入检测.

    栈槽追踪是inline write检测的关键:
      mov [rbp-N], rax  →  stack_slots[-N] = reg_val['rax']
      mov rax, [rbp-N]  →  reg_val['rax'] = stack_slots[-N]
    malloc返回值通过栈槽传递到循环体, 无此机制会丢失追踪链.
    """
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''

    dst_reg = extract_register(dst)
    src_reg = extract_register(src)
    src_const = extract_constant(src) if '[' not in src else None

    # 内存写入分支
    if '[' in dst:
        # 栈槽写入: mov [rbp-N], reg
        if 'rbp' in dst.lower() or 'rsp' in dst.lower():
            dst_base, dst_off = extract_mem_offset(dst)
            if dst_base in ('rbp', 'rsp') and dst_off is not None:
                if src_reg and src_reg in reg_val:
                    stack_slots[dst_off] = reg_val[src_reg]
                elif src_const is not None:
                    stack_slots[dst_off] = src_const
                return

        # 堆写入: mov [malloc_ptr+offset], val
        base_reg, base_off = extract_mem_offset(dst)
        if base_reg:
            base_val = reg_val.get(base_reg)
            if isinstance(base_val, str) and 'malloc' in str(base_val):
                fa.writes.append(WriteRecord(
                    addr=insn.addr, write_func='inline_mov',
                    base_src=str(base_val),
                    offset=base_off or 0,
                    access_size=infer_access_size(dst, insn.raw),
                    size_val=src_const,
                    func_name=fn_name))
        return

    # 寄存器赋值分支
    if dst_reg:
        if src_reg and src_reg in reg_val:
            reg_val[dst_reg] = reg_val[src_reg]
        elif '[' in src and ('rbp' in src.lower() or 'rsp' in src.lower()):
            src_base, src_off = extract_mem_offset(src)
            if src_base in ('rbp', 'rsp') and src_off is not None:
                if src_off in stack_slots:
                    reg_val[dst_reg] = stack_slots[src_off]
                else:
                    reg_val.pop(dst_reg, None)
            else:
                reg_val.pop(dst_reg, None)
        elif '[' in src:
            base_reg, _ = extract_mem_offset(src)
            if base_reg and base_reg in reg_val:
                reg_val[dst_reg] = reg_val[base_reg]
        elif src_const is not None:
            reg_val[dst_reg] = src_const
        else:
            reg_val.pop(dst_reg, None)


def handle_lea(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """lea dst, [base+offset] → 地址标签传播."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)

    if not dst_reg:
        return
    if '[' in src:
        base_reg, base_off = extract_mem_offset(src)
        off = base_off or 0
        if base_reg and base_reg in reg_val:
            base_val = reg_val[base_reg]
            if isinstance(base_val, str):
                reg_val[dst_reg] = f"{base_val}+{off}"
                return
            elif isinstance(base_val, int):
                reg_val[dst_reg] = base_val + off
                return
    reg_val.pop(dst_reg, None)


def handle_addsub(insn: Instruction, reg_val: Dict[str, object],
                  op: str = 'add') -> None:
    """add/sub reg, const → 更新已知常量或偏移标签."""
    parts = insn.operands.split(',')
    dst_reg = extract_register(parts[0].strip())
    src_const = extract_constant(parts[-1].strip()) if len(parts) > 1 else None

    if dst_reg and src_const is not None:
        cur = reg_val.get(dst_reg)
        if isinstance(cur, int):
            delta = src_const if op == 'add' else -src_const
            reg_val[dst_reg] = max(0, cur + delta) if op == 'sub' else cur + delta
        elif isinstance(cur, str) and 'malloc' in str(cur):
            suffix = f"+{src_const}" if op == 'add' else f"-{src_const}"
            reg_val[dst_reg] = f"{cur}{suffix}"


def handle_xor(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """xor reg, reg → reg = 0."""
    parts = insn.operands.split(',')
    r1 = extract_register(parts[0].strip())
    r2 = extract_register(parts[1].strip()) if len(parts) > 1 else None
    if r1 and r2 and r1 == r2:
        reg_val[r1] = 0


def record_memcpy(insn: Instruction, reg_val: Dict[str, object],
                  fa: FuncAnalysis, fn_name: str,
                  arg_regs: List[str]) -> None:
    """记录memcpy/memmove/memset调用的目标缓冲区和size."""
    dst_val = reg_val.get(arg_regs[0])
    size_val = reg_val.get(arg_regs[2]) if len(arg_regs) > 2 else None

    fa.writes.append(WriteRecord(
        addr=insn.addr,
        write_func=insn.mnemonic,
        base_src=str(dst_val) if dst_val else 'unknown',
        size_reg=arg_regs[2] if len(arg_regs) > 2 else '',
        size_val=_safe_int(size_val),
        func_name=fn_name))


def _safe_int(v) -> Optional[int]:
    if isinstance(v, int):
        return v
    return None
