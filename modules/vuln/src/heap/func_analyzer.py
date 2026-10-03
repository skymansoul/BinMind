"""函数内堆操作分析 — 寄存器追踪 + malloc/free/memcpy 数据流提取.

创建: 2024-09-27 , 修改: 2024-09-27
用途: 单函数内轻量抽象寄存器追踪, 提取 malloc→ptr 关系和堆指针的 memcpy/write/free。
设计决策: 不用完整数据流框架(对生产二进制太重), 仅追踪值来源(常量/malloc@addr/argN),
区间推断留给 HeapBoundInferrer; ABI默认 Windows/MinGW (rcx=arg1).
"""
import os
import sys
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from insn_parser import (
    Instruction, is_call_to, extract_register,
    extract_constant, extract_mem_offset, infer_access_size)


@dataclass
class FunctionAnalysis:
    """单个函数内的堆操作分析结果."""
    name: str = ""
    n_insns: int = 0
    mallocs: List[dict] = field(default_factory=list)
    frees: List[dict] = field(default_factory=list)
    writes: List[dict] = field(default_factory=list)
    memcpys: List[dict] = field(default_factory=list)
    violations: int = 0


def analyze_function(name: str,
                     insns: List[Instruction]) -> FunctionAnalysis:
    """在单个函数内追踪寄存器以提取 malloc→write/memcpy 数据流.

    Windows x64 calling convention (MinGW):
      rcx = arg1 (malloc: size; memcpy: dst)
      rdx = arg2 (memcpy: src)
      r8  = arg3 (memcpy: size)
      rax = return value

    追踪策略:
      - call malloc/calloc/realloc: 记录分配点, 标记 rax=malloc@addr
      - call memcpy/memmove/memset: 记录 dst/size 源
      - mov reg, src: 传播值标签 (常量 / malloc@addr / argN)
      - mov [reg+off], val: 检测对 malloc 指针的写入
      - add/sub reg, const: 更新已知常量值
      - lea: 地址计算, 对 argN+const 模式特殊追踪
      - xor reg, reg: 清零
      - call <other>: 清除 caller-saved 寄存器 (rcx,rdx,r8,r9)
    """
    fa = FunctionAnalysis(name=name, n_insns=len(insns))
    reg_val: Dict[str, object] = {}      # 寄存器→值
    mem_val: Dict[str, object] = {}      # 内存槽→值
    malloc_records: Dict[int, dict] = {} # malloc记录
    # 函数入口参数 (Windows x64: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4)
    for i, reg in enumerate(['rcx', 'rdx', 'r8', 'r9'], 1):
        reg_val[reg] = f"arg{i}"

    for insn in insns:
        op = insn.operands
        mn = insn.mnemonic

# call malloc/calloc/realloc
        if is_call_to(insn, 'malloc'):
            size_val = reg_val.get('rcx')
            malloc_records[insn.addr] = {
                'addr': insn.addr,
                'size_reg': 'rcx',
                'size_val': size_val if isinstance(size_val, int) else None,
            }
            reg_val['rax'] = f"malloc@{insn.addr:x}"
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'calloc'):
            reg_val['rax'] = f"calloc@{insn.addr:x}"
            malloc_records[insn.addr] = {
                'addr': insn.addr, 'size_reg': 'rcx',
            }
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'realloc'):
            # Win x64: rdx=arg2=new_size. ptr in rcx.
            size_val = reg_val.get('rdx')
            reg_val['rax'] = f"realloc@{insn.addr:x}"
            malloc_records[insn.addr] = {
                'addr': insn.addr, 'size_reg': 'rdx',
                'size_val': size_val if isinstance(size_val, int) else None,
            }
            _clear_caller_saved(reg_val)
            continue

# call memcpy/memmove/memset
        if (is_call_to(insn, 'memcpy')
                or is_call_to(insn, 'memmove')
                or is_call_to(insn, 'memset')):
            dst_val = reg_val.get('rcx')
            size_val = reg_val.get('r8')
            fa.memcpys.append({
                'addr': insn.addr,
                'dst_reg': 'rcx', 'dst_val': dst_val,
                'size_reg': 'r8',
                'size_val': size_val if isinstance(size_val, int) else None,
            })
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'strcpy') or is_call_to(insn, 'strcat'):
            dst_val = reg_val.get('rcx')
            fa.memcpys.append({
                'addr': insn.addr,
                'dst_reg': 'rcx', 'dst_val': dst_val,
                'size_reg': '', 'size_val': None,
                'type': 'strcpy',
            })
            _clear_caller_saved(reg_val)
            continue

# call free
        if is_call_to(insn, 'free'):
            ptr_val = reg_val.get('rcx')
            fa.frees.append({
                'addr': insn.addr,
                'ptr_reg': 'rcx',
                'ptr_val': ptr_val,
                'function': name,
            })
            _clear_caller_saved(reg_val)
            continue

# 其他 call: 清除 caller-saved
        if mn == 'call':
            _clear_caller_saved(reg_val)
            continue

# mov/movsxd/movzx
        if mn in ('mov', 'movsxd', 'movzx', 'movsx'):
            _handle_mov(insn, reg_val, mem_val, fa, name)
            continue

# add: reg += const
        if mn == 'add':
            _handle_add(insn, reg_val)
            continue

# sub: reg -= const
        if mn == 'sub':
            _handle_sub(insn, reg_val)
            continue

# lea: 纯地址计算
        if mn == 'lea':
            _handle_lea(insn, reg_val)
            continue

# xor/pxor: 清零
        if mn in ('xor', 'pxor'):
            _handle_xor(insn, reg_val)
            continue

# shl/sal: reg <<= const
        if mn in ('shl', 'sal'):
            _handle_shift(insn, reg_val, 'shl')
            continue

# shr/sar: reg >>= const
        if mn in ('shr', 'sar'):
            _handle_shift(insn, reg_val, 'shr')
            continue

    fa.mallocs = list(malloc_records.values())
    return fa


# 指令处理器
# caller-saved 寄存器 (Windows x64)
_CALLER_SAVED = {'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}


def _clear_caller_saved(reg_val: Dict[str, object]) -> None:
    for r in _CALLER_SAVED:
        reg_val.pop(r, None)


def _handle_mov(insn: Instruction,
                reg_val: Dict[str, object],
                mem_val: Dict[str, object],
                fa: FunctionAnalysis,
                fn_name: str) -> None:
    """处理 mov 及其变体指令."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''

    dst_reg = extract_register(dst)
    src_reg = extract_register(src)
    src_const = extract_constant(src) if '[' not in src else None

    # 内存写入: mov [reg+offset], val
    if '[' in dst:
        base_reg, base_off = extract_mem_offset(dst)
        if base_reg:
            base_val = reg_val.get(base_reg)
            if isinstance(base_val, str) and 'malloc' in str(base_val):
                fa.writes.append({
                    'addr': insn.addr,
                    'base_reg': base_reg,
                    'base_val': base_val,
                    'offset': base_off or 0,
                    'access_size': infer_access_size(dst, insn.raw),
                    'src_val': src_const,
                    'function': fn_name,
                })
        mem_key = f"mem@{dst}"
        if src_reg and src_reg in reg_val:
            mem_val[mem_key] = reg_val[src_reg]
        elif src_const is not None:
            mem_val[mem_key] = src_const
        return

    # 寄存器赋值
    if dst_reg:
        if src_reg and src_reg in reg_val:
            reg_val[dst_reg] = reg_val[src_reg]
        elif '[' in src:
            base_reg, _ = extract_mem_offset(src)
            mem_key = f"mem@{src}"
            if mem_key in mem_val:
                reg_val[dst_reg] = mem_val[mem_key]
            elif base_reg and base_reg in reg_val:
                reg_val[dst_reg] = reg_val[base_reg]
        elif src_const is not None:
            reg_val[dst_reg] = src_const
        else:
            reg_val.pop(dst_reg, None)


def _handle_add(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """add reg, const → 更新已知常量或指针偏移."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    src_const = extract_constant(src)

    if dst_reg and src_const is not None:
        cur = reg_val.get(dst_reg)
        if isinstance(cur, int):
            reg_val[dst_reg] = cur + src_const
        elif isinstance(cur, str) and 'malloc' in str(cur):
            reg_val[dst_reg] = f"{cur}+{src_const}"


def _handle_sub(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """sub reg, const → 减量更新, 下界为0."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    src_const = extract_constant(src)

    if dst_reg and src_const is not None:
        cur = reg_val.get(dst_reg)
        if isinstance(cur, int):
            reg_val[dst_reg] = max(0, cur - src_const)


def _handle_lea(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """lea dst, [base+offset] → 地址传播."""
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
            if isinstance(base_val, str) and 'malloc' in str(base_val):
                reg_val[dst_reg] = f"{base_val}+{off}"
                return
            elif isinstance(base_val, int):
                reg_val[dst_reg] = base_val + off
                return
            elif isinstance(base_val, str) and base_val.startswith('arg'):
                reg_val[dst_reg] = f"{base_val}+{off}"
                return

    # lea 产生指针, 无法追踪为简单值
    reg_val.pop(dst_reg, None)


def _handle_xor(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """xor reg, reg → reg = 0."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    src_reg = extract_register(src)
    if dst_reg and src_reg and dst_reg == src_reg:
        reg_val[dst_reg] = 0


def _handle_shift(insn: Instruction,
                  reg_val: Dict[str, object],
                  direction: str) -> None:
    """shl/sal/shr/sar reg, const → 更新 reg 值为移位结果.
    32位溢出: 若 reg 32位值 * 2^amt > 2^32, 取模 (模拟整数回绕)."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    amount = extract_constant(src)

    if not dst_reg or amount is None:
        return
    cur = reg_val.get(dst_reg)
    if not isinstance(cur, int):
        return
    # 32位回绕检测: 若当前值可用32位表示且为32位操作寄存器
    is_32bit = dst.rstrip(',') in ('eax', 'ecx', 'edx', 'ebx', 'esi', 'edi',
                                    'r8d', 'r9d', 'r10d', 'r11d')
    if direction in ('shl', 'sal'):
        result = cur << amount
        if is_32bit and result > 0xFFFFFFFF:
            result = result & 0xFFFFFFFF
    else:
        result = cur >> amount
    reg_val[dst_reg] = result
