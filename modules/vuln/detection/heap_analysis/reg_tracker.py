"""函数内寄存器值追踪 — 轻量级抽象解释, 追踪malloc→write数据流.

设计决策:
  不做全函数SSA/数据流分析, 只做前向单遍扫描的寄存器值标签传播。
  堆操作涉及的关键指令链很短(malloc→mov链→memcpy), 简单追踪覆盖90%+场景。
  复杂场景(跨函数/循环内多次分配)留给DP-TVRA的三阶段过滤处理。

ABI:
  Windows x64(MinGW): rcx=arg1, rdx=arg2, r8=arg3, r9=arg4
  Linux x86_64:       rdi=arg1, rsi=arg2, rdx=arg3, rcx=arg4, r8=arg5, r9=arg6
  通过自动检测objdump中call前对rdi/rcx的使用来确定ABI。

  BIFT的轻量级值流追踪思想, 但这里只追踪堆相关值(非全污点)。
"""
from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis._types import (
    AllocRecord, WriteRecord, FuncAnalysis)
from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, is_call_to)

# 指令handler提取到独立模块
from modules.vuln.detection.heap_analysis._insn_handlers import (
    handle_mov as _handle_mov,
    handle_lea as _handle_lea,
    handle_addsub as _handle_addsub,
    handle_xor as _handle_xor,
    record_memcpy as _record_memcpy)

# Windows x64 caller-saved寄存器
_CALLER_SAVED = {'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}

# Linux x86_64系统调用ABI的参数寄存器
_SYSV_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_WIN64_ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']

def analyze_function(fn_name: str, insns: List[Instruction],
                     abi: str = "auto") -> FuncAnalysis:
    """单函数内寄存器追踪, 提取alloc→write数据流.

    abi="auto"时自动检测: 若大部分函数入口使用rcx而非rdi, 判定为Windows ABI.
    """
    fa = FuncAnalysis(name=fn_name, n_insns=len(insns))
    if len(insns) < 5:
        return fa

    # 自动ABI检测
    if abi == "auto":
        arg_regs = _detect_abi(insns)
    elif abi == "win64":
        arg_regs = _WIN64_ARG_REGS
    else:
        arg_regs = _SYSV_ARG_REGS

    reg_val: Dict[str, object] = {}
    # 栈槽追踪: {rbp_offset: value_label} — 记录malloc指针在栈上的存储位置
    # 样本02/06/07/11等inline write依赖此机制追踪栈→寄存器往返
    stack_slots: Dict[int, object] = {}
    # 入口参数标记
    for i, reg in enumerate(arg_regs, 1):
        reg_val[reg] = f"arg{i}"

    # 追踪状态
    alloc_records: Dict[int, AllocRecord] = {}
    DEFAULT_UNKNOWN_ALLOC = 128

    # 控制流状态: 追踪是否在 null-check 后的 error 路径上
    _skip_until_addr: int = 0

    for i, insn in enumerate(insns):
        op = insn.operands
        mn = insn.mnemonic

        # 跳过死代码 (null-check error路径)
        if _skip_until_addr and insn.addr < _skip_until_addr:
            continue
        if _skip_until_addr and insn.addr >= _skip_until_addr:
            _skip_until_addr = 0

# call malloc/calloc/realloc
        if is_call_to(insn, 'malloc'):
            size_reg = _WIN64_ARG_REGS[0]
            size_val = _safe_int(reg_val.get(size_reg))
            alloc_records[insn.addr] = AllocRecord(
                addr=insn.addr, alloc_func='malloc',
                size_reg=size_reg, size_val=size_val, func_name=fn_name)
            reg_val['rax'] = f"malloc@{insn.addr:x}"
            _clobber_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'calloc'):
            # calloc(rcx=nmemb, rdx=size) minGW; Linux: (rdi, rsi)
            reg_val['rax'] = f"calloc@{insn.addr:x}"
            alloc_records[insn.addr] = AllocRecord(
                addr=insn.addr, alloc_func='calloc', size_reg=arg_regs[0],
                func_name=fn_name)
            _clobber_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'realloc'):
            reg_val['rax'] = f"realloc@{insn.addr:x}"
            alloc_records[insn.addr] = AllocRecord(
                addr=insn.addr, alloc_func='realloc', size_reg=arg_regs[1],
                func_name=fn_name)
            _clobber_caller_saved(reg_val)
            continue

# call memcpy/memmove/memset
        if (is_call_to(insn, 'memcpy')
                or is_call_to(insn, 'memmove')
                or is_call_to(insn, 'memset')):
            _record_memcpy(insn, reg_val, fa, fn_name, arg_regs)
            _clobber_caller_saved(reg_val)
            continue

        if (is_call_to(insn, 'strcpy') or is_call_to(insn, 'strcat')
                or is_call_to(insn, 'sprintf') or is_call_to(insn, 'snprintf')):
            dst_val = reg_val.get(arg_regs[0])
            fa.writes.append(WriteRecord(
                addr=insn.addr, write_func=insn.mnemonic,
                base_src=str(dst_val) if dst_val else 'unknown',
                size_val=None, func_name=fn_name))
            _clobber_caller_saved(reg_val)
            continue

# 其他call: 清除caller-saved
        if mn == 'call':
            _clobber_caller_saved(reg_val)
            continue

# mov/movsxd/movzx
        if mn in ('mov', 'movsxd', 'movzx', 'movsx'):
            _handle_mov(insn, reg_val, stack_slots, fa, fn_name)
            continue

# lea: 地址计算
        if mn == 'lea':
            _handle_lea(insn, reg_val)
            continue

# add/sub
        if mn == 'add':
            _handle_addsub(insn, reg_val, op='add')
            continue
        if mn == 'sub':
            _handle_addsub(insn, reg_val, op='sub')
            continue

# xor reg,reg → 清零
        if mn in ('xor', 'pxor'):
            _handle_xor(insn, reg_val)
            continue

# 控制流: null-check → 跳过error死代码
        if _is_null_check(insn, insns, i):
            next_insn = insns[i + 1] if i + 1 < len(insns) else None
            if next_insn and next_insn.mnemonic in ('jne', 'je'):
                target = _parse_jump_target(next_insn)
                if target:
                    _skip_until_addr = target
            continue

    fa.allocs = list(alloc_records.values())
    return fa

def _is_null_check(insn: Instruction,
                   insns: List[Instruction], i: int) -> bool:
    """cmp [mem], 0 — malloc null-check前奏."""
    if insn.mnemonic != 'cmp':
        return False
    op = insn.operands.lower()
    return ('qword' in op and '[rbp' in op
            and (op.endswith(',0x0') or op.endswith(',0]')
                 or op.endswith(',0')))

def _parse_jump_target(insn: Instruction) -> Optional[int]:
    """从 jne/jmp 提取目标地址."""
    op = insn.operands.strip()
    try:
        return int(op, 16)
    except ValueError:
        pass
    return None

def _detect_abi(insns: List[Instruction]) -> List[str]:
    """检测ABI: 统计前10条指令中的rcx vs rdi使用."""
    rcx_count = rdi_count = 0
    for insn in insns[:20]:
        if 'rcx' in insn.operands.lower():
            rcx_count += 1
        if 'rdi' in insn.operands.lower():
            rdi_count += 1
    return _WIN64_ARG_REGS if rcx_count >= rdi_count else _SYSV_ARG_REGS

def _safe_int(v) -> Optional[int]:
    if isinstance(v, int):
        return v
    return None

def _clobber_caller_saved(reg_val: Dict[str, object]) -> None:
    """调用后清除caller-saved寄存器(保留rax返回值)."""
    for r in _CALLER_SAVED:
        reg_val.pop(r, None)

