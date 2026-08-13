"""ACPE 符号追踪共享类型与工具 — 供 SymSizeTracker 使用.

创建: 2025-03-28
内容:
  数据类型  SymAlloc / SymWrite / FuncSymResult
  工具     _is_call_name / _extract_scale / _reg_width_bits / _detect_abi
  便捷入口 analyze_function_sym / match_write_alloc
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from modules.vuln.detection.heap_analysis.insn_parser import Instruction
from modules.vuln.detection.heap_analysis.acpe.capacity_model import CapExpr
from modules.vuln.detection.heap_analysis.acpe.guard_dominance import GuardRecord

_CALLER_SAVED = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
_ARG_REGS_WIN = ['rcx', 'rdx', 'r8', 'r9']
_ARG_REGS_SYSV = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_COND_JCC = {'jbe', 'jle', 'jb', 'jl', 'ja', 'jg', 'jae', 'jge'}


@dataclass
class SymAlloc:
    """符号化分配点."""
    addr: int
    func_name: str
    alloc_func: str        # malloc/calloc/realloc
    size_expr: CapExpr     # 分配 size 的符号容量表达式
    dst_label: str         # 返回指针标签, 如 'alloc@140001773'


@dataclass
class SymWrite:
    """符号化写入点."""
    addr: int
    func_name: str
    write_func: str        # memcpy/strcpy/read/...
    size_expr: CapExpr     # 写入 size 的符号容量表达式
    dst_label: str         # 目标缓冲区的 malloc 标签
    dst_offset: int = 0    # 目标缓冲区内的常量偏移 (如 box+200)
    dst_offset_unknown: bool = False  # 偏移符号化, 无法静态判定
    unbounded: bool = False  # strcpy/gets 类: 长度未知
    dst_is_stack: bool = False  # 目标为栈/局部地址, 非堆写入


@dataclass
class FuncSymResult:
    """单函数符号追踪结果."""
    name: str
    allocs: List[SymAlloc] = field(default_factory=list)
    writes: List[SymWrite] = field(default_factory=list)
    guards: List[GuardRecord] = field(default_factory=list)
    insns: List[Instruction] = field(default_factory=list)


def _is_call_name(insn: Instruction, names: Tuple[str, ...]) -> bool:
    if insn.mnemonic != 'call':
        return False
    op = insn.operands.lower()
    return any(n in op for n in names)


def _extract_scale(operand: str) -> int:
    """提取内存操作数中的缩放因子: [rax*8+0x20] → 8."""
    import re
    m = re.search(r'\*(\d+)', operand)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return 1
    return 1


def _reg_width_bits(operand: str) -> int:
    """寄存器操作数的位宽: rax→64, eax→32, ax→16, al→8."""
    import re
    m = re.search(
        r'\b(r[0-9]+[dwb]|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p|[er]?ip)\b',
        operand.lower())
    if not m:
        return 64
    r = m.group(1)
    if r[-1] in 'dwb':
        return {'d': 32, 'w': 16, 'b': 8}[r[-1]]
    if r.startswith('e'):
        return 32
    if r in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
        return 16
    if r in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
             'sil', 'dil', 'bpl', 'spl'):
        return 8
    return 64


def _detect_abi(insns: List[Instruction]) -> List[str]:
    """统计前若干指令的 rcx/rdi 使用, 粗判 Win64 或 SysV."""
    rcx = rdi = 0
    for insn in insns[:20]:
        op = insn.operands.lower()
        if 'rcx' in op:
            rcx += 1
        if 'rdi' in op:
            rdi += 1
    return _ARG_REGS_WIN if rcx >= rdi else _ARG_REGS_SYSV


def analyze_function_sym(func_name: str,
                         insns: List[Instruction]) -> 'FuncSymResult':
    """便捷入口."""
    from modules.vuln.detection.heap_analysis.acpe.sym_size_tracker import (
        SymSizeTracker)
    return SymSizeTracker().analyze_function(func_name, insns)


def match_write_alloc(w: SymWrite,
                      allocs: List[SymAlloc]) -> Optional[SymAlloc]:
    """将写入关联到目标分配点.

    优先用 dst_label(如 'alloc@140001773')精确匹配;
    无标签时回退到写入前最近的分配点(保守)。
    """
    for a in allocs:
        if a.dst_label == w.dst_label:
            return a
    best = None
    for a in allocs:
        if a.addr < w.addr:
            best = a
        else:
            break
    return best
