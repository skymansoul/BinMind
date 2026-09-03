"""FPE 格式溯源追踪器 — 前向扫描, 提取格式参数溯源标签.

用途: 格式字符串漏洞误报削减的追踪侧。对单个函数维护寄存器/栈槽的
      溯源标签, 在格式化函数调用点记录格式参数的标签。

与 format_string_detector.py 的关系(优化而非替代):
  既有检测用固定 5 条指令回溯窗口判断格式串是否常量——常量经局部
  变量/栈槽间接传递时漏判为"非常量", 产生误报。本模块做全链标签
  传播, 任意距离均可解析.

关键设计决策:
  - lea reg,[rip+off] → .rdata 标签 (常量池).
  - mov reg, OFFSET .LCx / lea 全局 → .rdata.
  - 栈槽保存/恢复标签, 覆盖 `const char *f = "%s"; ... printf(f, x)`.
"""

from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, extract_register, extract_constant, extract_mem_offset)

from modules.vuln.detection.heap_analysis.acpe.sym_types import _detect_abi

from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_types import (
    FmtCall, FuncFmtResult)

_CALLER_SAVED = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
_FMT_FUNCS = {
    'printf': 0, 'fprintf': 1, 'sprintf': 1, 'snprintf': 2,
    'dprintf': 1, 'syslog': 1, 'vprintf': 0, 'vfprintf': 1,
    'vsprintf': 1, 'vsnprintf': 2, 'err': 1, 'warn': 1,
}


class FmtTracker:
    """格式溯源标签追踪器 — 单个函数内前向扫描."""

    def __init__(self):
        self._labels: Dict[str, str] = {}
        self._slots: Dict[int, str] = {}

    def analyze_function(self, func_name: str,
                         insns: List[Instruction]) -> FuncFmtResult:
        result = FuncFmtResult(name=func_name)
        arg_regs = _detect_abi(insns)
        self._reset(arg_regs)

        for insn in insns:
            mn = insn.mnemonic
            if mn == 'call':
                self._on_call(insn, result, arg_regs)
            elif mn == 'jmp' and '<' in insn.operands:
                # 尾调用: jmp <func> 等价 call, 参数寄存器保持
                self._on_call(insn, result, arg_regs)
            elif mn in ('mov', 'movzx', 'movsx', 'movsxd'):
                self._on_mov(insn)
            elif mn == 'lea':
                self._on_lea(insn)
            elif mn in ('add', 'sub'):
                self._on_addsub(insn)
            elif mn in ('xor', 'pxor'):
                self._on_xor(insn)
        return result

    def _on_call(self, insn: Instruction, result: FuncFmtResult,
                 arg_regs: List[str]) -> None:
        op = insn.operands.lower()
        callee = self._callee_name(op)
        if callee:
            if callee.startswith('__mingw_'):
                callee = callee[len('__mingw_'):]
            fmt_idx = _FMT_FUNCS.get(callee)
            if fmt_idx is not None:
                reg = arg_regs[fmt_idx] if fmt_idx < len(arg_regs) else 'rcx'
                label = self._labels.get(reg, 'unknown')
                result.calls.append(FmtCall(
                    addr=insn.addr, func_name=result.name,
                    fmt_func=callee, fmt_label=label, fmt_reg=reg))
        self._clobber()

    def _callee_name(self, op: str) -> str:
        if '<' in op and '>' in op:
            return op.split('<')[-1].split('>')[0]
        # 无符号注释: 取最后一个 token (测试/直接调用场景)
        tokens = op.replace(',', ' ').split()
        if tokens:
            return tokens[-1].split('@')[0]
        return ''

    def _on_mov(self, insn: Instruction) -> None:
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip()
        if '[' in dst:
            base, off = extract_mem_offset(dst)
            if base in ('rbp', 'rsp') and off is not None:
                self._slots[off] = self._label_of(src)
            return
        dst_reg = extract_register(dst)
        if not dst_reg:
            return
        if '[' in src:
            base, off = extract_mem_offset(src)
            if base in ('rbp', 'rsp') and off is not None:
                self._labels[dst_reg] = self._slots.get(off, 'unknown')
            elif base:
                self._labels[dst_reg] = self._labels.get(base, 'unknown')
            return
        self._labels[dst_reg] = self._label_of(src)

    def _on_lea(self, insn: Instruction) -> None:
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip()
        dst_reg = extract_register(dst)
        if not dst_reg:
            return
        if '[' in src:
            base, off = extract_mem_offset(src)
            if base in ('rsp', 'rbp'):
                self._labels[dst_reg] = 'stack'
                return
            if base == 'rip' or '.rdata' in src.lower() or '.rodata' in src.lower():
                self._labels[dst_reg] = '.rdata'
                return
            if base and base in self._labels:
                self._labels[dst_reg] = self._labels[base]
                return
        self._labels.pop(dst_reg, None)

    def _on_addsub(self, insn: Instruction) -> None:
        op = insn.operands
        parts = [p.strip() for p in op.split(',')]
        dst_reg = extract_register(parts[0])
        if dst_reg and dst_reg in self._labels:
            pass  # 同对象内偏移, 溯源标签不变

    def _on_xor(self, insn: Instruction) -> None:
        op = insn.operands
        parts = [p.strip() for p in op.split(',')]
        r1 = extract_register(parts[0])
        r2 = extract_register(parts[1]) if len(parts) > 1 else None
        if r1 and r2 and r1 == r2:
            self._labels[r1] = 'const'

    def _label_of(self, operand: str) -> str:
        if '[' in operand:
            base, off = extract_mem_offset(operand)
            if base in ('rbp', 'rsp') and off is not None:
                return self._slots.get(off, 'unknown')
            if base:
                return self._labels.get(base, 'unknown')
            return 'unknown'
        low = operand.lower()
        if 'offset' in low or 'lc' in low or '.rdata' in low or '.rodata' in low:
            return '.rdata'
        c = extract_constant(operand)
        if c is not None:
            return 'const'
        reg = extract_register(operand)
        if reg:
            return self._labels.get(reg, 'unknown')
        return 'unknown'

    def _reset(self, arg_regs: List[str]) -> None:
        self._labels.clear()
        self._slots.clear()
        for i, reg in enumerate(arg_regs, 1):
            self._labels[reg] = f'arg{i}'

    def _clobber(self) -> None:
        for r in _CALLER_SAVED:
            self._labels.pop(r, None)


def analyze_function_fmt(func_name: str,
                         insns: List[Instruction]) -> FuncFmtResult:
    """便捷入口."""
    return FmtTracker().analyze_function(func_name, insns)
