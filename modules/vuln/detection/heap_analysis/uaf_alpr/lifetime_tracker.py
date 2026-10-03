"""ALPR 生命周期溯源追踪器 — 函数内前向扫描, 提取 free/use 与指针溯源标签.

用途: UAF 误报削减的追踪侧。对单个函数维护寄存器/栈槽的指针溯源
       标签, 在 free 调用点记录释放标签, 在解引用/间接调用点记录 use。

与 uaf_detector.py 的关系(优化而非替代):
  uaf_detector 按寄存器记录"已释放", 无法区分 free 后重绑定新分配
  的指针——产生误报。本模块记录标签级溯源, 重绑定会改变标签,
  供 rebound_filter 判定 use 是否作用于已释放对象。

关键设计决策:
  - 标签传播链: mov/lea/add/sub/xor 保持对象归属, 分配函数建立新标签。
  - 解引用判定: 方括号内基址寄存器 + 目标为内存写 / 源为内存读。
  - 写函数 dst: memcpy/strcpy 等通过目标参数写堆, 视为写 use。
  - 过程间摘要: summaries 参数在 call 点展开被调函数的 free/use 参数,
    使跨函数 UAF (free 在 A, use 在 B) 得以关联。
"""

from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, extract_register, extract_constant, extract_mem_offset)

from modules.vuln.detection.heap_analysis.acpe.sym_types import _detect_abi

from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
    FreeRecord, UafUse, UseKind, FuncLifetimeResult)

_CALLER_SAVED = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
_MALLOC_FUNCS = ('malloc', 'calloc', 'realloc')
_FREE_FUNCS = ('free', 'delete', '_ZdlPv', 'HeapFree')
_WRITE_CALLS = ('memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat',
                'memset', 'sprintf', 'read', 'recv', 'fread')


class LifetimeTracker:
    """指针溯源标签追踪器 — 单个函数内前向扫描.

    使用:
      tracker = LifetimeTracker()
      result = tracker.analyze_function(func_name, insns, summaries)
    """

    def __init__(self):
        self._labels: Dict[str, str] = {}
        self._slots: Dict[int, str] = {}
        self._freed_labels: Dict[str, int] = {}
        self._arg_regs: List[str] = []

    def analyze_function(self, func_name: str,
                         insns: List[Instruction],
                         summaries: Optional[dict] = None) -> FuncLifetimeResult:
        result = FuncLifetimeResult(name=func_name)
        arg_regs = _detect_abi(insns)
        self._reset(arg_regs)

        for insn in insns:
            mn = insn.mnemonic
            if mn == 'call':
                self._on_call(insn, result, summaries or {})
            elif mn == 'jmp' and '<' in insn.operands:
                # 尾调用: jmp <func> 等价 call, 参数寄存器保持
                self._on_call(insn, result, summaries or {})
            elif mn in ('mov', 'movzx', 'movsx', 'movsxd'):
                self._on_mov(insn, result)
            elif mn == 'lea':
                self._on_lea(insn)
            elif mn in ('add', 'sub'):
                self._on_addsub(insn)
            elif mn in ('xor', 'pxor'):
                self._on_xor(insn)
        return result

    def _on_call(self, insn: Instruction, result: FuncLifetimeResult,
                 summaries: dict) -> None:
        op = insn.operands.lower()
        if any(f in op for f in _MALLOC_FUNCS):
            self._labels['rax'] = f'alloc@{insn.addr:x}'
            self._clobber()
            self._labels['rax'] = f'alloc@{insn.addr:x}'
            return
        if any(f in op for f in _FREE_FUNCS):
            ptr_reg = self._free_ptr_reg(op)
            label = self._labels.get(ptr_reg, 'unknown') if ptr_reg else 'unknown'
            is_df = (label in self._freed_labels)
            result.frees.append(FreeRecord(
                addr=insn.addr, func_name=result.name, ptr_reg=ptr_reg,
                freed_label=label, is_double_free=is_df))
            if label != 'unknown':
                self._freed_labels[label] = insn.addr
            self._clobber()
            return
        if any(f in op for f in _WRITE_CALLS):
            dst_reg = self._arg_regs[0] if self._arg_regs else 'rcx'
            label = self._labels.get(dst_reg, 'unknown')
            result.uses.append(UafUse(
                addr=insn.addr, func_name=result.name, ptr_reg=dst_reg,
                use_label=label, use_kind=UseKind.WRITE))
            self._clobber()
            return
        # 过程间摘要展开
        callee = self._callee_name(op)
        if callee and callee in summaries:
            summ = summaries[callee]
            for idx in summ.get('frees', []):
                reg = self._arg_regs[idx - 1] if 0 < idx <= len(self._arg_regs) else 'rcx'
                label = self._labels.get(reg, 'unknown')
                result.frees.append(FreeRecord(
                    addr=insn.addr, func_name=result.name, ptr_reg=reg,
                    freed_label=label))
            for idx in summ.get('uses', []):
                reg = self._arg_regs[idx - 1] if 0 < idx <= len(self._arg_regs) else 'rcx'
                label = self._labels.get(reg, 'unknown')
                result.uses.append(UafUse(
                    addr=insn.addr, func_name=result.name, ptr_reg=reg,
                    use_label=label, use_kind=UseKind.READ))
        self._clobber()

    def _free_ptr_reg(self, op: str) -> str:
        reg = extract_register(op)
        return reg or 'rcx'

    def _callee_name(self, op: str) -> str:
        if '<' in op and '>' in op:
            return op.split('<')[-1].split('>')[0]
        return ''

    def _on_mov(self, insn: Instruction, result: FuncLifetimeResult) -> None:
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip()
        if '[' in dst:
            base, off = extract_mem_offset(dst)
            if base in ('rbp', 'rsp') and off is not None:
                self._slots[off] = self._label_of(src)
            if base and base in self._labels:
                result.uses.append(UafUse(
                    addr=insn.addr, func_name=result.name, ptr_reg=base,
                    use_label=self._labels[base], use_kind=UseKind.WRITE))
            return
        dst_reg = extract_register(dst)
        if not dst_reg:
            return
        if '[' in src:
            base, off = extract_mem_offset(src)
            if base in ('rbp', 'rsp') and off is not None:
                if off in self._slots:
                    self._labels[dst_reg] = self._slots[off]
                else:
                    self._labels.pop(dst_reg, None)
            elif base:
                self._labels[dst_reg] = self._labels.get(base, 'unknown')
                if base in self._labels:
                    result.uses.append(UafUse(
                        addr=insn.addr, func_name=result.name, ptr_reg=base,
                        use_label=self._labels[base], use_kind=UseKind.READ))
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
        self._freed_labels.clear()
        self._arg_regs = list(arg_regs)
        for i, reg in enumerate(arg_regs, 1):
            self._labels[reg] = f'arg{i}'

    def _clobber(self) -> None:
        for r in _CALLER_SAVED:
            self._labels.pop(r, None)


def analyze_function_lifetime(func_name: str,
                              insns: List[Instruction],
                              summaries: Optional[dict] = None) -> FuncLifetimeResult:
    """便捷入口."""
    return LifetimeTracker().analyze_function(func_name, insns, summaries)
