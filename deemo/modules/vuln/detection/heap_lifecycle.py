# coding: utf-8
#
"""
堆操作生命周期建模-追踪malloc/free配对时序+size参数跨指令值流。

解决的问题:
  A. 堆溢出检测中size参数在当前指令之前（mov edi, n; call malloc）,
     当前heap_overflow_detector依赖外部传入known_constants字典,
     无法追踪变量传递场景（n来自更早的指令或函数参数）。
  B. UAF检测中缺少时序维度-free后重新malloc同大小内存并复用指针
     是合法行为, 但当前detect_uaf标记为UAF（误报）。

解决方案:
  A. 到达-定值分析（reaching definitions）-从call malloc反向扫描,
     追踪size参数寄存器(rdi)的定义链, 提取常量值或标记为"外部输入"。
     仅在同基本块内做线性扫描, O(N)复杂度。
  B. 每指针的alloc/free配对时序-维护{ptr_reg: [(op_type, insn_idx)]}列表,
     在检测deref时验证时序: 仅当use发生在free之后且在下一次alloc之前
     才标记为UAF。

输出:
  - LifecycleReport: 每指针的完整生命周期事件列表
  - alloc_size_map: {insn_idx: size_value}-供heap_overflow_detector消费
  - temporal_uaf_candidates: 经时序验证的UAF候选列表
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

_log = logging.getLogger(__name__)


@dataclass
class LifecycleEvent:
    """单次堆操作事件"""
    insn_idx: int
    address: int
    op_type: str          # malloc / calloc / realloc / free / deref_read / deref_write
    pointer_reg: str = "" # 涉及的指针寄存器
    size_value: int = 0   # 若为alloc且提取到size-此处存储; 0=未知
    size_source: str = "" # constant / param / unknown


@dataclass
class LifecycleReport:
    """函数内所有指针的完整生命周期报告"""
    function_name: str
    # 按指针分组的事件序列
    per_pointer: Dict[str, List[LifecycleEvent]] = field(default_factory=dict)
    # alloc_size_map: 指令索引-分配大小(供heap_overflow_detector消费)
    alloc_sizes: Dict[int, int] = field(default_factory=dict)
    # 时序UAF候选
    temporal_uaf: List[Tuple[int, int, str]] = field(default_factory=list)
    # (free_idx, deref_idx, ptr_reg)


class HeapLifecycleAnalyzer:
    """堆操作生命周期分析器-malloc/free配对+时序+size值流。

    用法:
      analyzer = HeapLifecycleAnalyzer()
      report = analyzer.analyze(instructions, 'function_name')
      # report.alloc_sizes 可直接传给 heap_overflow_detector
      # report.temporal_uaf 是经时序过滤的UAF候选
    """

    # 分配函数-大小参数在调用约定中的位置
    _ALLOC_SIZE_ARG = {'malloc': 0, 'calloc': 1, 'realloc': 1,
                       '_Znwm': 0, '_Znam': 0}

    # 释放函数
    _FREE_FUNCS = {'free', '_ZdlPv', '_ZdaPv', 'HeapFree', 'VirtualFree'}

    # x86_64参数寄存器
    _ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

    # 常见x86_64寄存器
    _X86_REGS = {'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10',
                 'r11','r12','r13','r14','r15','rbp','rsp',
                 'eax','ebx','ecx','edx','esi','edi'}

    def analyze(self, instructions: List[str],
                 function_name: str = "",
                 base_addr: int = 0x400000
                 ) -> LifecycleReport:
        report = LifecycleReport(function_name=function_name)

        if not instructions:
            return report

        # Phase 1: 收集所有堆事件
        events = []
        for i, insn in enumerate(instructions):
            evt = self._classify_insn(insn, i, base_addr, instructions)
            if evt:
                events.append(evt)

        # Phase 2: 按指针分组
        for evt in events:
            ptr = evt.pointer_reg
            if not ptr:
                continue
            if ptr not in report.per_pointer:
                report.per_pointer[ptr] = []
            report.per_pointer[ptr].append(evt)

        # Phase 3: 构建alloc_size_map
        for evt in events:
            if evt.op_type in self._ALLOC_SIZE_ARG and evt.size_value > 0:
                report.alloc_sizes[evt.insn_idx] = evt.size_value

        # Phase 4: 时序UAF检测
        for ptr_reg, evt_list in report.per_pointer.items():
            last_free_idx = -1
            for evt in evt_list:
                if evt.op_type == 'free':
                    last_free_idx = evt.insn_idx
                elif evt.op_type in ('deref_read', 'deref_write'):
                    if last_free_idx >= 0:
                        # 检查free和deref之间是否有新的alloc
                        has_new_alloc = any(
                            e.op_type in self._ALLOC_SIZE_ARG
                            and last_free_idx < e.insn_idx < evt.insn_idx
                            for e in evt_list)
                        if not has_new_alloc:
                            report.temporal_uaf.append(
                                (last_free_idx, evt.insn_idx, ptr_reg))

        return report

    def _classify_insn(self, insn: str, idx: int, base: int,
                        all_insns: List[str]) -> Optional[LifecycleEvent]:
        stripped = insn.strip()
        if ':' in stripped[:20]:
            addr_str = stripped.split(':')[0]
            try: addr = int(addr_str, 16)
            except ValueError: addr = base + idx * 4
            rest = stripped.split(':', 1)[1].strip()
        else:
            addr = base + idx * 4
            rest = stripped

        parts = rest.split()
        if len(parts) < 2:
            return None
        mnem = parts[0].lower()

        # 识别call指令
        if mnem != 'call' or len(parts) < 2:
            # 非call指令-检查是否为指针解引用
            return self._check_deref(rest, idx, addr)

        callee = parts[1].strip().lower()
        # 去除@plt后缀
        callee = callee.split('@')[0]

        # malloc(size) / calloc(n, size)
        for afunc, size_arg_idx in self._ALLOC_SIZE_ARG.items():
            if afunc in callee:
                ptr_reg = self._alloc_return_reg()
                size_val = self._trace_size_arg(
                    all_insns, idx, size_arg_idx)
                return LifecycleEvent(
                    insn_idx=idx, address=addr, op_type=afunc,
                    pointer_reg=ptr_reg, size_value=size_val,
                    size_source='constant' if size_val > 0 else 'unknown')

        # free(ptr)
        for ffunc in self._FREE_FUNCS:
            if ffunc in callee:
                ptr_reg = self._trace_ptr_arg(all_insns, idx, 0)
                return LifecycleEvent(
                    insn_idx=idx, address=addr, op_type='free',
                    pointer_reg=ptr_reg)

        return None

    def _check_deref(self, rest: str, idx: int,
                      addr: int) -> Optional[LifecycleEvent]:
        """检查非call指令是否为指针解引用。"""
        rest_lower = rest.lower()
        if '[' not in rest_lower:
            return None
        # 提取方括号内的寄存器
        m = re.search(r'\[(\w+)', rest_lower)
        if not m:
            return None
        ptr_reg = m.group(1)
        if ptr_reg not in self._X86_REGS:
            return None
        # 判断读/写
        if 'mov' in rest_lower:
            parts = rest_lower.replace(',', ' ').split()
            if len(parts) >= 3 and '[' in parts[1]:
                dtype = 'deref_write'
            else:
                dtype = 'deref_read'
        else:
            dtype = 'deref_read'
        return LifecycleEvent(
            insn_idx=idx, address=addr, op_type=dtype,
            pointer_reg=ptr_reg)

    # 32位-64位寄存器名映射
    _REG32_TO_64 = {'edi': 'rdi', 'esi': 'rsi', 'edx': 'rdx', 'ecx': 'rcx',
                    'eax': 'rax', 'ebx': 'rbx', 'r8d': 'r8', 'r9d': 'r9'}

    def _trace_size_arg(self, insns: List[str], call_idx: int,
                          arg_idx: int) -> int:
        """从call指令反向追踪size参数的值。

        同时匹配64位(rdi)和32位(edi)寄存器名。
        若无法提取立即数, 返回0。
        """
        if arg_idx >= len(self._ARG_REGS):
            return 0
        target64 = self._ARG_REGS[arg_idx]
        # 生成所有可能的寄存器名变体 (rdi + edi)
        target32 = {k for k, v in self._REG32_TO_64.items() if v == target64}
        all_names = {target64} | target32
        for j in range(call_idx - 1, max(-1, call_idx - 15), -1):
            insn = insns[j].lower().strip()
            if ':' in insn[:20]:
                insn = insn.split(':', 1)[1].strip()
            for tgt in all_names:
                if f'mov {tgt},' in insn or f'mov {tgt}, ' in insn:
                    parts = insn.replace(',', ' ').split()
                    found_target = False
                    for k, p in enumerate(parts):
                        if p == tgt and not found_target:
                            found_target = True
                            continue
                        if found_target:
                            src = p
                            try:
                                if src.startswith('0x'):
                                    return int(src, 16)
                                return int(src)
                            except ValueError:
                                return 0
            # lea也可表示大小-lea edi/rdi, [rax+imm]中imm可能是大小
            if any(f'lea {tgt},' in insn and '+' in insn for tgt in all_names):
                m = re.search(r'\+0x([0-9a-fA-F]+)', insn)
                if m:
                    return int(m.group(1), 16)
        return 0

    def _trace_ptr_arg(self, insns: List[str], call_idx: int,
                         arg_idx: int) -> str:
        """从call指令反向追踪指针参数-返回寄存器名。"""
        target_reg = self._ARG_REGS[arg_idx] if arg_idx < len(
            self._ARG_REGS) else 'rdi'
        for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
            insn = insns[j].lower().strip()
            if ':' in insn[:20]:
                insn = insn.split(':', 1)[1].strip()
            if f'mov {target_reg},' in insn:
                parts = insn.replace(',', ' ').split()
                found = False
                for p in parts:
                    if p == target_reg:
                        found = True
                        continue
                    if found and p in self._X86_REGS:
                        return p
                return 'unknown'
        return 'unknown'

    @staticmethod
    def _alloc_return_reg() -> str:
        return 'rax'


__all__ = [
    "LifecycleEvent", "LifecycleReport", "HeapLifecycleAnalyzer",
]
