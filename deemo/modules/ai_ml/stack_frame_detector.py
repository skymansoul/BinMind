# created: 2026-08-23
# 栈帧边界检测——通过调用约定模式识别推断函数边界和栈帧布局
#
# 核心问题: 剥离二进制丢失了函数边界和栈帧信息。现有方法依赖
# 符号表(如果有)或启发式(函数序言/尾声模式)，对非标准序言
# （如O3优化后的函数、手写汇编）失效。
#
# 技术方案:
#   1. 调用约定指纹: 通过分析函数体内的参数寄存器使用模式，
#      推断调用约定(cdecl/stdcall/fastcall/x64 System V)
#   2. 栈帧边界: 从rsp/rbp操作指令推断栈帧大小和局部变量布局
#   3. 函数边界: 组合调用约定指纹+栈帧边界+控制流结构→
#      推断函数入口和出口

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class CallingConvention(Enum):
    X64_SYSV = 'x64_sysv'       # rdi, rsi, rdx, rcx, r8, r9
    X64_WIN = 'x64_win'         # rcx, rdx, r8, r9
    CDECL = 'cdecl'             # 栈传参，调用者清理
    STDCALL = 'stdcall'          # 栈传参，被调用者清理
    FASTCALL = 'fastcall'        # ecx, edx + 栈
    UNKNOWN = 'unknown'


@dataclass
class StackFrame:
    """推断的栈帧布局"""
    func_start: int              # 函数入口地址
    func_end: int                # 函数出口地址
    frame_size: int              # 栈帧总大小(字节)
    saved_regs_offset: int       # 保存的寄存器区偏移
    local_vars_offset: int       # 局部变量区偏移
    local_vars_size: int         # 局部变量区大小
    args_offset: int             # 参数区偏移
    calling_convention: CallingConvention
    has_frame_pointer: bool      # 是否使用rbp帧指针
    confidence: float


class StackFrameDetector:
    """栈帧边界检测器——通过调用约定模式识别。

    检测策略(按优先级):
      1. 函数序言识别: push rbp; mov rbp, rsp → 标准帧指针
      2. rsp调整分析: sub rsp, N → 推断栈帧大小
      3. 参数寄存器使用: 函数入口处对rdi/rsi/rdx的读取→推断调用约定
      4. 尾声识别: leave; ret 或 add rsp, N; ret
    """

    def __init__(self):
        self._prologue_patterns = [
            (re.compile(r'push\s+rbp.*mov\s+rbp,\s*rsp', re.I | re.DOTALL),
             'standard_frame_pointer'),
            (re.compile(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', re.I),
             'stack_adjustment'),
            (re.compile(r'push\s+(r[a-z0-9]+).*push\s+(r[a-z0-9]+)', re.I | re.DOTALL),
             'callee_saved'),
        ]
        self._epilogue_patterns = [
            re.compile(r'leave', re.I),
            re.compile(r'add\s+rsp,\s*(0x[0-9a-f]+|\d+).*ret', re.I | re.DOTALL),
            re.compile(r'pop\s+rbp.*ret', re.I | re.DOTALL),
        ]
        self._param_regs_x64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                                'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d']
        self._param_regs_x86 = ['ecx', 'edx']  # fastcall

    def detect(self,
               instructions: List[str],
               addresses: List[int],
               hint_entry: Optional[int] = None
               ) -> List[StackFrame]:
        """检测指令序列中的所有函数栈帧。

        Args:
            instructions: 汇编指令列表
            addresses: 每条指令的地址
            hint_entry: 提示的入口地址(可选)

        Returns:
            检测到的栈帧列表，按置信度降序
        """
        n = len(instructions)
        if n < 3:
            return []

        frames = []
        i = 0
        while i < n - 2:
            frame = self._try_detect_frame(instructions, addresses, i)
            if frame is not None:
                frames.append(frame)
                # 跳过该函数的指令
                i = max(i + 1, self._find_next_function_start(
                    instructions, addresses, frame.func_end))
            else:
                i += 1

        # 如果提示了入口地址，优先返回匹配的
        if hint_entry is not None:
            frames.sort(key=lambda f: (
                0 if f.func_start == hint_entry else abs(f.func_start - hint_entry),
                -f.confidence))

        frames.sort(key=lambda f: -f.confidence)
        return frames

    def _try_detect_frame(self, instructions, addresses,
                          start_idx: int) -> Optional[StackFrame]:
        """尝试从start_idx位置检测函数栈帧"""
        n = len(instructions)
        if start_idx >= n - 2:
            return None

        addr = addresses[start_idx] if start_idx < len(addresses) else start_idx
        has_fp = False
        frame_size = 0
        saved_regs = 0
        local_size = 0
        convention = CallingConvention.UNKNOWN
        confidence = 0.3  # 基础置信度

        # 检测序言——看前5条指令
        prologue_text = ' '.join(
            instructions[j] for j in range(start_idx, min(start_idx + 5, n)))
        for pattern, ptype in self._prologue_patterns:
            if pattern.search(prologue_text):
                if ptype == 'standard_frame_pointer':
                    has_fp = True
                    confidence += 0.25
                elif ptype == 'stack_adjustment':
                    m = pattern.search(prologue_text)
                    if m:
                        val_str = m.group(1)
                        frame_size = int(val_str, 16) if '0x' in val_str.lower() else int(val_str)
                        confidence += 0.15
                elif ptype == 'callee_saved':
                    saved_regs = len(re.findall(r'push\s+(r\w+)', prologue_text, re.I))
                    confidence += 0.1

        # 检测调用约定——在前10条指令中搜索参数寄存器使用
        param_text = ' '.join(
            instructions[j] for j in range(start_idx, min(start_idx + 10, n)))
        x64_params_used = sum(1 for reg in self._param_regs_x64
                             if re.search(rf'\b{reg}\b', param_text, re.I))
        if x64_params_used >= 2:
            convention = CallingConvention.X64_SYSV
            confidence += 0.15
        elif x64_params_used >= 1:
            convention = CallingConvention.X64_SYSV
            confidence += 0.08
        else:
            x86_params = sum(1 for reg in self._param_regs_x86
                           if re.search(rf'\b{reg}\b', param_text, re.I))
            if x86_params >= 1:
                convention = CallingConvention.FASTCALL
                confidence += 0.08

        # 检测尾声——向后搜索ret/leave
        end_idx = start_idx
        for j in range(start_idx + 2, min(start_idx + 500, n)):
            instr = instructions[j].strip().lower()
            for ep_pat in self._epilogue_patterns:
                if ep_pat.search(instr):
                    end_idx = j
                    confidence += 0.2
                    break
            if end_idx > start_idx:
                break

        if end_idx == start_idx:
            end_idx = min(start_idx + 50, n - 1)

        end_addr = addresses[end_idx] if end_idx < len(addresses) else addr + 100

        # 推断局部变量大小
        if frame_size > 0:
            local_size = max(0, frame_size - saved_regs * 8 - 32)  # 32=返回地址+对齐

        return StackFrame(
            func_start=addr,
            func_end=end_addr,
            frame_size=max(0, frame_size),
            saved_regs_offset=0 if not has_fp else -8,
            local_vars_offset=-(saved_regs * 8 + 8) if has_fp else 0,
            local_vars_size=local_size,
            args_offset=16 if has_fp else (frame_size if frame_size > 0 else 16),
            calling_convention=convention,
            has_frame_pointer=has_fp,
            confidence=min(0.95, confidence))

    def _find_next_function_start(self, instructions, addresses,
                                   current_end: int) -> int:
        """在当前函数结束后查找下一个可能的函数入口"""
        n = len(instructions)
        for j in range(min(current_end + 1, n - 1), min(current_end + 20, n)):
            instr = instructions[j].strip().lower()
            if instr.startswith('push rbp') or instr.startswith('sub rsp'):
                return j
        return min(current_end + 10, n)

    def classify_leaf_function(self, frame: StackFrame,
                                instructions: List[str]) -> bool:
        """判断是否为叶子函数（不调用其他函数）"""
        func_text = ' '.join(instructions[
            self._addr_to_idx(frame.func_start, instructions):
            self._addr_to_idx(frame.func_end, instructions) + 1])
        return 'call ' not in func_text

    def _addr_to_idx(self, addr: int, instructions: List[str]) -> int:
        return 0  # 简化——实际中需要地址→索引的映射表
