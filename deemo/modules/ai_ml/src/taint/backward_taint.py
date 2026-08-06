# created: 2026-08-06
# 轻量级后向污点传播——从sink出发沿def-use链反向追踪参数来源
# 理论依据: Mango (USENIX Security 2024) 证明sink-to-source分析比前向传播
# 大幅减少误报——发现路径不可达或值被净化时立即放弃
#
# 核心设计决策:
#   1. 追踪深度限制为5——5步def-use链足以覆盖大部分漏洞路径，
#      更深追踪在静态分析中误报率急剧升高
#   2. 三级分类而非二进制taint/not-taint——CONSTRAINED状态是关键创新，
#      区分"用户输入经过边界检查"(安全)和"用户输入未经检查"(危险)
#   3. 仅追踪寄存器级def-use——不建模内存别名的精确关系，
#      这是性能(线性时间)和精度(处理80%常见模式)的折衷

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class TaintLevel(Enum):
    TAINTED = 'tainted'          # 直接来自用户输入(read/recv/参数)
    CONSTRAINED = 'constrained'  # 经过边界检查/净化后
    CONSTANT = 'constant'        # 编译期常量(安全)
    UNKNOWN = 'unknown'          # 无法确定来源


@dataclass
class TaintResult:
    sink_addr: int               # 危险函数调用地址
    sink_func: str               # 危险函数名(strcpy/memcpy/printf等)
    param_index: int             # 哪个参数被污染(0-indexed)
    taint_level: TaintLevel
    source_origin: str           # 污点来源描述("arg[0] of parent_func")
    trace_length: int            # 追踪步数
    constrained_at: Optional[int] = None  # 在哪个地址被净化


class BackwardTaintEngine:
    """后向污点传播引擎——从危险函数参数沿def-use链反向追踪。

    支持的指令模式(x86_64):
      mov dst, src    → dst被污染当且仅当src被污染
      lea dst, [base] → dst被污染当且仅当base被污染
      add/sub dst, N  → dst保持原有污染状态
      cmp dst, N      → 若dst被污染且N是常量→标记为CONSTRAINED
      call func       → 若func已知是输入源(read/recv)→标记为TAINTED
    """

    # 用户输入源——调用这些函数后返回值/参数被标记为TAINTED
    _INPUT_SOURCES = {'read', 'recv', 'recvfrom', 'fread', 'fgets',
                      'scanf', 'gets', 'ReadFile', 'recvmsg'}
    # 净化操作——检测到这些模式时标记为CONSTRAINED
    _SANITIZERS = {'strlen', 'strnlen', 'sizeof', 'min', 'max',
                   'if', 'cmp', 'test', 'je', 'jne', 'jb', 'ja'}
    _CONST_REGEX = re.compile(r'\b(0x[0-9a-fA-F]+|\d+)\b')

    def __init__(self, max_trace_depth: int = 5):
        self._max_depth = max_trace_depth
        self._reg_pattern = re.compile(
            r'\b(r[a-z0-9]+|e[a-z]{2}|[abcd]x)\b', re.I)

    def trace_param(self,
                    sink_instr_idx: int,
                    param_reg: str,
                    instructions: List[str],
                    func_args: Optional[List[str]] = None
                    ) -> TaintResult:
        """从sink指令的指定参数寄存器反向追踪污点来源。

        Args:
            sink_instr_idx: 危险函数调用指令的索引
            param_reg: 要追踪的参数寄存器名(如'rdi'=第一个参数)
            instructions: 函数内所有指令列表
            func_args: 函数参数名列表(用于判断参数来源)

        Returns:
            TaintResult with taint level and trace
        """
        current_reg = param_reg.lower()
        trace_steps = 0
        constrained = False

        for i in range(sink_instr_idx - 1, max(-1, sink_instr_idx - self._max_depth * 3), -1):
            if i < 0 or i >= len(instructions):
                break
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith(';'):
                continue

            trace_steps += 1

            # mov reg, imm: 常量赋值→CONSTANT (必须在reg-to-reg之前检查)
            m_imm = re.match(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)', instr)
            if m_imm and m_imm.group(1) == current_reg:
                return TaintResult(
                    sink_addr=0, sink_func='', param_index=0,
                    taint_level=TaintLevel.CONSTANT,
                    source_origin=f"constant {m_imm.group(2)}",
                    trace_length=trace_steps)

            # mov dst, src: 若追踪dst, 只匹配两个都是寄存器的mov
            m_mov = re.match(r'mov\s+(\w+),\s*(\w+)', instr)
            if m_mov:
                dst, src = m_mov.group(1), m_mov.group(2)
                # 仅当src看起来像寄存器名(不以数字或0x开头)时才追踪
                if dst == current_reg and not src.startswith(('0x', '0X')) and not src[0].isdigit():
                    current_reg = src
                    continue

            # mov reg, [mem]: 从内存加载→可能来自外部(标记为TAINTED)
            m_load = re.match(r'mov\s+(\w+),\s*\[', instr)
            if m_load and m_load.group(1) == current_reg:
                return TaintResult(
                    sink_addr=0, sink_func='', param_index=0,
                    taint_level=TaintLevel.CONSTRAINED if constrained else TaintLevel.TAINTED,
                    source_origin=f"memory load at instr[{i}]",
                    trace_length=trace_steps,
                    constrained_at=i if constrained else None)

            # lea reg, [rip+offset]: .rodata常量引用→CONSTANT
            if re.match(rf'lea\s+{current_reg},\s*\[rip', instr):
                return TaintResult(
                    sink_addr=0, sink_func='', param_index=0,
                    taint_level=TaintLevel.CONSTANT,
                    source_origin=f"rodata ref at instr[{i}]",
                    trace_length=trace_steps)

            # lea reg, [base+offset]: 地址计算→追踪base
            m_lea = re.match(r'lea\s+(\w+),\s*\[(\w+)', instr)
            if m_lea and m_lea.group(1) == current_reg:
                base = m_lea.group(2)
                if base not in ('rip', 'eip'):  # rip相对寻址已被上面处理
                    current_reg = base
                continue

            # cmp reg, N: 边界检查→标记为CONSTRAINED
            m_cmp = re.match(r'cmp\s+(\w+),\s*(.+)', instr)
            if m_cmp and m_cmp.group(1) == current_reg:
                constrained = True
                continue

            # call input_source: 函数调用输入源→TAINTED
            m_call = re.match(r'call\s+(\w+)', instr)
            if m_call and m_call.group(1) in self._INPUT_SOURCES:
                return TaintResult(
                    sink_addr=0, sink_func='', param_index=0,
                    taint_level=TaintLevel.TAINTED,
                    source_origin=f"input source {m_call.group(1)}",
                    trace_length=trace_steps,
                    constrained_at=i if constrained else None)

            # call sanitizer: 净化函数→CONSTRAINED
            if m_call and m_call.group(1) in self._SANITIZERS:
                constrained = True
                continue

            # add/sub/inc/dec: 算术操作保持污染状态
            if re.match(r'(add|sub|inc|dec|shl|shr|mul)\s+', instr):
                continue

            # xor reg, reg: 清零→CONSTANT
            m_xor = re.match(r'xor\s+(\w+),\s*\1', instr)
            if m_xor and m_xor.group(1) == current_reg:
                return TaintResult(
                    sink_addr=0, sink_func='', param_index=0,
                    taint_level=TaintLevel.CONSTANT,
                    source_origin="zeroed register",
                    trace_length=trace_steps)

        # 追踪深度耗尽→UNKNOWN
        return TaintResult(
            sink_addr=0, sink_func='', param_index=0,
            taint_level=TaintLevel.UNKNOWN,
            source_origin=f"trace exhausted after {trace_steps} steps",
            trace_length=trace_steps,
            constrained_at=None if not constrained else sink_instr_idx)

    def is_vulnerable_sink(self, result: TaintResult) -> bool:
        """判断污点分析结果是否构成真正漏洞。

        仅当参数直接来自用户输入且未经净化时才报告。
        """
        return (result.taint_level == TaintLevel.TAINTED and
                result.constrained_at is None)

    def batch_trace(self,
                    sinks: List[Tuple[int, str, str]],
                    instructions: List[str],
                    func_args: Optional[List[str]] = None
                    ) -> Dict[Tuple[int, str], TaintResult]:
        """对函数内的多个sink批量执行污点追踪。

        Args:
            sinks: [(instr_idx, sink_func, param_reg), ...]
            instructions: 函数指令列表

        Returns:
            {(instr_idx, sink_func): TaintResult}
        """
        results = {}
        for idx, func, reg in sinks:
            results[(idx, func)] = self.trace_param(
                idx, reg, instructions, func_args)
        return results
