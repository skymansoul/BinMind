"""整数溢出检测器核心 — 框架 + 栈值收集 + 辅助方法.

创建: 2025-05-12

IntOverflowDetector 是主入口, 协调各检测模式:
  mode_alloc_size: LARGE_IMM64 / TRUNCATION / SUSPICIOUS_SIZE
  mode_arithmetic: SIGNED_IDX / MUL_OVERFLOW / 16-bit wraparound
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ._types import (
    IntOverflowFinding, OverflowType,
    _MAX_UINT32, _SUSPICIOUS_VALS, _ALLOC_FUNCS,
    MOVABS64, MOV_STACK_DWORD, MOV_STACK_WORD, MOV_REG_FROM_STACK,
    ADD_STACK_DWORD, MOV_R64_IMM64, MOV_STACK_EAX, MOV_STACK_AX,
)
from . import _mode_alloc_size as _alloc
from . import _mode_arithmetic as _arith
from . import _mode_shift_wrap as _shift


class IntOverflowDetector:
    """整数溢出检测器 — x86-64 objdump 静态分析.

    八模式检测管线:
      LARGE_IMM64: movabs rax, >2^32 → alloc
      TRUNCATION: 64-bit → mov [mem], eax → malloc
      SIGNED_IDX: INT_MAX + const → signed overflow
      SUSPICIOUS_SIZE: 0xFF... 直接或栈传参
      MUL_OVERFLOW: imul 结果 → alloc
      16-bit wraparound: add + mov WORD PTR [ax] → alloc
      SHL_OVERFLOW: shl N≥5 → cdqe → alloc
      16-bit intent: WORD near 0xFFFF → movzx → arithmetic → alloc
      32-bit ADD wraparound: DWORD params → LEA offset + memcpy size → wrap
    """

    def __init__(self):
        self._stack_vals: Dict[int, int] = {}  # slot_offset → value

# 主入口

    def analyze(self, instructions: List[str],
                function_name: str = "",
                addrs: Optional[List[int]] = None,
                ) -> List[IntOverflowFinding]:
        findings: List[IntOverflowFinding] = []
        self._stack_vals.clear()

        # 第一遍: 收集栈上存储的立即数值 (所有模式共用)
        self._collect_stack_vals(instructions)

        # 模式1-2-4: 分配大小相关检测
        findings += _alloc.detect_large_imm64(
            instructions, function_name, addrs)
        findings += _alloc.detect_truncation(
            instructions, function_name, addrs)
        findings += _alloc.detect_suspicious_size(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)

        # 模式3-5-6-7-8-9: 算术溢出检测
        findings += _arith.detect_signed_idx_overflow(
            instructions, function_name, addrs, self._stack_vals)
        findings += _arith.detect_mul_overflow(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += _arith.detect_16bit_wraparound(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += _arith.detect_32bit_add_wraparound(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += _shift.detect_shl_overflow(
            instructions, function_name, addrs,
            self._find_next_alloc_call)
        findings += _shift.detect_16bit_overflow_intent(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)

        findings.sort(key=lambda f: -f.confidence)
        return findings

# 栈值收集 (第一遍扫描)

    def _collect_stack_vals(self, instructions: List[str]) -> None:
        """第一遍扫描: 收集栈上 DWORD/WORD 存储的常量值."""
        for instr in instructions:
            il = instr.strip().lower()
            m = MOV_STACK_DWORD.match(il)
            if m:
                self._stack_vals[self._offset(m.group(1), m.group(2))] = \
                    self._parse_int(m.group(3))
                continue
            m = MOV_STACK_WORD.match(il)
            if m:
                self._stack_vals[self._offset(m.group(1), m.group(2))] = \
                    self._parse_int(m.group(3))

    def _read_stack_val(self, instructions: List[str],
                         insn_idx: int) -> Optional[int]:
        """从 mov reg, [rbp±N] 指令中读取对应栈槽值."""
        il = instructions[insn_idx].strip().lower()
        m = MOV_REG_FROM_STACK.match(il)
        if not m:
            return None
        return self._stack_vals.get(
            self._offset(m.group(2), m.group(3)))

# 辅助方法

    def _find_next_alloc_call(self, instructions: List[str],
                               start_idx: int) -> Optional[Tuple[str, int]]:
        """从 start_idx 前向查找最近的 alloc 函数调用 (≤30指令)."""
        for j in range(start_idx + 1, min(start_idx + 30, len(instructions))):
            il = instructions[j].strip().lower()
            if 'call' not in il:
                continue
            for f in _ALLOC_FUNCS:
                if f in il:
                    return (f, j)
        return None

    def clear(self) -> None:
        """重置内部状态, 准备下一个函数."""
        self._stack_vals.clear()

# 静态工具

    @staticmethod
    def _offset(sign_str: str, num_str: str) -> int:
        sign = 1 if sign_str == '+' else -1
        return sign * int(num_str, 16 if '0x' in num_str else 10)

    @staticmethod
    def _parse_int(s: str) -> int:
        return int(s, 16 if '0x' in s else 10)
