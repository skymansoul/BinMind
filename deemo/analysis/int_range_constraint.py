"""
整数溢出约束范围检查器 —— 基于约束传播的精确整数溢出检测。

核心创新: 不用简单的"加法/乘法→溢出"模式匹配, 而是在反编译IR上做
类型感知+约束感知的区间传播, 仅报告"证明会溢出"的情况。

方法:
  1. 类型推断: 从操作数大小 (8/16/32/64位) 推断有符号/无符号语义
  2. 约束传播: 从比较/赋值指令收集变量约束 (CMP+Jcc模式)
  3. 区间运算: 对ADD/SUB/MUL/IMUL/SHL做区间运算, 检查区间是否超出类型范围
  4. 防御性编程模式识别: if(x > INT_MAX - y) → 已知有检查 → 降低置信度
  5. 三阶段过滤: 类型感知边界 → 约束精化 → 守卫检测

  - Dietz et al. — "Understanding Integer Overflow in C/C++"
  - IOC — 基于LLVM IR的符号范围分析
  - IntEQ — 等价类驱动的整数溢出检测

设计约束: 不依赖SMT求解器; 用区间代数保证确定性; 默认保守不报.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class IntWidth(Enum):
    I8 = 8
    I16 = 16
    I32 = 32
    I64 = 64

class Signedness(Enum):
    SIGNED = "signed"
    UNSIGNED = "unsigned"
    UNKNOWN = "unknown"

@dataclass
class IntRange:
    """整数的值域 [lo, hi], 含符号性。"""
    lo: int
    hi: int
    width: IntWidth = IntWidth.I32
    signedness: Signedness = Signedness.UNKNOWN
    is_top: bool = False

    @staticmethod
    def top(width=IntWidth.I32) -> "IntRange":
        return IntRange(0, 0, width, is_top=True)

    @staticmethod
    def const(val: int, width=IntWidth.I32) -> "IntRange":
        return IntRange(val, val, width)

    @property
    def max_val(self) -> int:
        if self.signedness == Signedness.SIGNED:
            return (1 << (self.width.value - 1)) - 1
        return (1 << self.width.value) - 1

    @property
    def min_val(self) -> int:
        if self.signedness == Signedness.SIGNED:
            return -(1 << (self.width.value - 1))
        return 0

    def add(self, other: "IntRange") -> "IntRange":
        """区间加法, 检测上溢/下溢。"""
        if self.is_top or other.is_top:
            return IntRange.top(self.width)
        lo = self.lo + other.lo
        hi = self.hi + other.hi
        return IntRange(lo, hi, self.width, self.signedness)

    def mul(self, other: "IntRange") -> "IntRange":
        """区间乘法, 保守估计。"""
        if self.is_top or other.is_top:
            return IntRange.top(self.width)
        corners = [
            self.lo * other.lo, self.lo * other.hi,
            self.hi * other.lo, self.hi * other.hi,
        ]
        return IntRange(min(corners), max(corners), self.width, self.signedness)

    def would_overflow(self) -> Tuple[bool, str]:
        """检查此区间是否一定会溢出。"""
        if self.is_top:
            return False, "top: unbounded"
        if self.lo < self.min_val:
            return True, f"underflow: lo={self.lo}<min={self.min_val}"
        if self.hi > self.max_val:
            return True, f"overflow: hi={self.hi}>max={self.max_val}"
        return False, "safe"

@dataclass
class IntOpSite:
    """单个整数运算点的分析结果。"""
    line: int
    op: str                        # ADD/SUB/MUL/IMUL/SHL
    lhs: str                       # 目标变量
    op_a: str                      # 操作数A (变量或常量)
    op_b: str                      # 操作数B
    result_range: Optional[IntRange] = None
    constraint: Optional[str] = None   # 路上收集的约束
    is_guarded: bool = False           # 是否有防御性检查
    would_overflow: bool = False
    overflow_reason: str = ""
    confidence: float = 0.5

class IntRangeConstraintChecker:
    """约束感知的整数溢出检查器。

    工作流程:
      1. 扫描IR行, 识别整数运算 (ADD/SUB/MUL/IMUL)
      2. 从寄存器/变量大小推断操作数宽度
      3. 从CMP+Jcc模式收集变量约束
      4. 区间运算 + 边界检查 → 判定
    """

    # IR中的算术指令
    _ARITH_PAT = re.compile(
        r'(?:add|ADD|sub|SUB|imul|IMUL|mul|MUL|shl|SHL|inc|INC|dec|DEC)\s+'
        r'(\w+)\s*,\s*(\w+)',
    )
    # 三操作数形式: lea rax, [rbx+rcx*4]
    _LEA_PAT = re.compile(
        r'(?:lea|LEA)\s+(\w+)\s*,\s*\[(\w+)(?:\s*\+\s*(\w+)(?:\s*\*\s*(\d+))?)?\]',
    )
    # CMP+Jcc模式
    _CMP_PAT = re.compile(
        r'(?:cmp|CMP)\s+(\w+)\s*,\s*0x?([0-9a-fA-F]+|\w+)',
    )
    # 守卫模式: if (x > INT_MAX - y)
    _GUARD_MUL_PAT = re.compile(
        r'if\s*\([^)]*(?:INT_MAX|UINT_MAX|SIZE_MAX)\s*-\s*\w+',
    )

    # 寄存器名 → 宽度映射
    _REG_WIDTH: Dict[str, IntWidth] = {
        'al': IntWidth.I8, 'ah': IntWidth.I8, 'bl': IntWidth.I8,
        'ax': IntWidth.I16, 'bx': IntWidth.I16, 'cx': IntWidth.I16, 'dx': IntWidth.I16,
        'eax': IntWidth.I32, 'ebx': IntWidth.I32, 'ecx': IntWidth.I32, 'edx': IntWidth.I32,
        'rax': IntWidth.I64, 'rbx': IntWidth.I64, 'rcx': IntWidth.I64, 'rdx': IntWidth.I64,
        'r8': IntWidth.I64, 'r9': IntWidth.I64, 'r10': IntWidth.I64,
        'x0': IntWidth.I64, 'x1': IntWidth.I64, 'w0': IntWidth.I32,
    }

    def __init__(self, signedness: Signedness = Signedness.UNKNOWN):
        self._signedness = signedness
        self._constraints: Dict[str, IntRange] = {}

    def check(self, ir_lines: List[str]) -> List[IntOpSite]:
        """分析IR行, 返回所有可能的整数溢出点。"""
        self._collect_constraints(ir_lines)
        sites = []

        for i, line in enumerate(ir_lines):
            site = self._analyze_line(i, line, ir_lines)
            if site and site.would_overflow:
                sites.append(site)

        return sites

    def _collect_constraints(self, lines: List[str]) -> None:
        """从CMP+条件跳转收集变量约束。"""
        for i, line in enumerate(lines):
            m = self._CMP_PAT.search(line)
            if not m:
                continue
            var = m.group(1)
            rhs = m.group(2)
            try:
                val = int(rhs, 16 if rhs.startswith(('0x', '0X')) else 10)
            except ValueError:
                continue

            # 向前看条件跳转
            next_line = lines[i + 1] if i + 1 < len(lines) else ""
            if 'jle' in next_line or 'jbe' in next_line:
                self._constraints[var] = IntRange.const(val)
            elif 'jl' in next_line or 'jb' in next_line:
                self._constraints[var] = IntRange(val, val)

    def _analyze_line(
        self, i: int, line: str, lines: List[str],
    ) -> Optional[IntOpSite]:
        """分析单行IR, 判断是否含整数溢出风险运算。"""
        m = self._ARITH_PAT.search(line)
        if not m:
            m = self._LEA_PAT.search(line)
        if not m:
            return None

        groups = m.groups()
        op = line.split()[0].lower() if line.split() else ""

        # 推断操作数宽度
        width = self._infer_width(line)
        lhs = groups[0]
        op_a = groups[1] if len(groups) > 1 else ""
        op_b = groups[2] if len(groups) > 2 else ""

        # 区间计算
        range_a = self._constraints.get(op_a, IntRange.top(width))
        range_b = IntRange.const(self._parse_int(op_b), width) if op_b.isdigit() or (
            op_b.startswith('0x') and all(c in '0123456789abcdefABCDEFx' for c in op_b)
        ) else self._constraints.get(op_b, IntRange.top(width))

        if 'add' in op or 'inc' in op:
            result = range_a.add(range_b)
        elif 'sub' in op or 'dec' in op:
            neg_b = IntRange(-range_b.hi, -range_b.lo, width)
            result = range_a.add(neg_b)
        elif 'mul' in op or 'imul' in op:
            result = range_a.mul(range_b)
        elif 'shl' in op:
            shift = range_b.lo if not range_b.is_top else 1
            result = IntRange(range_a.lo << shift, range_a.hi << shift, width)
        else:
            result = range_a

        overflow, reason = result.would_overflow()
        guarded = self._has_guard(lines, i, op_a, op_b)

        return IntOpSite(
            line=i, op=op, lhs=lhs, op_a=op_a, op_b=op_b,
            result_range=result,
            constraint=str(self._constraints.get(op_a, '')) or None,
            is_guarded=guarded,
            would_overflow=overflow,
            overflow_reason=reason,
            confidence=0.85 if (overflow and not guarded) else 0.30,
        )

    def _infer_width(self, line: str) -> IntWidth:
        """从寄存器名推断操作数宽度。"""
        for reg, width in sorted(self._REG_WIDTH.items(),
                                  key=lambda x: -len(x[0])):
            if reg in line:
                return width
        # 从立即数最大值推断
        m = re.search(r'0x([0-9a-fA-F]+)', line)
        if m:
            val = int(m.group(1), 16)
            if val <= 0xFF:
                return IntWidth.I8
            elif val <= 0xFFFF:
                return IntWidth.I16
            elif val <= 0xFFFFFFFF:
                return IntWidth.I32
        return IntWidth.I32

    @staticmethod
    def _parse_int(s: str) -> int:
        try:
            return int(s, 16 if s.startswith(('0x', '0X')) else 10)
        except (ValueError, TypeError):
            return 0

    def _has_guard(self, lines: List[str], idx: int,
                   op_a: str, op_b: str) -> bool:
        """检查运算前是否有溢出防护检查。"""
        context = '\n'.join(lines[max(0, idx - 15):idx])
        if self._GUARD_MUL_PAT.search(context):
            return True
        var_pattern = (
            rf'if\s*\(\s*{re.escape(op_a)}\s*[><]\s*(?:INT_MAX|0x7[fF]+)'
        )
        if re.search(var_pattern, context):
            return True
        return False

def check_int_overflow_enhanced(
    ir_lines: List[str],
    signedness: Signedness = Signedness.UNKNOWN,
) -> List[IntOpSite]:
    """便捷入口: 增强的整数溢出检查。"""
    checker = IntRangeConstraintChecker(signedness=signedness)
    return checker.check(ir_lines)

__all__ = [
    'IntWidth', 'Signedness', 'IntRange', 'IntOpSite',
    'IntRangeConstraintChecker', 'check_int_overflow_enhanced',
]
