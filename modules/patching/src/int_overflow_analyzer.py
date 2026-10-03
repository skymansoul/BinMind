# 整数溢出检测深度强化 — 值范围传播 + 溢出条件检查
"""整数溢出检测器 — 基于值范围传播的溢出可行性分析。

旧方法(fix_distiller): 正则模式匹配 add+mul→call malloc，不分析溢出是否可达。

新方法：
  1. 对参与算术运算的操作数做值范围估计
  2. 若两个操作数的值范围上界之和超过类型宽度 → 可能溢出
  3. 若溢出结果直接用于 malloc(size) → 标记为高危(IO2BO: IntOverflow→BufferOverflow)

值范围来源：
  - 立即数: [val, val]
  - 用户输入: [0, MAX_INT]
  - 经过cmp约束: [0, bound]
  - 算术结果: [a.low+b.low, a.high+b.high] (加法)

区间域建模方法参照 IntTracer。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

_log = logging.getLogger(__name__)


@dataclass
class ValueRange:
    """操作数的值范围。"""
    low: int = -2**63
    high: int = 2**63 - 1
    is_tainted: bool = False
    bit_width: int = 32            # 默认32位整数


@dataclass
class OverflowSite:
    """一个潜在的整数溢出点。"""
    line_index: int = 0
    operation: str = ""            # add / sub / mul / imul / shl
    left_operand: str = ""
    right_operand: str = ""
    left_range: ValueRange = field(default_factory=ValueRange)
    right_range: ValueRange = field(default_factory=ValueRange)
    result_range: ValueRange = field(default_factory=ValueRange)
    may_overflow: bool = False
    # IO2BO: 溢出结果是否直接流向malloc
    flows_to_alloc: bool = False
    alloc_line: int = -1
    is_dangerous: bool = False


@dataclass
class IntOverflowReport:
    """整数溢出检测报告。"""
    function_name: str = ""
    sites: List[OverflowSite] = field(default_factory=list)
    total_sites: int = 0
    overflow_count: int = 0        # 可能溢出的点
    io2bo_count: int = 0           # 溢出流向malloc的点
    fp_candidates: int = 0         # 确定不溢出的点

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total': self.total_sites,
            'overflow': self.overflow_count,
            'io2bo': self.io2bo_count,
            'fp': self.fp_candidates,
        }


# 值范围传播器

class ValueRangePropagator:
    """在基本指令块内传播操作数的值范围。

    来源追踪:
      - 立即数 → [val, val]
      - call read/recv → rax ∈ [0, MAX_INT], tainted
      - mov reg, src → 继承src的范围
      - add reg, imm → [reg.low+imm, reg.high+imm]
      - and reg, mask → [0, mask], 去污
      - cmp reg, N; ja .err → reg ∈ [0, N] (若err走向abort)
    """

    _SOURCE_PATTERNS = re.compile(
        r'\bcall\s+(read|recv|recvfrom|fgets|scanf|getenv)\b', re.I)

    def propagate(self, asm_lines: List[str]) -> Dict[str, ValueRange]:
        """逐指令传播值范围，返回最终的寄存器值域映射。"""
        regs = defaultdict(ValueRange)

        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower().replace(',', ' ')

            # 用户输入源 → rax 范围变为全范围
            if self._SOURCE_PATTERNS.search(stripped):
                regs['rax'] = ValueRange(low=0, high=2**31 - 1, is_tainted=True)
                continue

            parts = stripped.split()
            if len(parts) < 2:
                continue
            mnemonic = parts[0]

            # mov dst, imm → 精确值
            m = re.search(r'\bmov\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', stripped)
            if m:
                dst = m.group(1)
                v = m.group(2)
                val = int(v, 16) if v.lower().startswith('0x') else int(v)
                regs[dst] = ValueRange(low=val, high=val, bit_width=32)
                continue

            # mov dst, src_reg → 继承范围
            m = re.search(r'\bmov\s+(\w+),?\s*(\w+)', stripped)
            if m:
                dst, src = m.group(1), m.group(2)
                if src in regs:
                    regs[dst] = regs[src]
                continue

            # add dst, imm → 平移范围
            m = re.search(r'\badd\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', stripped)
            if m:
                dst = m.group(1); v = m.group(2)
                delta = int(v, 16) if v.lower().startswith('0x') else int(v)
                if dst in regs:
                    r = regs[dst]
                    regs[dst] = ValueRange(
                        low=r.low + delta, high=r.high + delta,
                        is_tainted=r.is_tainted, bit_width=r.bit_width)
                continue

            # and dst, mask → 收窄到 [0, mask]
            m = re.search(r'\band\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', stripped)
            if m:
                dst = m.group(1); v = m.group(2)
                mask = int(v, 16) if v.lower().startswith('0x') else int(v)
                if dst in regs:
                    r = regs[dst]
                    regs[dst] = ValueRange(low=0, high=mask, is_tainted=False,
                                           bit_width=r.bit_width)
                continue

            # cmp dst, N; ja .err → 隐含上界
            m = re.search(r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', stripped)
            if m and self._has_abort_after(asm_lines, i):
                dst = m.group(1); v = m.group(2)
                bound = int(v, 16) if v.lower().startswith('0x') else int(v)
                if dst in regs and bound < regs[dst].high:
                    r = regs[dst]
                    regs[dst] = ValueRange(low=r.low, high=bound,
                                           is_tainted=False, bit_width=r.bit_width)
                continue

        return dict(regs)

    def _has_abort_after(self, asm: List[str], cmp_idx: int) -> bool:
        for j in range(cmp_idx + 1, min(cmp_idx + 6, len(asm))):
            if re.search(r'\bcall\s+(abort|exit)\b', asm[j].strip().lower()):
                return True
        return False


# 溢出检测器

class IntOverflowDetector:
    """基于值范围的整数溢出检测。"""

    _ARITH_OPS = re.compile(r'\b(add|sub|mul|imul|shl)\b', re.I)
    _ALLOC_FUNCS = re.compile(r'\bcall\s+(malloc|calloc|realloc)\b', re.I)

    def __init__(self):
        self._propagator = ValueRangePropagator()

    def detect(self, asm_lines: List[str],
               function_name: str = "") -> IntOverflowReport:
        report = IntOverflowReport(function_name=function_name)
        reg_ranges = self._propagator.propagate(asm_lines)

        for i, line in enumerate(asm_lines):
            m = self._ARITH_OPS.search(line.strip().lower())
            if not m:
                continue

            op = m.group(1)
            dst, src = self._parse_arith_operands(line)
            if not dst or not src:
                continue

            left_r = reg_ranges.get(dst, ValueRange())
            right_r = reg_ranges.get(src, ValueRange())
            # 若src是立即数
            imm_m = re.search(r'(0x[0-9a-f]+|\d+)', src)
            if imm_m:
                v = imm_m.group(1)
                val = int(v, 16) if v.lower().startswith('0x') else int(v)
                right_r = ValueRange(low=val, high=val)

            may_overflow = False
            if op == 'add':
                may_overflow = (left_r.high + right_r.high) > (2**left_r.bit_width - 1)
            elif op == 'mul' or op == 'imul':
                may_overflow = (left_r.high * right_r.high) > (2**left_r.bit_width - 1)
            elif op == 'shl':
                may_overflow = (left_r.high << min(right_r.high, 63)) > (2**left_r.bit_width - 1)

            site = OverflowSite(
                line_index=i, operation=op,
                left_operand=dst, right_operand=src,
                left_range=left_r, right_range=right_r,
                may_overflow=may_overflow,
                result_range=ValueRange(
                    low=left_r.low + right_r.low,
                    high=min(left_r.high + right_r.high, 2**63 - 1)))

            # IO2BO检查：溢出结果是否流向malloc
            if may_overflow and dst in reg_ranges:
                for j in range(i + 1, min(i + 15, len(asm_lines))):
                    if self._ALLOC_FUNCS.search(asm_lines[j].strip().lower()):
                        site.flows_to_alloc = True
                        site.alloc_line = j
                        site.is_dangerous = True
                        break

            report.sites.append(site)
            report.total_sites += 1
            if may_overflow:
                report.overflow_count += 1
            else:
                report.fp_candidates += 1
            if site.is_dangerous:
                report.io2bo_count += 1

        return report

    def _parse_arith_operands(self, inst: str) -> Tuple[str, str]:
        parts = inst.strip().lower().replace(',', ' ').split()
        if len(parts) >= 3:
            return parts[1].rstrip(','), parts[2]
        return '', ''
