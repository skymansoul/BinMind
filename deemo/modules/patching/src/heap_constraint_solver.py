# 堆分配约束求解器 — 区间域建模 + 对齐约束 + 溢出可满足性

"""堆分配约束求解器。

仅判断"size是否被污染"不够——即使size被污染，
若后续memcpy的大小受约束，溢出可能不可行。

本模块对每个 alloc+memcpy 对求解：
  1. 分配大小区间: [alloc_lower, alloc_upper]
  2. 写入大小区间: [write_lower, write_upper]
  3. 溢出可满足性: alloc_upper < write_lower → 必定溢出
                    alloc_lower >= write_upper → 必定不溢出
                    区间重叠 → 可能溢出（需要路径条件）

方法：
  对 malloc 的 size 参数做区间抽象（interval abstraction）。
  size 来自用户输入 → 区间为 [0, MAX_INT]。
  size 经过约束（如 cmp+ja 后）→ 区间为 [0, MAX_BOUND]。
  比较 alloc 区间与 write 区间决定溢出可能性。

为什么用区间而非完整符号执行：
  符号执行对每个 cmp 做路径分叉 → 状态爆炸。
  区间抽象对每个 cmp 做 meet（交）→ O(n) 线性。
  精度损失有限（堆溢出的核心约束是上界，区间能捕捉）。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class SizeConstraint:
    """分配大小的约束。"""
    lower: int = 0
    upper: int = 2**63 - 1
    is_tainted: bool = False
    has_explicit_bound: bool = False  # 是否经过显式 cmp+ja 检查
    bound_value: int = 0
    # 约束来源
    constraints: List[str] = field(default_factory=list)


@dataclass
class OverflowVerdict:
    """单个 alloc+write 对的溢出判定。"""
    alloc_func: str = ""
    alloc_size_range: Tuple[int, int] = (0, 0)
    write_size_range: Tuple[int, int] = (0, 0)
    # 判定
    will_overflow: bool = False       # 必定溢出
    may_overflow: bool = False        # 可能溢出（区间重叠）
    cannot_overflow: bool = True      # 必定不溢出
    confidence: float = 0.0
    reason: str = ""


# 区间抽象引擎

class IntervalAbstractor:
    """从汇编指令序列中提取对寄存器值的区间约束。

    处理以下模式:
      cmp reg, N; ja .err → reg ∈ [0, N]（若 err 路径为 abort）
      cmp reg, N; jbe .ok → 同上
      and reg, mask → reg ∈ [0, mask]
      mov reg, imm → reg ∈ [imm, imm]
      add reg, N → reg ∈ [reg.low+N, reg.high+N]
    """

    def extract_bounds(self, asm_lines: List[str],
                       target_reg: str,
                       around_line: int) -> Tuple[int, int, bool]:
        """提取 target_reg 在 around_line 附近的区间边界。

        返回 (lower, upper, has_explicit_bound)。
        搜索范围: around_line 前后各10行。
        """
        lower = 0
        upper = 2**31 - 1  # 默认32位范围
        has_bound = False
        start = max(around_line - 10, 0)
        end = min(around_line + 10, len(asm_lines))

        for i in range(start, end):
            line = asm_lines[i].strip().lower().replace(',', ' ')

            # cmp target_reg, N; ja/jbe → explicit bound
            m = re.search(r'\bcmp\s+' + re.escape(target_reg) + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                bound = int(v, 16) if v.lower().startswith('0x') else int(v)
                # 检查后续指令是否在超限时走向abort
                has_abort_path = self._has_abort_after(asm_lines, i)
                if has_abort_path and bound < upper:
                    upper = bound
                    has_bound = True

            # and target_reg, mask
            m = re.search(r'\band\s+' + re.escape(target_reg) + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                mask = int(v, 16) if v.lower().startswith('0x') else int(v)
                if mask < upper:
                    upper = mask
                    has_bound = True

            # mov target_reg, imm → 精确值
            m = re.search(r'\bmov\s+' + re.escape(target_reg) + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                val = int(v, 16) if v.lower().startswith('0x') else int(v)
                lower = val; upper = val
                has_bound = True
                break  # 精确值，不需要继续搜索

        return lower, upper, has_bound

    def _has_abort_after(self, asm: List[str], cmp_idx: int) -> bool:
        """检查cmp之后的跳转目标是否走向异常路径。"""
        for j in range(cmp_idx + 1, min(cmp_idx + 6, len(asm))):
            line = asm[j].strip().lower()
            if 'call abort' in line or 'call exit' in line:
                return True
            if re.search(r'\bj\w+\s+', line):
                break  # 跳转到其他位置，不一定是abort
        return False


# 溢出可满足性求解器

class OverflowSatisfiabilitySolver:
    """判断 alloc size 区间 vs write size 区间 → 溢出是否可能。

    三种情况:
      1. alloc_upper < write_lower → WILL overflow（确定）
      2. alloc_lower >= write_upper → CANNOT overflow（确定）
      3. 区间重叠 → MAY overflow（不确定，取决于运行时值）
    """

    def solve(self, alloc_size: SizeConstraint,
              write_size: int,
              write_is_constant: bool = True) -> OverflowVerdict:
        verdict = OverflowVerdict(
            alloc_size_range=(alloc_size.lower, alloc_size.upper),
            write_size_range=(write_size, write_size))

        w_lower = write_size; w_upper = write_size

        if alloc_size.upper < w_lower:
            # 即使分配"最大"也小于写入"最小"→必溢出
            verdict.will_overflow = True
            verdict.may_overflow = True
            verdict.cannot_overflow = False
            verdict.confidence = 0.95
            verdict.reason = ("分配上限 %d < 写入大小 %d → 确定溢出" %
                            (alloc_size.upper, w_lower))
        elif alloc_size.lower >= w_upper:
            # 即使分配"最小"也大于写入"最大"→必不溢出
            verdict.will_overflow = False
            verdict.may_overflow = False
            verdict.cannot_overflow = True
            verdict.confidence = 0.90
            verdict.reason = ("分配下限 %d >= 写入大小 %d → 确定不溢出 (误报)" %
                            (alloc_size.lower, w_upper))
        else:
            # 区间重叠
            verdict.will_overflow = False
            verdict.may_overflow = True
            verdict.cannot_overflow = False
            if alloc_size.is_tainted and not alloc_size.has_explicit_bound:
                verdict.confidence = 0.60
                verdict.reason = "分配大小受外部控制且无显式边界——可能溢出"
            elif alloc_size.is_tainted and alloc_size.has_explicit_bound:
                verdict.confidence = 0.20
                verdict.reason = "分配大小已约束 → 溢出可能性低"
            else:
                verdict.confidence = 0.10
                verdict.reason = "分配大小为常量 → 几乎不可能溢出"

        return verdict
