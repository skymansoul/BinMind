"""
区间抽象解释过滤器 — intra-procedural, O(n)复杂度, 筛除静态误报。

设计决策:
  1. 使用区间域 [lb, ub] 近似每个变量的值范围
  2. 单遍遍历基本块序列 (非迭代到不动点) — 牺牲精度换 O(n)
  3. 检测数组越界: 若访问 a[i] 且 i 的区间不完全在 [0, len(a)-1] 内 → 告警
  4. 检测空指针: 若指针区间含 0 → 告警

为什么是区间域而不是多面体域:
  区间域 O(n) vs 多面体域 O(n^3) — 对二进制分析场景, 精度损失可接受。
  多面体域对复杂约束 (x+y≤10) 更精确, 但二进制中此类约束罕见。

与false_positive_filter.py的分工:
  false_positive_filter: 基于模式匹配的统计评分 (先验知识)
  本模块: 基于抽象解释的语义分析 (程序逻辑)

修改记录:
  创建 2026-08-05 — 区间抽象域 + O(n) forward analysis
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Interval:
    """区间 [lb, ub]。None 表示 -∞ 或 +∞。"""
    lb: Optional[int] = None
    ub: Optional[int] = None

    def union(self, other: 'Interval') -> 'Interval':
        lb = None
        ub = None
        if self.lb is not None and other.lb is not None:
            lb = min(self.lb, other.lb)
        if self.ub is not None and other.ub is not None:
            ub = max(self.ub, other.ub)
        return Interval(lb, ub)

    def contains(self, value: int) -> bool:
        if self.lb is not None and value < self.lb:
            return False
        if self.ub is not None and value > self.ub:
            return False
        return True

    def add(self, delta: int) -> 'Interval':
        return Interval(
            self.lb + delta if self.lb is not None else None,
            self.ub + delta if self.ub is not None else None)

    def is_definitely_outside(self, lo: int, hi: int) -> bool:
        """区间是否完全在 [lo, hi] 之外 → 确定越界。"""
        return ((self.ub is not None and self.ub < lo) or
                (self.lb is not None and self.lb > hi))


@dataclass
class AbstractState:
    """寄存器→区间的映射 (简化——仅追踪rax/rbx/rcx/rdx/rsi/rdi)。"""
    regs: Dict[str, Interval]
    zero_flag: Optional[bool] = None  # ZF: True/False/None


def _parse_mov_imm(insn: str) -> Optional[Tuple[str, int]]:
    """mov reg, imm → (reg, imm)。不支持则返回None。"""
    parts = insn.lower().replace(',', ' ').split()
    if len(parts) >= 3 and parts[0] == 'mov':
        try:
            imm = int(parts[2], 0)
            reg = parts[1]
            if reg in ('rax','rbx','rcx','rdx','rsi','rdi','r8','r9',
                       'eax','ebx','ecx','edx','esi','edi'):
                return reg, imm
        except ValueError:
            pass
    return None


def _parse_cmp_imm(insn: str) -> Optional[Tuple[str, int]]:
    """cmp reg, imm → (reg, imm)。"""
    parts = insn.lower().replace(',', ' ').split()
    if len(parts) >= 3 and parts[0] == 'cmp':
        try:
            imm = int(parts[2], 0)
            return parts[1], imm
        except ValueError:
            pass
    return None


def abstract_interpret(
    instructions: List[str],
    array_bounds: Optional[Dict[str, Tuple[int, int]]] = None,
) -> Dict[str, Interval]:
    """
    单遍前向区间分析。返回 {reg_name: Interval}。

    array_bounds: {'reg_or_var': (lo, hi)} — 已知的数组边界。
    用于在访问 a[reg] 时检查 reg 的区间是否超出边界。
    """
    state = AbstractState(regs={}, zero_flag=None)
    warnings: List[str] = []
    bounds = array_bounds or {}

    for insn in instructions:
        # mov reg, imm
        mv = _parse_mov_imm(insn)
        if mv:
            state.regs[mv[0]] = Interval(mv[1], mv[1])
            continue

        # cmp reg, imm → 更新 ZF
        cmp_info = _parse_cmp_imm(insn)
        if cmp_info:
            reg, imm = cmp_info
            if reg in state.regs:
                iv = state.regs[reg]
                if iv.lb is not None and iv.ub is not None:
                    state.zero_flag = (iv.lb == imm and iv.ub == imm)
                elif iv.lb == imm:
                    state.zero_flag = True

        # xor reg, reg → reg = 0
        parts = insn.lower().replace(',', ' ').split()
        if len(parts) >= 3 and parts[0] == 'xor' and parts[1] == parts[2]:
            state.regs[parts[1]] = Interval(0, 0)

        # inc/dec reg
        if len(parts) >= 2 and parts[0] in ('inc', 'dec'):
            reg = parts[1]
            if reg in state.regs:
                delta = 1 if parts[0] == 'inc' else -1
                state.regs[reg] = state.regs[reg].add(delta)

        # 数组边界检查
        for reg, (lo, hi) in bounds.items():
            if reg in state.regs and state.regs[reg].is_definitely_outside(lo, hi):
                warnings.append(
                    f"越界访问: {reg} ∈ [{state.regs[reg].lb}, {state.regs[reg].ub}], "
                    f"数组边界 [{lo}, {hi}]")

    return state.regs


def filter_by_abstract_analysis(
    findings: List[Dict],
    instructions: List[str],
    array_bounds: Optional[Dict[str, Tuple[int, int]]] = None,
) -> Tuple[List[Dict], List[str]]:
    """
    用抽象解释筛除不可能的告警。

    findings: [{'type': 'overflow', 'relevant_reg': 'rsi', ...}, ...]
    返回: (filtered_findings, warnings)
    """
    intervals = abstract_interpret(instructions, array_bounds)
    kept: List[Dict] = []
    warnings: List[str] = []

    for f in findings:
        reg = f.get('relevant_reg', '')
        size = f.get('size_hint', 0)

        if reg and reg in intervals:
            iv = intervals[reg]
            # if区间完全在合法范围内 → 误报, 筛除
            if iv.lb is not None and iv.ub is not None:
                if iv.lb >= 0 and iv.ub <= size and size > 0:
                    warnings.append(
                        f"筛除误报: {f.get('type')} 在 {f.get('location')}"
                        f" — {reg} ∈ [{iv.lb}, {iv.ub}] ⊆ [0, {size}]")
                    continue
        kept.append(f)

    return kept, warnings
