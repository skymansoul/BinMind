"""
路径守卫窄化 — 把分支条件转化为写大小的区间上界。

误报的高频来源是"机械比较 write_size > alloc_size", 而忽略
write_size 在到达写点前已被分支守卫 (guard) 约束。典型模式:
  if (len < 64) memcpy(buf, src, len);   // len < 64 已证明
  for (i = 0; i < N; i++) buf[i] = x;    // i < N 隐含上界
本模块从 IR 行中提取 (cmp reg, imm; jcc) 对, 把守卫转化为对
变量的区间约束, 并在写点处按"路径经过守卫"的保守语义收窄。

  保守原则: 只使用必定成立的守卫 (guard 成立才执行写, 或循环
  上界比较), 不推断守卫不成立的分支。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .alloc_aware_interval import Interval


@dataclass(frozen=True)
class Guard:
    """单个路径守卫: 变量 var 满足 cond 与常量 bound."""
    var: str
    cond: str        # '<' '>' '<=' '>=' '==' '!='
    bound: int
    pc: int

    def interval(self) -> Interval:
        """守卫约束对应的区间."""
        if self.cond == '<':
            return Interval(0, self.bound - 1)
        if self.cond == '<=':
            return Interval(0, self.bound)
        if self.cond == '>':
            return Interval(self.bound + 1, Interval.top().hi)
        if self.cond == '>=':
            return Interval(self.bound, Interval.top().hi)
        if self.cond == '==':
            return Interval(self.bound, self.bound)
        return Interval.top()  # '!=' 不提供上界信息


_RE_CMP = re.compile(
    r'cmp\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$', re.IGNORECASE)
_RE_CMP_REV = re.compile(
    r'cmp\s+(0x[0-9a-fA-F]+|\d+)\s*,\s*(\w+)\s*$', re.IGNORECASE)
_RE_JCC_LT = re.compile(r'\b(jl|jb|jle|jbe)\b', re.IGNORECASE)
_RE_JCC_GT = re.compile(r'\b(jg|ja|jge|jae)\b', re.IGNORECASE)
_RE_JCC_EQ = re.compile(r'\b(je|jz|jne|jnz)\b', re.IGNORECASE)
_RE_LOOP_HEAD = re.compile(r'\b(jmp\s+\w+|loop)\b', re.IGNORECASE)
_RE_STORE = re.compile(
    r'(?:store|mov).*?\[(\w+)\s*\+\s*(\d+)\].*?', re.IGNORECASE)
_RE_LOOP_CMP = re.compile(
    r'\bcmp\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\b', re.IGNORECASE)


@dataclass
class GuardSet:
    """写点可达守卫集合 — 用于收窄写大小区间."""
    upper_bounds: Dict[str, int] = field(default_factory=dict)
    lower_bounds: Dict[str, int] = field(default_factory=dict)

    def narrow(self, var: str, iv: Interval) -> Interval:
        ub = self.upper_bounds.get(var)
        lb = self.lower_bounds.get(var)
        if ub is not None:
            iv = iv.meet(Interval(0, ub))
        if lb is not None:
            iv = iv.meet(Interval(lb, Interval.top().hi))
        return iv


def collect_guards(ir_lines: List[str],
                   start_pc: int, end_pc: int) -> List[Guard]:
    """在 [start_pc, end_pc] 窗口内收集 cmp+jcc 守卫对."""
    guards: List[Guard] = []
    pending: List[Tuple[str, str, int, int]] = []  # (var, cmp, bound, pc)
    for i in range(start_pc, min(end_pc, len(ir_lines))):
        line = ir_lines[i]
        m = _RE_CMP.search(line)
        if m:
            var, bound = m.group(1), int(m.group(2), 0)
            pending.append((var, 'cmp', bound, i))
            continue
        m = _RE_CMP_REV.search(line)
        if m:
            bound, var = int(m.group(1), 0), m.group(2)
            pending.append((var, 'cmp_rev', bound, i))
            continue
        if not pending:
            continue
        # 语义: Intel 语法 cmp reg, imm; jcc target。
        #   jge/jg/ja/jae: 跳转条件为 reg >= imm, fall-through 是
        #     reg < imm → 上界收窄 (守卫保护写点的典型模式)。
        #   jle/jl/jb/jbe: fall-through 是 reg > imm → 仅下界, 无抑制价值。
        #   cmp_rev (AT&T 或 imm 在前) 方向相反。
        if _RE_JCC_GT.search(line):
            var, rev, bound, pc = pending.pop()
            cond = '<' if not rev else '>'
            guards.append(Guard(var, cond, bound, pc))
        elif _RE_JCC_LT.search(line):
            var, rev, bound, pc = pending.pop()
            cond = '>' if not rev else '<'
            guards.append(Guard(var, cond, bound, pc))
        elif _RE_JCC_EQ.search(line):
            var, _, bound, pc = pending.pop()
            guards.append(Guard(var, '==', bound, pc))
    return guards


# TODO: 循环上界存于内存槽 (如 [rbp-0x10]) 时当前仅取立即数,
# 栈槽间接上界 (libwebp 场景) 需寄存器值流回溯支持
def loop_bound_from_region(ir_lines: List[str],
                           anchor_pc: int, window: int = 40,
                           backward: bool = False) -> Optional[int]:
    """从锚点提取循环上界.

    策略: 在 jmp 回边之前的最后一次 cmp reg, imm, 且 imm 在
    (0, 1e6) 区间内, 视为循环上界候选。backward=True 时从
    锚点向前搜索 (写点在循环体内, 循环头 cmp 在写点之前)。
    """
    last_cmp: Optional[Tuple[str, int]] = None
    if backward:
        lo = max(0, anchor_pc - window)
        for i in range(anchor_pc - 1, lo - 1, -1):
            line = ir_lines[i]
            m = _RE_LOOP_CMP.search(line)
            if m:
                try:
                    v = int(m.group(2), 0)
                except ValueError:
                    continue
                if 0 < v < 1000000:
                    last_cmp = (m.group(1), v)
                    break
        if last_cmp is None:
            return None
        return last_cmp[1]
    saw_jmp_back = False
    for i in range(anchor_pc, min(anchor_pc + window, len(ir_lines))):
        line = ir_lines[i]
        m = _RE_LOOP_CMP.search(line)
        if m:
            try:
                v = int(m.group(2), 0)
            except ValueError:
                continue
            if 0 < v < 1000000:
                last_cmp = (m.group(1), v)
        if _RE_LOOP_HEAD.search(line):
            saw_jmp_back = True
    if last_cmp is None:
        return None
    var, bound = last_cmp
    return bound if saw_jmp_back else bound