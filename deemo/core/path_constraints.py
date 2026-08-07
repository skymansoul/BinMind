"""
路径敏感约束收集 —— 从条件分支中提取数值约束并用于求精抽象状态。

DDAI-ASR 系统的第二层: 在反编译伪代码的每个条件分支处收集约束。
例如:
  if (size > 1024) { size = 1024; }
  buf = malloc(size);
  memcpy(buf, src, size);

  若不追踪 if 约束, 分析到 memcpy 时 size 的范围是 (-∞, +∞)
  → 误报。收集约束后 size ∈ [0, 1024], 配合分配器模型可精确判定。

约束表示: 使用 Presburger 算术子集 —— 线性不等式 a·x ≤ b。

与 SMT 方案的差异:
  - 不调用 Z3/CVC4, 直接用区间代数求解 —— 速度优先
  - 仅追踪 size 变量, 不做全程序符号执行
  - 若区间推理不足以判定 → 保守保留 (宁可误报, 不漏报)

  - Cousot "Modular Static Analysis" —— 路径条件的区间传播
  - Cheng et al. —— 跨域稀疏抽象执行中的约束传递
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class ConstraintOp(Enum):
    LE = "<="
    LT = "<"
    GE = ">="
    GT = ">"
    EQ = "=="
    NE = "!="

@dataclass
class LinearConstraint:
    """a·x op b 形式的线性约束。"""
    var: str
    op: ConstraintOp
    bound: int
    is_signed: bool = True
    context_line: int = -1  # 伪代码中的行号

    def to_interval(self) -> Tuple[Optional[int], Optional[int]]:
        """转换为区间 [low, high] (None = 无界)。"""
        if self.op == ConstraintOp.LE:
            return (None, self.bound)
        elif self.op == ConstraintOp.LT:
            return (None, self.bound - 1)
        elif self.op == ConstraintOp.GE:
            return (self.bound, None)
        elif self.op == ConstraintOp.GT:
            return (self.bound + 1, None)
        elif self.op == ConstraintOp.EQ:
            return (self.bound, self.bound)
        else:  # NE —— 不贡献区间约束
            return (None, None)

@dataclass
class PathCondition:
    """一条路径上的约束集合。

    每个分支点产生一个 PathCondition node:
      条件 if(x < N): true分支 → x ∈ (-∞, N-1], false分支 → x ∈ [N, +∞)
    """
    constraints: List[LinearConstraint] = field(default_factory=list)
    parent: Optional["PathCondition"] = None
    branch_direction: bool = True  # True = then分支, False = else分支

    def resolve(self, var: str) -> Tuple[Optional[int], Optional[int]]:
        """解析变量 var 在整个约束链上的区间。"""
        lo, hi = None, None
        current = self
        while current is not None:
            for c in current.constraints:
                if c.var == var:
                    clo, chi = c.to_interval()
                    if clo is not None:
                        lo = max(lo, clo) if lo is not None else clo
                    if chi is not None:
                        hi = min(hi, chi) if hi is not None else chi
            current = current.parent
        return (lo, hi)

class ConstraintExtractor:
    """从反编译伪代码中提取数值约束。

    支持的 C 语法模式:
      if (var op constant) { ... }
      if (var > N) var = M;
      if (var < N) return;
      var = min(var, N);
      var = max(var, M);
      var = (cond) ? true_val : false_val;
    """

    _IF_COND = re.compile(
        r'if\s*\(\s*(\w+)\s*(>=?|<=?|==|!=)\s*(-?\d+)\s*\)'
    )
    _IF_CLAMP = re.compile(
        r'if\s*\(\s*(\w+)\s*([><]=?)\s*(\d+)\s*\)\s*\n?\s*\1\s*=\s*(\d+)\s*;'
    )
    _MINMAX = re.compile(
        r'(\w+)\s*=\s*(min|max|MIN|MAX)\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)'
    )
    _TERNARY = re.compile(
        r'(\w+)\s*=\s*\(?\s*(\w+)\s*([><=!]=)\s*(-?\d+)\s*\)?\s*\?\s*(-?\w+)\s*:\s*(-?\w+)'
    )
    _ASSERT = re.compile(
        r'(?:assert|BUG|BUG_ON)\s*\(\s*(\w+)\s*([><=!]=)\s*(-?\d+)\s*\)'
    )

    def extract(self, pseudocode: str) -> List[LinearConstraint]:
        """从伪代码中提取所有线性约束。"""
        constraints: List[LinearConstraint] = []
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            constraints.extend(self._match_if(stripped, i))
            constraints.extend(self._match_minmax(stripped, i))
            constraints.extend(self._match_ternary(stripped, i))
            constraints.extend(self._match_assert(stripped, i))

        return constraints

    def extract_for_var(self, pseudocode: str, target_var: str,
                        before_line: int = -1) -> List[LinearConstraint]:
        """只提取与 target_var 相关且在 before_line 之前的约束。"""
        all_c = self.extract(pseudocode)
        return [
            c for c in all_c
            if c.var == target_var
            and (before_line < 0 or c.context_line < before_line)
        ]

    def _match_if(self, line: str, line_no: int) -> List[LinearConstraint]:
        results = []
        for m in self._IF_COND.finditer(line):
            var, op_str, val_str = m.group(1), m.group(2), m.group(3)
            op = self._parse_op(op_str)
            if op:
                results.append(LinearConstraint(
                    var=var, op=op, bound=int(val_str), context_line=line_no,
                ))
        return results

    def _match_minmax(self, line: str, line_no: int) -> List[LinearConstraint]:
        results = []
        for m in self._MINMAX.finditer(line):
            lhs, func, var, val_str = m.group(1), m.group(2), m.group(3), m.group(4)
            val = int(val_str)
            if func in ('min', 'MIN'):
                # lhs = min(var, N) → lhs <= N
                results.append(LinearConstraint(
                    var=lhs, op=ConstraintOp.LE, bound=val, context_line=line_no,
                ))
            else:
                # lhs = max(var, N) → lhs >= N
                results.append(LinearConstraint(
                    var=lhs, op=ConstraintOp.GE, bound=val, context_line=line_no,
                ))
        return results

    def _match_ternary(self, line: str, line_no: int) -> List[LinearConstraint]:
        results = []
        for m in self._TERNARY.finditer(line):
            lhs = m.group(1)
            true_val = m.group(5)
            false_val = m.group(6)
            for val_str in (true_val, false_val):
                if val_str and val_str.lstrip('-').isdigit():
                    results.append(LinearConstraint(
                        var=lhs, op=ConstraintOp.LE,
                        bound=int(val_str), context_line=line_no,
                    ))
        return results

    def _match_assert(self, line: str, line_no: int) -> List[LinearConstraint]:
        results = []
        for m in self._ASSERT.finditer(line):
            var, op_str, val_str = m.group(1), m.group(2), m.group(3)
            op = self._parse_op(op_str)
            if op:
                results.append(LinearConstraint(
                    var=var, op=op, bound=int(val_str), context_line=line_no,
                ))
        return results

    @staticmethod
    def _parse_op(s: str) -> Optional[ConstraintOp]:
        s = s.strip()
        for op in ConstraintOp:
            if op.value == s:
                return op
        return None

def refine_interval_with_constraints(
    var: str,
    initial_lo: Optional[int],
    initial_hi: Optional[int],
    constraints: List[LinearConstraint],
) -> Tuple[Optional[int], Optional[int]]:
    """用约束列表求精变量的区间。

    返回求精后的 (low, high)。
    若约束使区间矛盾 (low > high), 返回 (None, None) 表示不可行。
    """
    lo, hi = initial_lo, initial_hi
    for c in constraints:
        if c.var != var:
            continue
        clo, chi = c.to_interval()
        if clo is not None:
            lo = max(lo, clo) if lo is not None else clo
        if chi is not None:
            hi = min(hi, chi) if hi is not None else chi

    if lo is not None and hi is not None and lo > hi:
        return (None, None)
    return (lo, hi)

__all__ = [
    'ConstraintOp', 'LinearConstraint', 'PathCondition',
    'ConstraintExtractor', 'refine_interval_with_constraints',
]
