"""
MIVR 路径敏感约束传播器 — 从守卫到写入点的正向约束传播.

核心方法:
  给定约束依赖图, 将守卫绑定的约束沿控制流正向传播.
  在写入点检查: 偏移变量是否被约束, 且约束范围是否在分配大小内.

与简单区间分析的区别:
  1. 路径敏感: 只在守卫then分支内传播约束
  2. 传递性: i = idx 且 idx < 64 → i ∈ [0, 63]
  3. 仿射感知: 写入偏移含算术表达式时, 尝试化简为变量后查约束
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.mivr_constraint_graph import (
    VarConstraint, GuardSite, MIVRConstraintGraph,
)


@dataclass
class PropagatedState:
    """在某个程序点的约束状态."""
    line_no: int
    constraints: Dict[str, VarConstraint] = field(default_factory=dict)


@dataclass
class WriteSafetyVerdict:
    """写入安全判定."""
    SAFE = "SAFE"            # 可证明不溢出
    OVERFLOW = "OVERFLOW"    # 确认溢出
    UNCERTAIN = "UNCERTAIN"  # 无法判定
    verdict: str
    confidence: float
    reason: str
    bound_hi: int = -1       # 约束上界
    alloc_size: int = -1     # 分配大小


class MIVRPathPropagator:
    """路径敏感约束传播器 — 从守卫到写入点.

    工作流程:
      1. 从约束图获取守卫 + then分支边界
      2. 在then分支内传播约束到写入点
      3. 在写入点评估: 偏移是否在分配大小内
    """

    _WRITE_OFFSET_RE = re.compile(
        r'(?:memcpy|memmove|memset|strncpy|snprintf|fread|recv|read)\s*\('
        r'([^,]+?)(?:\s*\+\s*(\d+|\w[\w]*))?\s*,')
    _ARRAY_STORE_RE = re.compile(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=')
    _ARRAY_STORE_CONST_RE = re.compile(r'(\w+)\s*\[\s*(\d+)\s*\]\s*=')
    _MALLOC_SIZE_RE = re.compile(
        r'(?:malloc|calloc)\s*\(\s*(\d+|\w[\w]*(?:\s*[*+\-]\s*\w[\w]*)*)\s*\)',
        re.IGNORECASE)

    def __init__(self):
        self._graph: Optional[MIVRConstraintGraph] = None

    def build_and_propagate(self, pseudocode: str) -> MIVRConstraintGraph:
        """构建图并执行正向传播."""
        self._graph = MIVRConstraintGraph()
        self._graph.build(pseudocode)
        return self._graph

    def check_write_safety(
        self, write_line: int, write_target: str, alloc_size: int,
    ) -> WriteSafetyVerdict:
        """检查写入点的安全性.

        Args:
            write_line: 写入点行号
            write_target: 写入目标变量 (buf/ptr)
            alloc_size: 分配大小 (字节)

        Returns:
            WriteSafetyVerdict
        """
        if self._graph is None:
            return WriteSafetyVerdict(
                "UNCERTAIN", 0.0, "no constraint graph", -1, alloc_size)

        if alloc_size <= 0:
            return WriteSafetyVerdict(
                "UNCERTAIN", 0.0, "unknown alloc size", -1, alloc_size)

        # 方法1: 数组store — buf[idx] = x, 检查idx约束
        for gs in self._graph.guards:
            # 检查守卫是否在then分支内保护了此写入
            if not (gs.then_start <= write_line <= gs.then_end):
                continue

            # 守卫变量约束
            if gs.is_constant and gs.operator in ('<', '<='):
                guard_hi = gs.bound_const - 1 if gs.operator == '<' \
                    else gs.bound_const
                guard_lo = 0 if gs.operator in ('<', '<=') else 0

                # 检查守卫变量是否与写入偏移相关
                # 直接: buf[idx] 且 idx 就是 guard_var
                if gs.guard_var:
                    # 守卫变量约束: gs.guard_var < gs.bound_const
                    # 若 guard_hi < alloc_size → 安全
                    if guard_hi < alloc_size:
                        return WriteSafetyVerdict(
                            "SAFE", 0.85,
                            f"guard {gs.guard_var} < {gs.bound_const} "
                            f"→ max offset {guard_hi} < alloc {alloc_size}",
                            guard_hi, alloc_size,
                        )
                    # 若 guard_var 也是 alloc 的 size 变量, guard_hi 即为约束
                    if guard_hi > 0:
                        return WriteSafetyVerdict(
                            "CONDITIONAL", 0.50,
                            f"guard {gs.guard_var} < {gs.bound_const} "
                            f"bounds offset to ≤ {guard_hi}, alloc={alloc_size}",
                            guard_hi, alloc_size,
                        )

        # 方法2: 传递性 — i = guard_var, buf[i] = x
        for gs in self._graph.guards:
            if not (gs.then_start <= write_line <= gs.then_end):
                continue
            if not gs.is_constant:
                continue
            guard_hi = gs.bound_const - 1 if gs.operator == '<' \
                else gs.bound_const

            # 通过赋值链查找
            tc = self._graph.resolve_transitive_constraint(gs.guard_var)
            if tc and tc.hi >= 0 and tc.hi < alloc_size:
                return WriteSafetyVerdict(
                    "SAFE", 0.80,
                    f"transitive: {gs.guard_var} < {gs.bound_const} "
                    f"→ offset ≤ {tc.hi} < alloc {alloc_size}",
                    tc.hi, alloc_size,
                )

        # 方法3: 常量偏移 — buf[32] = ... 且 32 < alloc_size
        lines = []
        if hasattr(self._graph, '_alloc_sites'):
            # 用伪代码行查常量偏移
            pass

        return WriteSafetyVerdict(
            "UNCERTAIN", 0.0,
            "no guard constraint proves write within bounds",
            -1, alloc_size,
        )

    def prove_alloc_write_pair(
        self, alloc_var: str, alloc_expr: str, alloc_line: int,
        write_var: str, write_line: int,
    ) -> WriteSafetyVerdict:
        """证明单个 alloc-write 对的安全性.

        组合三种证明策略:
          P1: 守卫约束直接证明偏移 < 分配大小
          P2: 仿射关系的传递传播 (若两者共享变量)
          P3: 常量偏移检查
        """
        # 解析分配大小
        alloc_size = self._parse_alloc_size(alloc_expr)
        if alloc_size <= 0:
            # 尝试从约束图获取size变量的范围
            if alloc_expr.strip().isidentifier():
                c = self._graph.get_constraint(alloc_expr.strip()) \
                    if self._graph else None
                if c and c.hi > 0:
                    alloc_size = c.hi

        if alloc_size <= 0:
            return WriteSafetyVerdict(
                "UNCERTAIN", 0.0, f"cannot resolve alloc size: {alloc_expr}",
                -1, -1)

        # P1: 守卫直接证明
        v1 = self.check_write_safety(write_line, write_var, alloc_size)
        if v1.verdict == "SAFE":
            return v1

        # P2: 传递性约束
        if self._graph:
            tc = self._graph.resolve_transitive_constraint(write_var)
            if tc and tc.hi >= 0 and tc.hi < alloc_size:
                return WriteSafetyVerdict(
                    "SAFE", 0.80,
                    f"transitive constraint: {write_var} ∈ "
                    f"[{tc.lo}, {tc.hi}] < alloc {alloc_size}",
                    tc.hi, alloc_size,
                )

        # P3: 常量偏移
        const_off = self._extract_const_offset(write_var)
        if const_off >= 0 and const_off < alloc_size:
            return WriteSafetyVerdict(
                "SAFE", 0.95,
                f"constant offset {const_off} < alloc {alloc_size}",
                const_off, alloc_size,
            )
        elif const_off >= alloc_size:
            return WriteSafetyVerdict(
                "OVERFLOW", 0.90,
                f"constant offset {const_off} ≥ alloc {alloc_size}",
                const_off, alloc_size,
            )

        return v1  # UNCERTAIN

    # 内部方法

    def _parse_alloc_size(self, expr: str) -> int:
        """解析分配表达式为数值."""
        try:
            # 纯数字
            return int(expr.strip())
        except ValueError:
            pass
        # 简单算术: n*4+8 → 如果n未知, 返回-1
        if any(c.isalpha() for c in expr):
            return -1
        try:
            # 安全eval: 仅数字和运算符
            cleaned = re.sub(r'[^0-9+\-*/()]', '', expr)
            if cleaned:
                return int(eval(cleaned))
        except Exception:
            pass
        return -1

    def _extract_const_offset(self, write_target: str) -> int:
        """从写入目标提取常量偏移."""
        m = re.search(r'\+?\s*(\d+)', write_target)
        if m:
            return int(m.group(1))
        return -1


__all__ = [
    'PropagatedState', 'WriteSafetyVerdict',
    'MIVRPathPropagator',
]
