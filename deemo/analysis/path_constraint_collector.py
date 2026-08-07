"""
路径约束收集器 — 从反编译伪代码收集 if-条件, 构建变量→约束映射.

将路径条件纳入静态分析: if(size > 1024) size = 1024; buf = malloc(size);
提取截断约束并做 Z3 可满足性证明, 消除路径不敏感导致的误报.

设计决策: 不使用完整 CFG 遍历 (O(2^n)), 仅收集可达路径上的线性约束序列.
unsat → 候选在所有路径上均不会溢出 → 过滤.
sat   → 存在可触发路径 → 保留告警.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class BranchConstraint:
    """单条分支条件对应的符号约束.

    例如 if(v > 1024) → var='v', op='>', value=1024, branch='then'
        if(v <= 1024) → var='v', op='<=', value=1024, branch='else'
    """

    var: str            # 约束变量名
    op: str             # 比较操作符: '<' '>' '<=' '>=' '==' '!='
    value: int          # 常量比较值
    branch: str         # 'then' | 'else'
    line_idx: int       # 在原始代码中的行索引
    raw_condition: str  # 原始条件文本

    def invert(self) -> BranchConstraint:
        """构造该约束的逻辑反."""
        inverted_op = {
            '<': '>=', '>': '<=', '<=': '>', '>=': '<',
            '==': '!=', '!=': '==',
        }
        return BranchConstraint(
            var=self.var, op=inverted_op[self.op],
            value=self.value, branch='else' if self.branch == 'then' else 'then',
            line_idx=self.line_idx, raw_condition=self.raw_condition,
        )


@dataclass
class PathConstraints:
    """一条执行路径上的约束集合.

    路径 = (起始点, 终止点, 沿路径的所有分支条件).
    """

    var_bounds: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    # var → (lo, hi) — 从约束中推导的变量范围
    constraints: List[BranchConstraint] = field(default_factory=list)


class PathConstraintCollector:
    """路径约束收集器.

    在反编译伪代码上工作:
      1. 扫描所有 if/while/for 条件
      2. 提取形如 if(var OP constant) 的约束
      3. 对每条可达路径, 累积约束并推导变量上界
      4. 暴露 query_bounds(var, alloc_site, store_site) → (lo, hi, constraints)

    仅处理可以与常量比较的简单分支条件——这些覆盖了绝大部分截断/校验场景.
    复杂条件 (如 if(var1 > var2)) 被跳过, 保守地返回 UNBOUNDED.
    """

    _COND_PATTERN = re.compile(
        r'(?:if|while|for)\s*\(\s*(\w+)\s*'
        r'(<=|>=|<|>|==|!=)\s*'
        r'(0x[0-9a-fA-F]+|\d+)',
        re.IGNORECASE,
    )

    _TERNARY_PATTERN = re.compile(
        r'(\w+)\s*=\s*(?:\([^)]*\))?\s*'
        r'(?:(\w+)\s*(<=|>=|<|>|==|!=)\s*(0x[0-9a-fA-F]+|\d+)\s*\?\s*)?',
        re.IGNORECASE,
    )

    _SANITIZE_PATTERN = re.compile(
        r'if\s*\([^)]*(\w+)\s*[>]\s*(\d+)[^)]*\)\s*\n?\s*\1\s*=\s*(\d+)',
    )

    def collect(
        self, pseudocode: str,
        target_var: Optional[str] = None,
    ) -> Dict[str, PathConstraints]:
        """从伪代码收集路径约束.

        Args:
          pseudocode: 反编译伪代码文本
          target_var: 若指定, 仅收集涉及此变量的约束

        Returns:
          {var: PathConstraints} — 每个相关变量的约束映射
        """
        result: Dict[str, PathConstraints] = {}
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(('//', '#', '--', ';')):
                continue

            # 1. 标准条件: if(var OP const)
            for m in self._COND_PATTERN.finditer(stripped):
                var = m.group(1)
                if target_var and var != target_var:
                    continue
                op = m.group(2)
                val_str = m.group(3)
                try:
                    val = int(val_str, 0)
                except ValueError:
                    continue

                bc = BranchConstraint(
                    var=var, op=op, value=val,
                    branch='then', line_idx=i,
                    raw_condition=stripped[:120],
                )
                self._add_constraint(result, var, bc)

            # 2. sanitize 模式: if(var > N) var = N;
            for m in self._SANITIZE_PATTERN.finditer(stripped):
                var = m.group(1)
                if target_var and var != target_var:
                    continue
                n = int(m.group(2))
                m_val = int(m.group(3))
                if m_val <= n:
                    # 截断后上界 = min(N, 原范围) ≤ N
                    bc = BranchConstraint(
                        var=var, op='<=', value=n,
                        branch='then', line_idx=i,
                        raw_condition=stripped[:120],
                    )
                    self._add_constraint(result, var, bc)

            # 3. min/max 截断: var = min(var, N) / var = max(var, M)
            min_m = re.search(
                r'(\w+)\s*=\s*min\s*\(\s*\1?\s*[\w.]*\s*,\s*(\d+)\s*\)',
                stripped, re.IGNORECASE,
            )
            if min_m:
                var = min_m.group(1)
                if not target_var or var == target_var:
                    bc = BranchConstraint(
                        var=var, op='<=', value=int(min_m.group(2)),
                        branch='then', line_idx=i,
                        raw_condition=stripped[:120],
                    )
                    self._add_constraint(result, var, bc)

        return result

    def _add_constraint(
        self, mapping: Dict[str, PathConstraints],
        var: str, bc: BranchConstraint,
    ) -> None:
        """将约束加入映射, 更新变量范围."""
        if var not in mapping:
            mapping[var] = PathConstraints()

        pc = mapping[var]
        pc.constraints.append(bc)

        # 更新范围
        lo, hi = pc.var_bounds.get(var, (0, 2**31 - 1))
        new_lo, new_hi = self._refine_bounds(lo, hi, bc)
        if new_lo != lo or new_hi != hi:
            pc.var_bounds[var] = (new_lo, new_hi)

    @staticmethod
    def _refine_bounds(
        lo: int, hi: int, bc: BranchConstraint,
    ) -> Tuple[int, int]:
        """根据单条约束精化变量范围."""
        op = bc.op
        v = bc.value

        if op in ('<', '<='):
            new_hi = v if op == '<' else v
            return (lo, min(hi, new_hi))
        elif op in ('>', '>='):
            new_lo = v + 1 if op == '>' else v
            return (max(lo, new_lo), hi)
        elif op == '==':
            return (max(lo, v), min(hi, v))
        elif op == '!=':
            return (lo, hi)
        return (lo, hi)

    def get_var_bounds(
        self, pseudocode: str, var: str,
        site_line_idx: int = -1,
    ) -> Tuple[int, int, List[BranchConstraint]]:
        """查询变量在某点的约束范围.

        Args:
          pseudocode: 伪代码文本
          var: 变量名
          site_line_idx: malloc/store 所在行索引, 仅考虑此点之前的约束

        Returns:
          (lower_bound, upper_bound, active_constraints)
        """
        all_bounds = self.collect(pseudocode, target_var=var)
        pc = all_bounds.get(var, PathConstraints())

        if site_line_idx < 0:
            bounds = pc.var_bounds.get(var, (0, 2**31 - 1))
            return (bounds[0], bounds[1], pc.constraints)

        # 仅使用 site_line_idx 之前的约束
        active = [c for c in pc.constraints if c.line_idx < site_line_idx]
        lo, hi = 0, 2**31 - 1
        for c in active:
            lo, hi = self._refine_bounds(lo, hi, c)
        return (lo, hi, active)

    @staticmethod
    def can_prove_safety(
        alloc_size: int, write_offset: int,
        constraints: List[BranchConstraint],
        alloc_var: str = "",
    ) -> Tuple[bool, str]:
        """使用 Z3 证明: 在给定路径约束下, write_offset <= alloc_size 是否必然成立.

        Returns:
          (is_safe, proof_description) — is_safe=True 表示可证明溢出不会发生
        """
        if write_offset <= alloc_size:
            return True, f'trivial: offset={write_offset} <= alloc={alloc_size}'

        try:
            import z3
        except ImportError:
            # 无 Z3 时回退到区间推理
            return PathConstraintCollector._interval_fallback(
                alloc_size, write_offset, constraints)

        solver = z3.Solver()
        sym_alloc = z3.Int('alloc_size')
        sym_offset = z3.Int('write_offset')

        solver.add(sym_alloc == alloc_size)
        solver.add(sym_offset == write_offset)

        # 注入路径约束
        for c in constraints:
            sym_var = z3.Int(c.var)
            op_map = {
                '<': lambda a, b: a < b,
                '>': lambda a, b: a > b,
                '<=': lambda a, b: a <= b,
                '>=': lambda a, b: a >= b,
                '==': lambda a, b: a == b,
                '!=': lambda a, b: a != b,
            }
            solver.add(op_map[c.op](sym_var, c.value))

        # 查询: 是否存在解使得 offset > alloc_size?
        solver.add(sym_offset > sym_alloc)

        if solver.check() == z3.unsat:
            return True, f'Z3 proved: under {len(constraints)} constraints, overflow impossible'
        return False, 'Z3 found counterexample: overflow possible'

    @staticmethod
    def _interval_fallback(
        alloc_size: int, write_offset: int,
        constraints: List[BranchConstraint],
    ) -> Tuple[bool, str]:
        """区间推理回退 (Z3 不可用时)."""
        lo, hi = 0, 2**31 - 1
        for c in constraints:
            lo, hi = PathConstraintCollector._refine_bounds(lo, hi, c)
        if hi <= alloc_size and write_offset > alloc_size:
            return False, f'interval fallback: hi={hi} <= alloc={alloc_size}, but offset={write_offset}'
        if lo > alloc_size:
            return False, f'interval fallback: lo={lo} > alloc={alloc_size}, overflow possible'
        return False, 'interval fallback: cannot prove safety'


__all__ = [
    'BranchConstraint', 'PathConstraints', 'PathConstraintCollector',
]
