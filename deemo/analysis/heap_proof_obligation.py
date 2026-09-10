"""
堆安全证明义务生成与验证 — 双向约束传播 (Bidirectional Proof Obligation).

判定框架:
  对每个 (alloc, write) 对, 生成命题 P: write_offset + write_size ≤ alloc_effective_size
  若P在收集到的路径约束下恒成立 → SAFE (消除FP); 若存在反例 → 保留为候选溢出.

方法: 前向收集size变量约束 + 后向从write点追溯offset约束 → 在alloc点"交汇"验证.
不依赖SMT求解器, 使用区间代数+符号减法做保守近似 (复杂度 O(n*m)).

参考: Proof-carrying code, BIXIE, CSA.

数据类型 → heap_proof_types.py (ProofVerdict, SizeConstraint, ProofObligation)
"""


import re
from typing import Dict, List, Tuple

from analysis.heap_proof_types import (
    ProofObligation, ProofVerdict, SizeConstraint,
)


class HeapProofEngine:
    """堆安全证明义务引擎.

    两阶段:
      Phase A (前向): 扫描IR, 为所有相关变量收集约束
      Phase B (验证): 对每个(alloc,write)对, 检查约束是否可证安全
    """

    # 约束收集正则
    _GUARD_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(<|<=|>|>=|==)\s*(\d+)\s*\)', re.IGNORECASE)
    _ASSIGN_CONST_RE = re.compile(r'(\w+)\s*=\s*(\d+)\s*;')
    _MIN_MAX_RE = re.compile(
        r'(\w+)\s*=\s*(min|max|MIN|MAX)\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)', re.IGNORECASE)
    _LOOP_BOUND_RE = re.compile(
        r'for\s*\(\s*\w+\s+(\w+)\s*=\s*0\s*;\s*\1\s*[<]\s*(\d+)\s*;', re.IGNORECASE)
    _CLAMP_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|>=)\s*(\d+)\s*\)\s*(\w+)\s*=\s*(\d+)\s*;', re.IGNORECASE)

    def __init__(self):
        self._constraints: Dict[str, List[SizeConstraint]] = {}
        self._var_defs: Dict[str, int] = {}  # var → definition line

    def collect_constraints(self, ir_lines: List[str]) -> Dict[str, List[SizeConstraint]]:
        """Phase A: 扫描IR, 收集所有变量的数值约束.

        返回 {var_name: [SizeConstraint, ...]}.
        """
        self._constraints.clear()
        self._var_defs.clear()

        for i, line in enumerate(ir_lines):
            stripped = line.strip()

            # 赋值: var = const
            m = self._ASSIGN_CONST_RE.search(stripped)
            if m:
                var, val = m.group(1), int(m.group(2))
                self._add_constraint(var, SizeConstraint(
                    var=var, lo=val, hi=val, source_line=i,
                    constraint_type='assignment'))
                self._var_defs[var] = i
                continue

            # 守卫条件: if (var < N) / if (var <= N) / if (var > N)
            m = self._GUARD_RE.search(stripped)
            if m:
                var, op, val_str = m.group(1), m.group(2), m.group(3)
                val = int(val_str)
                if op == '<':
                    self._add_constraint(var, SizeConstraint(
                        var=var, hi=val - 1, source_line=i,
                        constraint_type='guard'))
                elif op == '<=':
                    self._add_constraint(var, SizeConstraint(
                        var=var, hi=val, source_line=i,
                        constraint_type='guard'))
                elif op == '>':
                    self._add_constraint(var, SizeConstraint(
                        var=var, lo=val + 1, source_line=i,
                        constraint_type='guard'))
                elif op == '>=':
                    self._add_constraint(var, SizeConstraint(
                        var=var, lo=val, source_line=i,
                        constraint_type='guard'))
                elif op == '==':
                    self._add_constraint(var, SizeConstraint(
                        var=var, lo=val, hi=val, source_line=i,
                        constraint_type='guard'))
                continue

            # min/max 约束: var = min(other, N) → var ≤ N
            m = self._MIN_MAX_RE.search(stripped)
            if m:
                var, fn = m.group(1), m.group(2).lower()
                val = int(m.group(4))
                if fn == 'min':
                    self._add_constraint(var, SizeConstraint(
                        var=var, hi=val, source_line=i,
                        constraint_type='assignment'))
                else:  # max
                    self._add_constraint(var, SizeConstraint(
                        var=var, lo=val, source_line=i,
                        constraint_type='assignment'))
                self._var_defs[var] = i
                continue

            # 循环边界: for (i = 0; i < N; i++)
            m = self._LOOP_BOUND_RE.search(stripped)
            if m:
                var, bound = m.group(1), int(m.group(2))
                self._add_constraint(var, SizeConstraint(
                    var=var, lo=0, hi=bound - 1, source_line=i,
                    constraint_type='loop_bound'))
                continue

            # 钳制模式: if (x > MAX) x = MAX;
            m = self._CLAMP_RE.search(stripped)
            if m:
                var, op, threshold_str, clamped_var, clamped_val_str = (
                    m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
                threshold = int(threshold_str)
                clamped_val = int(clamped_val_str)
                if var == clamped_var and threshold == clamped_val:
                    self._add_constraint(var, SizeConstraint(
                        var=var, hi=clamped_val, source_line=i,
                        constraint_type='guard'))

        return self._constraints

    def _add_constraint(self, var: str, c: SizeConstraint) -> None:
        """添加约束, 与已有约束取交集 (缩小范围)."""
        if var not in self._constraints:
            self._constraints[var] = []
        existing = self._constraints[var]
        for e in existing:
            if e.constraint_type == c.constraint_type and e.source_line == c.source_line:
                e.lo = max(e.lo, c.lo)
                e.hi = min(e.hi, c.hi)
                return
        existing.append(c)

    def get_effective_range(self, var: str) -> Tuple[int, int]:
        """获取变量在所有约束下的有效取值范围.

        返回 (lo, hi). 若无约束, lo=-inf, hi=+inf.
        """
        if var not in self._constraints or not self._constraints[var]:
            return (-(2**31), 2**31 - 1)
        lo = -(2**31)
        hi = 2**31 - 1
        for c in self._constraints[var]:
            lo = max(lo, c.lo)
            hi = min(hi, c.hi)
        return (lo, hi)

    def prove_obligation(
        self,
        alloc_size: int,
        write_offset: int,
        write_size: int,
        offset_var: str = "",
        size_var: str = "",
        alias_offset: int = 0,
    ) -> ProofObligation:
        """Phase B: 尝试验证单个(alloc, write)对的证明义务.

        P: write_offset + write_size ≤ max_chunk_size(alloc_size_range)
        若约束可证P恒成立 → PROVED_SAFE; 可证不成立 → PROVED_OVERFLOW; 否则 INCONCLUSIVE.
        """
        obl = ProofObligation(
            alloc_var=size_var,
            alloc_size_expr=str(alloc_size),
            write_var=offset_var,
            write_offset=write_offset,
            write_size=write_size,
            offset_var=offset_var,
            size_var=size_var,
        )

        # 确定有效分配大小的范围
        alloc_lo = alloc_size
        alloc_hi = alloc_size
        if size_var and size_var in self._constraints:
            s_lo, s_hi = self.get_effective_range(size_var)
            if alloc_size <= 0:
                alloc_lo = s_lo
                alloc_hi = s_hi
            else:
                alloc_lo = max(alloc_size, s_lo) if s_lo > -(2**31) else alloc_size
                alloc_hi = min(alloc_size, s_hi) if s_hi < 2**31 - 1 else alloc_size
        if size_var:
            obl.size_constraints = self._constraints.get(size_var, [])

        # 考虑分配器chunk开销
        chunk_lo = _min_chunk_size(alloc_lo)
        chunk_hi = _max_chunk_size(alloc_hi)

        # 确定写入结束位置的偏移范围
        write_end_lo = write_offset
        write_end_hi = write_offset
        if write_offset < 0 and offset_var:
            off_lo, off_hi = self.get_effective_range(offset_var)
            if off_lo > -(2**31):
                write_end_lo = off_lo
            if off_hi < 2**31 - 1:
                write_end_hi = off_hi

        if write_size > 0:
            write_end_lo += write_size
            write_end_hi += write_size
        elif write_size < 0:
            write_end_hi = 2**31 - 1  # 无界写入

        if offset_var:
            obl.offset_constraints = self._constraints.get(offset_var, [])

        # 考虑别名偏移
        write_end_lo += alias_offset
        write_end_hi += alias_offset

        # 核心判定
        if write_end_hi <= chunk_lo:
            obl.verdict = ProofVerdict.PROVED_SAFE
            obl.proof_detail = (
                f"write_end_hi({write_end_hi}) ≤ chunk_lo({chunk_lo}): "
                f"所有路径上写入在分配边界内"
            )
        elif write_end_lo > chunk_hi:
            obl.verdict = ProofVerdict.PROVED_OVERFLOW
            obl.proof_detail = (
                f"write_end_lo({write_end_lo}) > chunk_hi({chunk_hi}): "
                f"即使最乐观估计仍溢出"
            )
        else:
            obl.verdict = ProofVerdict.INCONCLUSIVE
            obl.proof_detail = (
                f"write_end=[{write_end_lo},{write_end_hi}] ∩ "
                f"chunk=[{chunk_lo},{chunk_hi}]: 区间重叠, 无法判定"
            )

        return obl


def _min_chunk_size(request_size: int) -> int:
    """glibc ptmalloc2 最小可用chunk大小 (request2size下界)."""
    if request_size <= 0:
        return 0
    aligned = ((request_size + 15) // 16) * 16
    return max(32, aligned)


def _max_chunk_size(request_size: int) -> int:
    """glibc ptmalloc2 最大可用chunk大小 (含对齐填充)."""
    if request_size <= 0:
        return 2**31 - 1
    aligned = ((request_size + 15) // 16) * 16
    return max(32, aligned + 15)  # 最多额外15字节对齐填充


def prove_heap_safety(
    ir_lines: List[str],
    alloc_size: int,
    write_offset: int,
    write_size: int,
    offset_var: str = "",
    size_var: str = "",
    alias_offset: int = 0,
) -> Tuple[ProofVerdict, str, float]:
    """便捷接口: 一键完成约束收集+证明义务验证.

    返回 (verdict, detail, confidence_adjustment).
    """
    engine = HeapProofEngine()
    engine.collect_constraints(ir_lines)
    obl = engine.prove_obligation(
        alloc_size, write_offset, write_size,
        offset_var, size_var, alias_offset,
    )

    if obl.verdict == ProofVerdict.PROVED_SAFE:
        return obl.verdict, obl.proof_detail, -0.60
    elif obl.verdict == ProofVerdict.PROVED_OVERFLOW:
        return obl.verdict, obl.proof_detail, +0.20
    else:
        return obl.verdict, obl.proof_detail, 0.0
