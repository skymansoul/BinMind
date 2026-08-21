"""
路径条件追踪器 v2 — 从分支守卫中提取线性约束并精化 strided interval.

v1 (已替换) 只做基本块级守卫标记; v2 将路径条件以 LinearConstraint
形式传递到 strided interval domain, 实现约束驱动的区间精化.

核心改进:
  - 解析 if(cond) 为 ConstraintOp + 常量, 而非简单标记 "有守卫"
  - 应用约束到 StridedInterval: hi 截断, lo 提升, EQ 收缩到单点
  - 路径段 (PathSegment) 模型: 每条路径持有独立的约束集合和可达行号集合
  - 集成到 heap shape model: 约束影响 allocation size range → overflow 判定

与现有 guard_inference.py 的关系:
  guard_inference 做"是否存在守卫"的二元判断; 本模块做"守卫如何精化区间"的定量分析.
  两者互补, 不是替代关系.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_unbounded,
)

class ConstraintOp(Enum):
    LE = "le"   # var <= N
    LT = "lt"   # var < N
    GE = "ge"   # var >= N
    GT = "gt"   # var > N
    EQ = "eq"   # var == N
    NE = "ne"   # var != N

@dataclass
class LinearConstraint:
    """线性约束: variable ⋈ constant. 用于精化 strided interval."""
    variable: str
    op: ConstraintOp
    constant: int

@dataclass
class PathSegment:
    """路径段: 一组约束 + 可达的 malloc/store 行号集合."""
    segment_id: str
    constraints: List[LinearConstraint] = field(default_factory=list)
    reachable_alloc_lines: Set[int] = field(default_factory=set)
    reachable_store_lines: Set[int] = field(default_factory=set)
    is_infeasible: bool = False

class PathConditionTracker:
    """路径条件追踪器 v2 — 约束提取 + 区间精化 + 路径级溢出判定.

    不重建完整CFG — 在伪代码文本上做结构化模式匹配,
    在速度和精度间取折中.
    """

    _IF_COND_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>=|<=|>|<|==|!=)\s*((?:0x)?[0-9a-fA-F]+)\s*\)',
    )
    _MINMAX_RE = re.compile(
        r'(\w+)\s*=\s*(?:min|MAX)\s*\(\s*(\w+)\s*,\s*((?:0x)?[0-9a-fA-F]+)\s*\)',
    )

    _ALLOC_RE = re.compile(
        r'(?:(\w+)\s*=\s*)?(?:malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        re.IGNORECASE,
    )
    _WRITE_RE = re.compile(
        r'(?:memcpy|memmove|strcpy|strncpy|sprintf)\s*\(([^)]+)\)',
        re.IGNORECASE,
    )

    _OP_MAP = {
        "<=": ConstraintOp.LE, "<": ConstraintOp.LT,
        ">=": ConstraintOp.GE, ">": ConstraintOp.GT,
        "==": ConstraintOp.EQ, "!=": ConstraintOp.NE,
    }

    def extract_constraints(self, pseudocode: str,
                            target_var: str = "") -> List[LinearConstraint]:
        """从伪代码中提取所有线性数值约束."""
        constraints = []
        for m in self._IF_COND_RE.finditer(pseudocode):
            var = m.group(1)
            if target_var and var != target_var:
                continue
            op = self._OP_MAP.get(m.group(2))
            if op is None:
                continue
            try:
                val = int(m.group(3), 0)
            except (ValueError, TypeError):
                continue
            constraints.append(LinearConstraint(var, op, val))

        # min/max 也产生约束
        for m in self._MINMAX_RE.finditer(pseudocode):
            var = m.group(1)
            if target_var and var != target_var:
                continue
            try:
                val = int(m.group(3), 0)
            except (ValueError, TypeError):
                continue
            constraints.append(LinearConstraint(var, ConstraintOp.LE, val))

        return constraints

    def refine_interval(self, interval: StridedInterval,
                        constraints: List[LinearConstraint]) -> StridedInterval:
        """用约束列表精化 strided interval — 收缩 lo/hi 边界."""
        lo, hi, stride = interval.lo, interval.hi, interval.stride
        is_unbounded = (hi < 0)

        for c in constraints:
            if c.op == ConstraintOp.LE:
                hi = c.constant if is_unbounded else min(hi, c.constant)
                lo = min(lo, c.constant)
            elif c.op == ConstraintOp.LT:
                hi = (c.constant - 1) if is_unbounded else min(hi, c.constant - 1)
            elif c.op == ConstraintOp.GE:
                lo = max(lo, c.constant)
            elif c.op == ConstraintOp.GT:
                lo = max(lo, c.constant + 1)
            elif c.op == ConstraintOp.EQ:
                lo = hi = c.constant

        if lo > hi and hi >= 0:
            return StridedInterval(0, -1, 1)  # bottom
        return StridedInterval(lo, hi if not is_unbounded or hi >= 0 else -1, stride)

    def build_path_segments(self, pseudocode: str,
                            func_name: str = "") -> List[PathSegment]:
        """将伪代码分解为路径段 — 每个 if-else 产生一对互补段.

        默认段 (无约束) 覆盖所有非分支代码.
        """
        segments = []

        default = PathSegment(
            segment_id=f"{func_name}@default",
        )
        segments.append(default)

        for m in self._IF_COND_RE.finditer(pseudocode):
            var = m.group(1)
            op = self._OP_MAP.get(m.group(2))
            if op is None:
                continue
            try:
                val = int(m.group(3), 0)
            except (ValueError, TypeError):
                continue

            neg_op = {
                ConstraintOp.LE: ConstraintOp.GT, ConstraintOp.LT: ConstraintOp.GE,
                ConstraintOp.GE: ConstraintOp.LT, ConstraintOp.GT: ConstraintOp.LE,
                ConstraintOp.EQ: ConstraintOp.NE, ConstraintOp.NE: ConstraintOp.EQ,
            }[op]

            true_seg = PathSegment(
                segment_id=f"{func_name}@L{m.start()}_true",
                constraints=[LinearConstraint(var, op, val)],
            )
            false_seg = PathSegment(
                segment_id=f"{func_name}@L{m.start()}_false",
                constraints=[LinearConstraint(var, neg_op, val)],
            )
            segments.extend([true_seg, false_seg])

        return segments

    def find_overflow_paths(
        self,
        alloc_size: int,
        write_size: int,
        segments: List[PathSegment],
        size_var: str = "size",
    ) -> Tuple[List[PathSegment], List[PathSegment]]:
        """逐路径判定: 在约束下 alloc_size 是否 < write_size.

        返回 (overflow_paths, safe_paths).
        """
        overflow = []
        safe = []

        for seg in segments:
            if seg.is_infeasible:
                continue

            lo_refined = alloc_size
            hi_refined = alloc_size

            for c in seg.constraints:
                if c.variable != size_var:
                    continue
                if c.op == ConstraintOp.LE:
                    hi_refined = min(hi_refined, c.constant)
                elif c.op == ConstraintOp.LT:
                    hi_refined = min(hi_refined, c.constant - 1)
                elif c.op == ConstraintOp.GE:
                    lo_refined = max(lo_refined, c.constant)
                elif c.op == ConstraintOp.GT:
                    lo_refined = max(lo_refined, c.constant + 1)
                elif c.op == ConstraintOp.EQ:
                    lo_refined = hi_refined = c.constant

            if write_size > hi_refined:
                overflow.append(seg)
            elif write_size <= lo_refined:
                safe.append(seg)
            else:
                overflow.append(seg)  # ambiguous → conservative

        return overflow, safe

    def compute_fp_likelihood(
        self,
        alloc_size: int,
        write_size: int,
        segments: List[PathSegment],
        size_var: str = "size",
    ) -> float:
        """计算误报概率: safe 路径占比越高, 误报概率越高.

        若所有路径都不可行或安全 → fp_likelihood ≈ 1.0
        若所有路径都溢出 → fp_likelihood ≈ 0.0
        """
        overflow_paths, safe_paths = self.find_overflow_paths(
            alloc_size, write_size, segments, size_var)
        total = len(overflow_paths) + len(safe_paths)
        if total == 0:
            return 0.50  # 无法确定
        return len(safe_paths) / total

def path_sensitive_check(pseudocode: str,
                         alloc_size: int,
                         write_size: int,
                         size_var: str = "size") -> Tuple[bool, str, float]:
    """便捷接口: 判断 alloc+write 对是否为真溢出.

    返回 (is_overflow, reason, fp_likelihood).
    """
    tracker = PathConditionTracker()
    segments = tracker.build_path_segments(pseudocode)
    overflow, safe = tracker.find_overflow_paths(
        alloc_size, write_size, segments, size_var)
    total = len(overflow) + len(safe)
    fp_likelihood = len(safe) / total if total > 0 else 0.50

    if not overflow:
        return False, f"all {len(safe)} path(s) safe", fp_likelihood
    if not safe:
        return True, f"all {len(overflow)} path(s) overflow", 0.0
    return True, (
        f"{len(overflow)} overflow + {len(safe)} safe paths → ambiguous"
    ), fp_likelihood

__all__ = [
    'ConstraintOp', 'LinearConstraint', 'PathSegment',
    'PathConditionTracker', 'path_sensitive_check',
]
