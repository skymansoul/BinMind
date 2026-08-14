"""
路径敏感约束收集器 — 在每条CFG路径上单独收集约束, 避免跨路径约束泄露与误报.
从反编译文本构建简化CFG, 对每个(alloc,write)对枚举有界路径集, 每条路径收集基础约束+路径级guard约束;
路径数超限或CFG构建失败时回退到全局收集(单路径, 含全部guard).
"""
from __future__ import annotations
import re
from typing import List, Tuple

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem,
)
from core.cj_constraint_collector import collect_constraints
from core.ps_cj_cfg_builder import CFGPath, SimplifiedCFGBuilder
from core.heap_overflow_detector import HeapOverflowCandidate

_ALLOC_RE = re.compile(
    r'\b(?:malloc|calloc|realloc)\s*\(\s*(\w+|\d+)', re.IGNORECASE)
_WRITE_RE = re.compile(
    r'\b(?:memcpy|memmove|memset|strncpy|strncat|strcpy|strcat)'
    r'\s*\(|\bstore\b|\[.*\]\s*=', re.IGNORECASE)


def collect_path_sensitive_constraints(
    candidate: HeapOverflowCandidate,
    ir_lines: list[str],
    decompiled_text: str = "",
) -> List[Tuple[CFGPath, ConstraintSystem]]:
    """为候选构建路径敏感约束系统列表。

    返回 [(path, constraint_system), ...]。
    单元素列表表示路径枚举失败, 回退到全局CJ。
    """
    base_sys = collect_constraints(candidate, ir_lines, decompiled_text)

    if not decompiled_text or not decompiled_text.strip():
        return [(
            CFGPath(description="no decompiled text, global CJ"),
            base_sys,
        )]

    lines = decompiled_text.splitlines()
    alloc_line = _find_alloc_line(lines, candidate)
    write_line = _find_write_line(lines, candidate)

    if alloc_line <= 0 or write_line <= 0:
        return [(
            CFGPath(description="alloc/write not found in decompiled text"),
            base_sys,
        )]

    builder = SimplifiedCFGBuilder(max_paths=128)
    builder.build(lines)
    paths = builder.enumerate_paths(alloc_line, write_line)

    if len(paths) <= 1:
        return [(
            CFGPath(description="single path, global CJ"),
            base_sys,
        )]

    base_no_guards = _strip_guard_constraints(base_sys)
    result: List[Tuple[CFGPath, ConstraintSystem]] = []

    for path in paths:
        path_sys = _clone_system(base_no_guards)
        for guard in path.guard_constraints:
            path_sys.add(guard)

        overlapping = _has_overlapping_guards(
            path_sys, path.guard_constraints)
        if overlapping:
            path.is_feasible = False

        desc = (
            f"path {len(result)+1}/{len(paths)}: "
            f"{len(path.blocks)} blocks, "
            f"{len(path.guard_constraints)} guards"
        )
        path.description = desc
        result.append((path, path_sys))

    if not result:
        result.append((
            CFGPath(description="fallback, global CJ"),
            base_sys,
        ))

    return result


def _find_alloc_line(
    lines: List[str],
    candidate: HeapOverflowCandidate,
) -> int:
    """在反编译文本中定位分配行(1-indexed)。"""
    for i, line in enumerate(lines):
        if _ALLOC_RE.search(line):
            return i + 1
    return 0


def _find_write_line(
    lines: List[str],
    candidate: HeapOverflowCandidate,
) -> int:
    """在反编译文本中定位写入行(1-indexed)。

    优先匹配具体的写入助记符, 其次匹配通用赋值模式。
    """
    mnemonic = candidate.overflow_store.mnemonic
    specific_re = re.compile(
        rf'\b{re.escape(mnemonic)}\s*\(', re.IGNORECASE
    ) if mnemonic else None

    for i, line in enumerate(lines):
        if not _ALLOC_RE.search(line):
            if specific_re and specific_re.search(line):
                return i + 1
            if _WRITE_RE.search(line):
                return i + 1
    return 0


def _strip_guard_constraints(
    sys: ConstraintSystem,
) -> ConstraintSystem:
    """从约束系统中移除全局GUARD_CONDITION约束, 保留路径无关约束。

    路径无关约束: ALLOC_SIZE, COPY_SIZE, WRITE_OFFSET, LOOP_BOUND,
    TYPE_BOUND, AFFINE_RELATION, ALIGNMENT。
    路径相关约束: GUARD_CONDITION — 需按路径重新注入。
    """
    stripped = _clone_system(sys)
    stripped.constraints = [
        c for c in stripped.constraints
        if c.source != ConstraintType.GUARD_CONDITION
    ]
    return stripped


def _clone_system(sys: ConstraintSystem) -> ConstraintSystem:
    """深拷贝约束系统。"""
    return ConstraintSystem(
        constraints=list(sys.constraints),
        alloc_var=sys.alloc_var,
        alloc_size=sys.alloc_size,
        copy_var=sys.copy_var,
        copy_size=sys.copy_size,
        offset_var=sys.offset_var,
        offset_val=sys.offset_val,
        loop_var=sys.loop_var,
        loop_bound=sys.loop_bound,
        mnemonic=sys.mnemonic,
        store_size=sys.store_size,
    )


def _has_overlapping_guards(
    sys: ConstraintSystem,
    path_guards: List[LinearConstraint],
) -> bool:
    """检测路径guard约束是否与系统中的已有约束矛盾。

    若路径本身不可行(guard自相矛盾), 标记为infeasible。
    """
    from core.cj_fourier_motzkin import check_feasibility

    all_guards = [
        c for c in sys.constraints
        if c.source == ConstraintType.GUARD_CONDITION
    ]
    if len(all_guards) < 2:
        return False

    feasible, _ = check_feasibility(all_guards)
    return not feasible


__all__ = [
    'collect_path_sensitive_constraints',
]
