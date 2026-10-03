"""循环不变式分层证明 Layer 1 — 路径条件传播器: 从IR提取条件分支中的比较，构建路径
谓词集并对变量施加上下界约束，使后向值流可判（如 if (n<=1024) 下
memcpy(buf, src, n) 判SAFE）。"""
from __future__ import annotations
import re
from typing import List, Optional, Set, Tuple

from core.loop_invariant_types import PathPredicate


_if_re = re.compile(r'\bif\s*\(([^)]+)\)')
_for_while_re = re.compile(r'\b(?:for|while)\s*\(([^)]+)\)')
_assert_re = re.compile(r'\bassert\s*\(([^)]+)\)')
_cond_re = re.compile(r'(\w+)\s*(<=|>=|<|>|==)\s*(\d+)')
_cond_re2 = re.compile(r'(\d+)\s*(<=|>=|<|>|==)\s*(\w+)')
_ternary_re = re.compile(
    r'(\w+)\s*=\s*\(\s*(\w+)\s*(<=|>=|<|>)\s*(\d+)\s*\)\s*\?')
_min_max_re = re.compile(
    r'(\w+)\s*=\s*(\w+)\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)')


def collect_path_predicates(
    ir_lines: List[str],
    alloc_pc: int,
    write_pc: int,
) -> List[PathPredicate]:
    """从ir_lines中alloc_pc到write_pc之间的条件语句提取路径谓词.

    搜索范围: alloc_pc之前的window行(grant条件通常在分配前)到write_pc.
    """
    window = 30
    start = max(0, alloc_pc - window)
    end = min(len(ir_lines), write_pc + 3)
    predicates: List[PathPredicate] = []

    for i in range(start, end):
        line = ir_lines[i].strip()
        preds = _extract_predicates_from_line(line, i)
        predicates.extend(preds)

    return _deduplicate(predicates)


def _extract_predicates_from_line(
    line: str, line_idx: int,
) -> List[PathPredicate]:
    """从单行提取所有路径谓词.

    支持复合&&条件: if (n > 0 && n < 64 && m <= 128)
    被拆分为独立子条件后逐个提取谓词.
    """
    results: List[PathPredicate] = []

    for m in _if_re.finditer(line):
        cond_text = m.group(1)
        results.extend(_extract_from_condition(cond_text, line_idx, line))

    for m in _for_while_re.finditer(line):
        cond_text = m.group(1)
        results.extend(_extract_from_condition(cond_text, line_idx, line))

    for m in _assert_re.finditer(line):
        cond_text = m.group(1)
        results.extend(_extract_from_condition(cond_text, line_idx, line))

    for m in _ternary_re.finditer(line):
        _, var2, op, val = m.group(1), m.group(2), m.group(3), float(m.group(4))
        results.append(PathPredicate(
            var=var2, bound=val, operator=op,
            origin_line=line_idx, condition_text=line[:80]))

    for m in _min_max_re.finditer(line):
        func, var, val_s = m.group(2), m.group(3), m.group(4)
        val = float(val_s)
        if func in ('min', 'MIN'):
            results.append(PathPredicate(
                var=var, bound=val, operator='<=',
                origin_line=line_idx, condition_text=line[:80]))
        elif func in ('max', 'MAX'):
            results.append(PathPredicate(
                var=var, bound=val, operator='>=',
                origin_line=line_idx, condition_text=line[:80]))

    return results


def _extract_from_condition(
    cond_text: str, line_idx: int, full_line: str,
) -> List[PathPredicate]:
    """从条件表达式中提取谓词, 处理&&和||连接的复合条件."""
    results: List[PathPredicate] = []
    sub_conds = re.split(r'&&|\|\|', cond_text)
    for sub in sub_conds:
        sub = sub.strip()
        for cm in _cond_re.finditer(sub):
            var, op, val = cm.group(1), cm.group(2), float(cm.group(3))
            results.append(PathPredicate(
                var=var, bound=val, operator=op,
                origin_line=line_idx, condition_text=full_line[:80]))
        for cm in _cond_re2.finditer(sub):
            val, op, var = float(cm.group(1)), cm.group(2), cm.group(3)
            flip = _flip_operator(op)
            results.append(PathPredicate(
                var=var, bound=val, operator=flip,
                origin_line=line_idx, condition_text=full_line[:80]))
    return results


def _flip_operator(op: str) -> str:
    """翻转比较运算符方向: a op b → b flip(a) a."""
    return {'<=': '>=', '>=': '<=', '<': '>', '>': '<', '==': '=='}.get(op, op)


def _deduplicate(preds: List[PathPredicate]) -> List[PathPredicate]:
    """去重: 同变量同方向取最严格约束."""
    best: dict = {}
    for p in preds:
        key = (p.var, p.operator)
        if key not in best:
            best[key] = p
        else:
            existing = best[key]
            if p.operator in ('<=', '<'):
                if p.bound < existing.bound:
                    best[key] = p
            elif p.operator in ('>=', '>'):
                if p.bound > existing.bound:
                    best[key] = p
    return list(best.values())


def derive_variable_bounds(
    predicates: List[PathPredicate],
    var: str,
) -> Tuple[Optional[float], Optional[float]]:
    """从谓词集推导变量的[lower, upper]边界."""
    lo = None
    hi = None
    for p in predicates:
        if p.var != var:
            continue
        if p.operator in ('<=', '<'):
            ub = p.bound
            if hi is None or ub < hi:
                hi = ub
        elif p.operator in ('>=', '>'):
            lb = p.bound
            if lo is None or lb > lo:
                lo = lb
    return lo, hi


__all__ = [
    'collect_path_predicates', 'derive_variable_bounds',
]
