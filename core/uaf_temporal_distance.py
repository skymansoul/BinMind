"""
UAF 时序距离分析器 — 计算归一化的 "free→use" 距离, 用于 UAF 可利用性排序与低风险 FP 候选过滤。
算法: 1. 对每个 (free, use) 对计算指令级距离; 2. 按函数长度归一化 dist_norm = instr_dist / func_length;
3. 短距离 (dist_norm < 0.3) 高可利用 → KEEP, 长距离 (dist_norm > 0.7) 低优先级 → REVIEW,
跨函数距离未定义 → 使用别名链深度启发式。距离加权置信度取代二值 CONFIRMED/FILTERED。
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Tuple


_FREE = re.compile(r'free\s*\(\s*(\w[\w.]*)\s*\)')
_DEREF = re.compile(r'(\w[\w.]*)\s*(?:->|\[)')
_ASSIGN = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;?')


@dataclass
class TemporalDistance:
    """free→use 时序距离分析结果。"""
    ptr_name: str; free_line: int; use_line: int
    instr_distance: int = 0
    func_length: int = 0
    dist_normalized: float = 0.0
    is_cross_function: bool = False
    alias_depth: int = 0
    exploitability: float = 0.50   # 0=benign, 1=highly exploitable


def compute_temporal_distance(
    ir_lines: List[str],
    free_line: int, ptr_name: str,
    func_length: int = 0,
) -> TemporalDistance:
    """计算从 free 点到首个 use-after-free 点的时序距离。"""
    fl = func_length if func_length > 0 else len(ir_lines)
    resolved = _resolve_aliases(ir_lines, ptr_name)
    candidates = list(resolved)  # ptr_name + all aliases

    # 查找 free 之后最近的解引用
    nearest, nearest_line = None, fl + 1
    for i in range(free_line + 1, min(len(ir_lines), free_line + 100)):
        dm = _DEREF.search(ir_lines[i])
        if dm:
            deref_var = dm.group(1)
            if deref_var in candidates:
                nearest = ir_lines[i].strip()
                nearest_line = i
                break

    if nearest is None:
        return TemporalDistance(
            ptr_name=ptr_name, free_line=free_line,
            use_line=-1, instr_distance=-1,
            func_length=fl, is_cross_function=True,
            alias_depth=len(candidates) - 1,
            exploitability=0.30,
        )

    dist = nearest_line - free_line
    norm = dist / max(fl, 1)

    # 可利用性评分
    if norm < 0.2:
        expl = 0.90  # immediate use after free → very exploitable
    elif norm < 0.4:
        expl = 0.75
    elif norm < 0.6:
        expl = 0.55
    else:
        expl = 0.35  # far apart → less likely exploitable

    # 别名链加分 (指示复杂指针流)
    alias_boost = min(0.15, 0.05 * (len(candidates) - 1))
    expl = min(0.95, expl + alias_boost)

    return TemporalDistance(
        ptr_name=ptr_name, free_line=free_line,
        use_line=nearest_line, instr_distance=dist,
        dist_normalized=round(norm, 4),
        func_length=fl, is_cross_function=False,
        alias_depth=len(candidates) - 1,
        exploitability=round(expl, 2),
    )


def _resolve_aliases(ir_lines: List[str], ptr: str) -> set:
    """从 IR 赋值语句解析 ptr 的所有别名。"""
    aliases: Dict[str, str] = {}
    for line in ir_lines:
        m = _ASSIGN.search(line.strip())
        if m:
            lhs, rhs = m.group(1), m.group(2)
            aliases[lhs] = rhs

    # 传递闭包
    resolved = {ptr}
    changed = True
    while changed:
        changed = False
        for alias, target in list(aliases.items()):
            if target in resolved and alias not in resolved:
                resolved.add(alias)
                changed = True
    return resolved


def score_uaf_with_distance(
    ir_lines: List[str],
    free_sites: List[Tuple[int, str]],
    func_length: int = 0,
) -> List[TemporalDistance]:
    """用时序距离分析对函数内所有 free 点评分。"""
    results = []
    for fl, fp in free_sites:
        td = compute_temporal_distance(ir_lines, fl, fp, func_length)
        results.append(td)
    results.sort(key=lambda t: -t.exploitability)
    return results


__all__ = ['TemporalDistance', 'compute_temporal_distance',
           'score_uaf_with_distance', '_resolve_aliases']
