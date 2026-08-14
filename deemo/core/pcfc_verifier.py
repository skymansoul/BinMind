"""PCFC路径条件验证器 — 格式串漏洞的路径条件感知误报过滤。
FCPV判定VULN时提取sink调用点的路径条件：early-return使攻击路径不可达、
sink路径与攻击输入路径互斥则过滤；路径不互斥或无路径条件信息时保持
VULN(保守, 零召回损失)。复用PCOL的约束提取器(target_line取sink行号)。"""
from __future__ import annotations
import re
from typing import Dict, List, Tuple

from analysis.uaf_pcol_constraints import (
    extract_path_conditions, check_path_mutex, PathCondition,
    _is_negation, _is_cmp_mutex, _parse_cmp,
)


def filter_fmt_by_pcfc(
    source: str,
    candidates: List,
) -> Tuple[List, Dict]:
    """对FCPV VULN判定执行PCFC路径条件感知过滤.

    返回 (filtered_candidates, stats).
    """
    stats = {
        'input': len(candidates),
        'pcfc_triggered': 0,
        'pcfc_filtered': 0,
        'pcfc_kept': 0,
        'output': 0,
    }

    lines = source.split('\n')
    kept = []

    for c in candidates:
        from core.fcpv_constraint_types import SafetyLabel
        if c.label != SafetyLabel.VULN:
            kept.append(c)
            continue

        stats['pcfc_triggered'] += 1

        sink_line = c.sink.line
        sink_idx = max(0, sink_line - 1)

        if sink_idx >= len(lines):
            stats['pcfc_kept'] += 1
            kept.append(c)
            continue

        sink_conds = extract_path_conditions(lines, sink_idx)

        filtered = False

        # 1. early-return检测: sink前有return/exit/abort
        filtered = _check_sink_early_return(lines, sink_idx)

        # 2. 条件互斥: sink路径与taint source路径互斥
        if not filtered and sink_conds:
            for taint in c.taints:
                taint_idx = max(0, taint.source_line - 1)
                if taint_idx < len(lines):
                    taint_conds = extract_path_conditions(
                        lines, taint_idx)
                    if taint_conds:
                        is_mutex, reason = _check_compound_mutex(
                            taint_conds, sink_conds)
                        if is_mutex:
                            filtered = True
                            break

        if filtered:
            stats['pcfc_filtered'] += 1
            c.label = SafetyLabel.SAFE
            c.confidence = 0.85
            c.reason = f'PCFC: {c.reason} [path-conditioned: unreachable]'
            kept.append(c)
        else:
            stats['pcfc_kept'] += 1
            kept.append(c)

    stats['output'] = len(kept)
    return kept, stats


def _find_enclosing_func_start(lines: List[str], idx: int) -> int:
    """向前搜索包含idx的函数定义起点.

    通过回溯寻找最近的函数签名行(含type name(params){),
    以确定sink所在函数的范围, 避免误匹配其他函数的return.
    """
    for i in range(idx, -1, -1):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith('//'):
            continue
        if '{' in stripped:
            fm = re.match(
                r'(?:void|int|char|long|short|float|double|unsigned|signed'
                r'|static|const|inline|size_t|ssize_t|struct\s+\w+)'
                r'[\s\*]+(\w[\w]*)\s*\([^)]*\)\s*\{', stripped)
            if fm:
                return i
        if stripped == '{' and i > 0:
            prev = lines[i - 1].strip()
            if re.search(
                    r'(?:void|int|char|long|short|float|double|unsigned|signed'
                    r'|static|const|inline|size_t|ssize_t|struct\s+\w+)'
                    r'[\s\*]+\w[\w]*\s*\([^)]*\)\s*$', prev):
                return i - 1
    return 0


def _check_sink_early_return(
    lines: List[str],
    sink_idx: int,
) -> bool:
    """检测sink前是否有return/exit使sink不可达.

    判定: 从sink所在函数的开头到sink_idx之间出现return/exit/abort
    且该return在同一无条件路径上 (保守: 仅检查无嵌套的return).
    函数边界感知: 仅扫描sink所在函数, 避免误匹配其他函数的return.
    """
    func_start = _find_enclosing_func_start(lines, sink_idx)
    for i in range(func_start, sink_idx):
        if i >= len(lines):
            break
        stripped = lines[i].strip()
        if re.match(r'\b(return|exit|_exit|abort)\b', stripped):
            if not _is_in_branch(lines, i):
                return True
    return False


def _decompose_condition(cond: str) -> List[str]:
    """将复合条件分解为原子子条件.

    支持逻辑与(&&)分割, 不分割逻辑或(保留保守性).
    """
    parts = re.split(r'\s*&&\s*', cond.strip())
    return [p.strip() for p in parts if p.strip()]


def _check_compound_mutex(
    taint_conds: List[PathCondition],
    sink_conds: List[PathCondition],
) -> Tuple[bool, str]:
    """检查复合路径条件互斥.

    先用原始check_path_mutex, 若不互斥再分解&&条件逐子项检查:
      taint含 debug(T) 且 sink含 !debug(T) -> 互斥
      taint含 mode==1(T) 且 sink含 mode!=1(T) -> 互斥
    """
    is_mutex, reason = check_path_mutex(taint_conds, sink_conds)
    if is_mutex:
        return True, reason

    for tc in taint_conds:
        t_parts = _decompose_condition(tc.condition)
        for sc in sink_conds:
            s_parts = _decompose_condition(sc.condition)
            for tp in t_parts:
                for sp in s_parts:
                    if _atom_mutex(tp, tc.branch_taken, sp, sc.branch_taken):
                        return True, (
                            f"compound mutex: '{tp}'@{tc.branch_taken} "
                            f"vs '{sp}'@{sc.branch_taken}")
    return False, "not proven mutex"


def _atom_mutex(a: str, a_taken: bool, b: str, b_taken: bool) -> bool:
    """两个原子条件是否互斥."""
    if _is_negation(a, b):
        return a_taken == b_taken
    ca = _parse_cmp(a)
    cb = _parse_cmp(b)
    if ca and cb:
        if _is_cmp_mutex(a, b, a_taken, b_taken):
            return True
    return False


def _is_in_branch(lines: List[str], idx: int) -> bool:
    """检测某行是否在条件分支块内."""
    depth = 0
    for i in range(idx - 1, -1, -1):
        line = lines[i].strip()
        if not line:
            continue
        closes = line.count('}')
        opens = line.count('{')
        depth += closes - opens
        if depth > 0:
            return True
        if re.match(r'\b(if|else|for|while|switch)\b', line):
            return True
    return False


def pcfc_filter_stats_summary(stats: Dict) -> str:
    """生成PCFC过滤器的统计摘要."""
    inp = stats.get('input', 0)
    trig = stats.get('pcfc_triggered', 0)
    filt = stats.get('pcfc_filtered', 0)
    kept = stats.get('pcfc_kept', 0)
    out = stats.get('output', 0)
    return (
        f"PCFC-Filter: input={inp}, triggered={trig}, "
        f"filtered={filt}, kept={kept}, output={out}"
    )


__all__ = [
    'filter_fmt_by_pcfc', 'pcfc_filter_stats_summary',
    '_find_enclosing_func_start',
]
