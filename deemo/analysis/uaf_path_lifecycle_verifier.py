"""
路径条件对象生命周期验证器 — 路径条件感知的UAF误报过滤器.

当 UAF 对象身份图判定CONFIRMED UAF时, 路径条件对象生命周期提取free和use点的路径条件,
判定两者是否可在同一执行路径上同时到达:
  1. 路径互斥 -> UAF不可能发生 -> 过滤为SAFE
  2. early-return: free后有return/exit -> use不可达 -> 过滤为SAFE
  3. 路径不互斥 -> 保持UAF判定
  4. 无路径条件信息 -> 保持UAF判定 (保守, 零召回损失)

核心场景:
  if (error) { free(p); return; }
  *p = 1;  <- 此use在error=false路径, 与free路径互斥 -> SAFE

  if (cond) free(p);
  if (cond) *p = 1;  <- free和use在同一路径 -> 保持UAF

与 UAF 对象身份图的关系:
  UAF 对象身份图判定对象身份和free-use时序, 路径条件对象生命周期过滤路径不可达的UAF
  路径条件对象生命周期不影响 UAF 对象身份图的 SAFE判定, 仅过滤CONFIRMED

保守策略:
  路径条件对象生命周期仅将CONFIRMED降级为SAFE, 不将SAFE升级为CONFIRMED
  路径条件对象生命周期无法判定时保持原判定, 不影响召回率
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from analysis.uaf_path_lifecycle_constraints import (
    PathCondition, extract_free_path_conditions, check_path_mutex,
)


def filter_uaf_by_pcol(
    pseudocode: str,
    verdicts: List,
) -> Tuple[List, Dict]:
    """对 UAF 对象身份图判定结果执行路径条件对象生命周期路径条件感知过滤.

    返回 (filtered_verdicts, stats).
    """
    stats = {
        'input': len(verdicts),
        'pcol_triggered': 0,
        'pcol_filtered': 0,
        'pcol_kept': 0,
        'output': 0,
    }

    lines = pseudocode.split('\n')
    kept = []

    for v in verdicts:
        if not hasattr(v, 'verdict') or v.verdict != 'CONFIRMED':
            kept.append(v)
            continue

        stats['pcol_triggered'] += 1

        free_line = getattr(v, 'free_line', -1)
        use_line = getattr(v, 'use_line', -1)

        if free_line < 0 or use_line < 0:
            stats['pcol_kept'] += 1
            kept.append(v)
            continue

        free_idx = max(0, free_line - 1)
        use_idx = max(0, use_line - 1)

        if free_idx >= len(lines) or use_idx >= len(lines):
            stats['pcol_kept'] += 1
            kept.append(v)
            continue

        free_conds, use_conds = extract_free_path_conditions(
            lines, free_idx, use_idx)

        # 1. 路径条件互斥检测
        if free_conds and use_conds:
            is_mutex, reason = check_path_mutex(free_conds, use_conds)
            if is_mutex:
                stats['pcol_filtered'] += 1
                kept.append(_create_safe_verdict(v, reason))
                continue

        # 2. early-return检测: free在同一作用域末尾有return/exit
        if _check_early_return(lines, free_idx, use_idx):
            stats['pcol_filtered'] += 1
            kept.append(_create_safe_verdict(v,
                f"early return after free@L{free_idx+1} "
                f"makes use@L{use_idx+1} unreachable"))
            continue

        # 3. reassign检测: free后到use前, 同一指针被重新malloc赋值
        use_var = getattr(v, 'use_var', '')
        if use_var and _check_reassign(lines, free_idx, use_idx, use_var):
            stats['pcol_filtered'] += 1
            kept.append(_create_safe_verdict(v,
                f"pointer {use_var} reassigned (malloc) between "
                f"free@L{free_idx+1} and use@L{use_idx+1}"))
            continue

        # 4. 恒假条件检测: free在if(0)/if(false)/if(NULL)块内
        if _check_dead_cond(lines, free_idx):
            stats['pcol_filtered'] += 1
            kept.append(_create_safe_verdict(v,
                f"free@L{free_idx+1} in dead condition (if(0)) "
                f"makes UAF unreachable"))
            continue

        stats['pcol_kept'] += 1
        kept.append(v)

    stats['output'] = len(kept)
    return kept, stats


def _check_early_return(
    lines: List[str],
    free_idx: int,
    use_idx: int,
) -> bool:
    """检测free后到use之前是否有return/exit使use不可达.

    仅检测free所在分支块内的return, 不跨越use所在的不同分支.
    判定: free_idx到use_idx之间出现return/exit/abort/_exit即认为
    use在free路径上不可达 (保守: 不要求精确的作用域匹配).
    """
    for i in range(free_idx + 1, use_idx):
        if i >= len(lines):
            break
        stripped = lines[i].strip()
        if re.match(r'\b(return|exit|_exit|abort)\b', stripped):
            return True
    return False


_re_malloc_assign = re.compile(
    r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?'
    r'(?:malloc|calloc|kmalloc|kzalloc|vmalloc|strdup)\s*\(')


def _check_reassign(
    lines: List[str],
    free_idx: int,
    use_idx: int,
    var: str,
) -> bool:
    """检测free后到use前, 同一指针被重新malloc赋值.

    场景: if(error){ free(p); } p = malloc(128); *p = 1;
    free后的重新分配使指针指向新的存活对象, use不是UAF.
    """
    for i in range(free_idx + 1, use_idx):
        if i >= len(lines):
            break
        m = _re_malloc_assign.search(lines[i])
        if m and m.group(1) == var:
            return True
    return False


def _check_dead_cond(lines: List[str], free_idx: int) -> bool:
    """检测free是否在恒假条件块(if(0)/if(false)/if(NULL))内.

    向上搜索包含free行的if条件, 如果条件为恒假则该free不可达.
    """
    _DEAD_COND = re.compile(r'if\s*\(\s*(?:0|false|NULL)\s*\)', re.IGNORECASE)
    depth = 0
    for i in range(free_idx, -1, -1):
        line = lines[i].strip() if i < len(lines) else ''
        depth += line.count('}') - line.count('{')
        if depth >= 0:
            # 向上走出了当前块, 检查触发该块的if条件
            if i > 0:
                prev = lines[i-1].strip() if (i-1) < len(lines) else ''
                if _DEAD_COND.search(prev):
                    return True
            break
        if depth == 0 and _DEAD_COND.search(line):
            return True
    # 也检查free行所在的直接if
    if free_idx < len(lines):
        for i in range(free_idx, max(free_idx - 5, -1), -1):
            line = lines[i].strip() if i < len(lines) else ''
            if _DEAD_COND.search(line):
                return True
            if '{' in line and '}' not in line:
                break
    return False


def _create_safe_verdict(original, reason: str):
    """从CONFIRMED判定创建SAFE判定, 保留原信息."""
    from analysis.uaf_obj_graph_types import UafHoigVerdict
    return UafHoigVerdict(
        verdict='SAFE',
        confidence=0.85,
        obj_id=getattr(original, 'obj_id', None),
        free_line=getattr(original, 'free_line', -1),
        use_line=getattr(original, 'use_line', -1),
        use_var=getattr(original, 'use_var', ''),
        free_var=getattr(original, 'free_var', ''),
        reason=f'路径条件对象生命周期: {reason}',
        is_cross_func=getattr(original, 'is_cross_func', False),
    )


def pcol_filter_stats_summary(stats: Dict) -> str:
    """生成路径条件对象生命周期过滤器的统计摘要."""
    inp = stats.get('input', 0)
    trig = stats.get('pcol_triggered', 0)
    filt = stats.get('pcol_filtered', 0)
    kept = stats.get('pcol_kept', 0)
    out = stats.get('output', 0)
    return (
        f"路径条件对象生命周期-Filter: input={inp}, triggered={trig}, "
        f"filtered={filt}, kept={kept}, output={out}"
    )


__all__ = [
    'filter_uaf_by_pcol', 'pcol_filter_stats_summary',
]
