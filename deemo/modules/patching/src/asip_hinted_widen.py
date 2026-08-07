"""
ASIP受提示延迟拓宽 — 解决区间域widen过激进丢失上界.

根因: heap_abstract_domain.py的Interval.widen在上界增长时
直接跳到+∞, 循环一次迭代就丢失有用边界信息.
如 malloc(n) where n<=100, 循环一次后n变为[-∞, +∞],
CJ求解器收到宽松约束无法证明安全.

本模块实现threshold widening with guard hints:
  1. 延迟拓宽: 前N次迭代用join替代widen, 保留精确边界
  2. 受提示拓宽: 利用路径守卫条件作为hint, 限制widen方向
     若guard(n<=100)存在, widen(n)上界不超过100

理论依据:
  - Cousot&Cousot 1992: widening with thresholds
  - Blanchet et al. (Astrée): widening with hints from user annotations
  - 本模块创新: hints来自自动提取的路径guard, 非手动标注

与cj_interval_domain.py的关系: 作为后处理增强,
不修改IntervalDomain原有逻辑. 对widen结果执行hint收窄.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class WideningHint:
    """从路径guard提取的拓宽提示."""
    var: str
    upper_bound: Optional[int] = None
    lower_bound: Optional[int] = None
    source: str = ""


# 延迟拓宽阈值: 前N次迭代使用join
_DELAY_THRESHOLD = 3


def extract_hints_from_guards(
    guard_conditions: List,
    target_vars: List[str],
) -> List[WideningHint]:
    """从路径guard条件中提取拓宽hint.

    支持的guard格式(与heap_guard_collector兼容):
      - GuardCondition(CMP_JA, bound=N, reg=var)  → var < N
      - GuardCondition(CMP_JBE, bound=N, reg=var) → var <= N
      - GuardCondition(CMP_JG, bound=N, reg=var)  → var > N
      - GuardCondition(CMP_JLE, bound=N, reg=var) → var <= N

    对于源码级管线, 直接从文本提取if(x<=N)模式.
    """
    hints = []
    for g in guard_conditions:
        reg = getattr(g, 'reg', '')
        kind = getattr(g, 'kind', None)
        bound = getattr(g, 'bound', None)
        if not reg or bound is None:
            continue
        reg = _normalize_var(reg)
        if reg not in target_vars:
            continue
        if bound is not None and isinstance(bound, (int, float)):
            bound = int(bound)
            kind_name = str(kind) if kind else ''
            if 'JA' in kind_name or 'JB' in kind_name:
                hints.append(WideningHint(
                    var=reg, upper_bound=bound - 1,
                    source=f'guard:{kind_name}'))
            elif 'JBE' in kind_name or 'JLE' in kind_name:
                hints.append(WideningHint(
                    var=reg, upper_bound=bound,
                    source=f'guard:{kind_name}'))
            elif 'JG' in kind_name or 'JGE' in kind_name:
                hints.append(WideningHint(
                    var=reg, lower_bound=bound + 1,
                    source=f'guard:{kind_name}'))
    return hints


def extract_hints_from_text(
    source: str,
    target_vars: List[str],
) -> List[WideningHint]:
    """从伪代码文本提取if(x<=N)模式作为hint."""
    hints = []
    pat = re.compile(
        r'\bif\s*\(\s*(\w[\w]*)\s*(<=|>=|<|>|==|!=)\s*'
        r'(0x[0-9a-f]+|\d+)\s*\)',
    )
    for m in pat.finditer(source):
        var = m.group(1)
        op = m.group(2)
        val = m.group(3)
        if var not in target_vars:
            continue
        try:
            n = int(val, 0) if val.lower().startswith('0x') else int(val)
        except ValueError:
            continue
        if op in ('<=', '<'):
            hints.append(WideningHint(
                var=var, upper_bound=n if op == '<=' else n - 1,
                source=f'if({var}{op}{n})'))
        elif op in ('>=', '>'):
            hints.append(WideningHint(
                var=var, lower_bound=n if op == '>=' else n + 1,
                source=f'if({var}{op}{n})'))
    return hints


def widen_with_hints(
    var: str,
    old_lo: Optional[int],
    old_hi: Optional[int],
    new_lo: Optional[int],
    new_hi: Optional[int],
    iter_count: int,
    hints: List[WideningHint],
) -> Tuple[Optional[int], Optional[int]]:
    """受提示延迟拓宽.

    策略:
      1. iter_count < _DELAY_THRESHOLD: 使用join(不拓宽)
      2. iter_count >= _DELAY_THRESHOLD: 使用hint限制的widen
         - 若widen使上界→+∞, 但hint提供upper_bound → 用hint
         - 若widen使下界→-∞, 但hint提供lower_bound → 用hint
      3. 无hint时: 使用原始widen
    """
    if iter_count < _DELAY_THRESHOLD:
        return new_lo, new_hi

    result_lo = old_lo
    result_hi = old_hi

    # widen上界
    if old_hi is not None and new_hi is not None and new_hi > old_hi:
        hint_bound = _find_hint_upper(var, hints)
        if hint_bound is not None:
            result_hi = hint_bound
        else:
            result_hi = None  # +∞
    elif new_hi is not None:
        result_hi = new_hi

    # widen下界
    if old_lo is not None and new_lo is not None and new_lo < old_lo:
        hint_bound = _find_hint_lower(var, hints)
        if hint_bound is not None:
            result_lo = hint_bound
        else:
            result_lo = None  # -∞
    elif new_lo is not None:
        result_lo = new_lo

    return result_lo, result_hi


def _find_hint_upper(var: str, hints: List[WideningHint]) -> Optional[int]:
    """查找变量上界hint (取最小上界)."""
    bounds = [h.upper_bound for h in hints
              if h.var == var and h.upper_bound is not None]
    return min(bounds) if bounds else None


def _find_hint_lower(var: str, hints: List[WideningHint]) -> Optional[int]:
    """查找变量下界hint (取最大下界)."""
    bounds = [h.lower_bound for h in hints
              if h.var == var and h.lower_bound is not None]
    return max(bounds) if bounds else None


def _normalize_var(v: str) -> str:
    """将寄存器名归一化到64位形式."""
    return {
        'al': 'rax', 'ah': 'rax', 'ax': 'rax', 'eax': 'rax',
        'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi',
        'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi',
        'dl': 'rdx', 'dh': 'rdx', 'dx': 'rdx', 'edx': 'rdx',
        'cl': 'rcx', 'ch': 'rcx', 'cx': 'rcx', 'ecx': 'rcx',
    }.get(v.lower(), v.lower())


__all__ = [
    'WideningHint', 'extract_hints_from_guards',
    'extract_hints_from_text', 'widen_with_hints',
]
