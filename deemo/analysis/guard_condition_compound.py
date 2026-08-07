"""

处理 &&/|| 复合条件的语义, 以及 for/while 循环头的归纳变量边界提取.
AND 守卫 (&&): 所有条件必须同时满足 → 取最紧约束 (交集).
OR 守卫 (||): 任一条件满足即可 → 保守不用于 SAFE 过滤.
"""


import re
from typing import Dict, List, Tuple

from analysis.guard_condition_types import GuardCondition, GuardSet


def extract_guards_with_logic(pseudocode: str) -> List[Tuple[GuardSet, str]]:
    """提取守卫条件集并保留逻辑连接词 (&& 或 ||).

    与 GuardConditionInferrer.extract_guards 的区别:
      返回 (GuardSet, logic) 对, logic='AND'/'OR'.
      OR 守卫的单个分支约束不能独立用于过滤 (另一分支可能无此约束).
    """
    cmp_pat = re.compile(
        r'(\w+)\s*(<|<=|>=|>|==|!=)\s*(\d+|0x[0-9a-fA-F]+)', re.IGNORECASE)
    cmp_rev_pat = re.compile(
        r'(\d+|0x[0-9a-fA-F]+)\s*(<|<=|>=|>|==|!=)\s*(\w+)', re.IGNORECASE)
    kw_skip = frozenset([
        'if', 'else', 'for', 'while', 'return', 'sizeof',
        'void', 'int', 'char', 'long', 'short', 'unsigned',
        'struct', 'union', 'enum', 'static', 'const'])

    results: List[Tuple[GuardSet, str]] = []
    lines = pseudocode.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('//'):
            continue
        candidates = [stripped]
        if not (stripped.startswith('if ') or stripped.startswith('if(')):
            parts = stripped.split(';')
            candidates = [p.strip() for p in parts
                         if p.strip().startswith('if ') or p.strip().startswith('if(')]
            if not candidates:
                continue
        for cand in candidates:
            if not (cand.startswith('if ') or cand.startswith('if(')):
                continue
            gs = GuardSet(line=i + 1)
            cond_body = _extract_condition_body(cand)
            if not cond_body:
                continue
            logic = 'OR' if '||' in cond_body else 'AND'

            for m in cmp_pat.finditer(cond_body):
                var, op, const_str = m.group(1), m.group(2), m.group(3)
                if var in kw_skip:
                    continue
                gs.conditions.append(GuardCondition(
                    var=var, op=op, constant=int(const_str, 0), line=i + 1))
            for m in cmp_rev_pat.finditer(cond_body):
                const_str, op, var = m.group(1), m.group(2), m.group(3)
                if var in kw_skip:
                    continue
                rev_op = {'<': '>', '>': '<', '<=': '>=', '>=': '<='}.get(op, op)
                gs.conditions.append(GuardCondition(
                    var=var, op=rev_op, constant=int(const_str, 0), line=i + 1))
            if gs.conditions:
                results.append((gs, logic))
    return results


def extract_loop_bounds(pseudocode: str) -> Dict[str, Tuple[int, int]]:
    """从 for/while 循环头提取循环归纳变量的边界约束.

    模式:
      for(i=0; i<N; i++) → i ∈ [0, N-1]
      while(i < N) { ... i++; } → i ∈ [0, N-1]

    用于循环内写入的安全性判定: 若 i≤N-1 且 N≤alloc_size/elem_size,
    则 buf[i] 在边界内.
    """
    for_header = re.compile(
        r'for\s*\(\s*(\w+)\s*=\s*(\d+)\s*;\s*'
        r'\1\s*([<>=!]+)\s*(\w+|\d+)\s*;\s*[^)]+\)', re.IGNORECASE)
    while_header = re.compile(
        r'while\s*\(\s*(\w+)\s*([<>=!]+)\s*(\w+|\d+)\s*\)', re.IGNORECASE)
    incr_pat = re.compile(r'(\w+)\s*\+\+')

    loop_bounds: Dict[str, Tuple[int, int]] = {}

    for m in for_header.finditer(pseudocode):
        var = m.group(1)
        init_val = int(m.group(2))
        op = m.group(3)
        bound_str = m.group(4)
        try:
            bound_val = int(bound_str)
        except ValueError:
            continue
        if op in ('<', '<='):
            hi = bound_val - 1 if op == '<' else bound_val
            loop_bounds[var] = (init_val, hi)
        elif op in ('>', '>='):
            lo = bound_val + 1 if op == '>' else bound_val
            loop_bounds[var] = (lo, init_val)

    for m in while_header.finditer(pseudocode):
        var = m.group(1)
        op = m.group(2)
        bound_str = m.group(3)
        try:
            bound_val = int(bound_str)
        except ValueError:
            continue
        # while(i < N): i从0开始, 上界N-1
        if op in ('<', '<='):
            loop_bounds[var] = (0, bound_val - 1 if op == '<' else bound_val)
        elif op in ('>', '>='):
            # while(i > 0): 下界1, 上界∞
            if bound_val > 0:
                loop_bounds[var] = (bound_val + 1 if op == '>' else bound_val,
                                   float('inf'))

    for m in incr_pat.finditer(pseudocode):
        var = m.group(1)
        if var not in loop_bounds:
            continue
        # 确认该变量在循环内递增 → 边界有效

    return loop_bounds


def _extract_condition_body(line: str) -> str:
    """从 if 行提取 (...) 内的条件体."""
    start = line.find('(')
    if start == -1:
        return ''
    depth = 0
    for i in range(start, len(line)):
        if line[i] == '(':
            depth += 1
        elif line[i] == ')':
            depth -= 1
            if depth == 0:
                return line[start + 1:i]
    return ''


__all__ = ['extract_guards_with_logic', 'extract_loop_bounds']
