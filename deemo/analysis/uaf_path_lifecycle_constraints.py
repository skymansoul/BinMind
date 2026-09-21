"""
路径条件对象生命周期约束提取器 — 从伪代码提取支配use点的路径条件.

当 UAF 对象身份图判定UAF时, 路径条件对象生命周期提取支配free点和use点的分支条件,
判定free-use路径是否互斥:
  if (error) free(p);
  ...
  if (!error) *p = 1;
  -> free路径(error=true)与use路径(error=false)互斥 -> 过滤UAF误报

与路径条件后向值流的技术关联:
  路径条件后向值流处理堆溢出中的路径约束感知, 路径条件对象生命周期将同一思想迁移到UAF:
  不再无条件认为free之后的use就是UAF, 而是检查free和use
  是否可在同一执行路径上同时到达.

设计决策:
  仅提取if/else条件中的布尔变量和简单比较, 保持O(n)复杂度
  支持逻辑非(!)和逻辑与(&&), 不支持逻辑或(保守保留)
  大括号处理顺序: 先关(}) 再关键字(if/elif/else) 再开({)
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class PathCondition:
    """支配某程序点的路径条件."""
    line_no: int
    condition: str
    branch_taken: bool = True
    negated: bool = False
    source: str = ""

    def negate(self) -> 'PathCondition':
        return PathCondition(
            line_no=self.line_no,
            condition=self.condition,
            branch_taken=not self.branch_taken,
            negated=not self.negated,
            source=f"!({self.source})",
        )

    def is_mutex_with(self, other: 'PathCondition') -> bool:
        """两个路径条件是否互斥."""
        if self.condition == other.condition:
            return self.branch_taken != other.branch_taken
        if _is_negation(self.condition, other.condition):
            return self.branch_taken == other.branch_taken
        # 比较条件互斥: mode==1(T) vs mode!=1(T)
        if _is_cmp_mutex(self.condition, other.condition,
                         self.branch_taken, other.branch_taken):
            return True
        return False


_if_re = re.compile(
    r'\bif\s*\(\s*(.+?)\s*\)\s*\{?', re.IGNORECASE)
_else_re = re.compile(r'\belse\b\s*\{?', re.IGNORECASE)
_else_if_re = re.compile(
    r'\belse\s+if\s*\(\s*(.+?)\s*\)\s*\{?', re.IGNORECASE)

_cond_var_re = re.compile(r'([a-zA-Z_]\w*)')
_bool_cmp_re = re.compile(
    r'(\w+)\s*(==|!=|<=|>=|<|>)\s*(\d+|0x[0-9a-fA-F]+|NULL|null|0)')


def extract_path_conditions(
    lines: List[str],
    target_line: int,
    window: int = 80,
) -> List[PathCondition]:
    """提取支配target_line的路径条件链.

    返回从外到内的路径条件列表.
    同一嵌套层取最后一条匹配的分支.

    大括号处理顺序: 先关(}) → 关键字(if/elif/else) → 再开({)
    这保证 } else { 中, else能获取到刚弹出的if条件.
    """
    conditions: List[PathCondition] = []
    brace_stack: List[Tuple[int, List[PathCondition]]] = []
    last_popped: List[PathCondition] = []
    pending: List[PathCondition] = []

    start = max(0, target_line - window)

    for i in range(start, min(target_line + 1, len(lines))):
        line = lines[i].strip()
        if not line:
            continue

        just_popped = False

        # 关闭大括号优先于一切
        if '}' in line:
            for _ in range(line.count('}')):
                if brace_stack:
                    bl, bl_conds = brace_stack.pop()
                    last_popped = bl_conds
                    conditions = [
                        c for c in conditions
                        if not any(c is bc for bc in bl_conds)
                    ]
            just_popped = True

        new_conds: List[PathCondition] = []
        m_elif = _else_if_re.search(line)
        m_if = _if_re.search(line)
        m_else = _else_re.search(line)

        if m_elif:
            cond = m_elif.group(1).strip()
            if last_popped:
                for j, pc in enumerate(last_popped):
                    if j == len(last_popped) - 1:
                        new_conds.append(PathCondition(
                            i, pc.condition, not pc.branch_taken,
                            f"elif_neg({pc.condition})"))
                    else:
                        new_conds.append(PathCondition(
                            i, pc.condition, pc.branch_taken,
                            f"elif_keep({pc.condition})"))
            new_conds.append(PathCondition(
                i, cond, True, f"elif({cond})"))
            last_popped = []
        elif m_if:
            cond = m_if.group(1).strip()
            new_conds.append(PathCondition(
                i, cond, True, f"if({cond})"))
            last_popped = []
        elif m_else:
            if last_popped:
                for j, pc in enumerate(last_popped):
                    if j == len(last_popped) - 1:
                        new_conds.append(PathCondition(
                            i, pc.condition, not pc.branch_taken,
                            f"else_neg({pc.condition})"))
                    else:
                        new_conds.append(PathCondition(
                            i, pc.condition, pc.branch_taken,
                            f"else_keep({pc.condition})"))
            last_popped = []
        elif not just_popped:
            last_popped = []

        conditions.extend(new_conds)
        if new_conds:
            pending = list(new_conds)

        if '{' in line:
            for _ in range(line.count('{')):
                brace_stack.append((i, list(pending)))
            pending = []

    return conditions


def extract_free_path_conditions(
    lines: List[str],
    free_line: int,
    use_line: int,
    window: int = 80,
) -> Tuple[List[PathCondition], List[PathCondition]]:
    """提取支配free点和use点的路径条件.

    返回 (free_conditions, use_conditions).
    """
    free_conds = extract_path_conditions(lines, free_line, window)
    use_conds = extract_path_conditions(lines, use_line, window)
    return free_conds, use_conds


def check_path_mutex(
    free_conds: List[PathCondition],
    use_conds: List[PathCondition],
) -> Tuple[bool, str]:
    """判定free路径与use路径是否互斥.

    返回 (is_mutex, reason).
    互斥条件: 存在变量v, free路径中v取某值, use路径中v取互斥值.
    early-return检测由verifier层处理, 此处仅做条件互斥判定.
    """
    if not free_conds or not use_conds:
        return False, "no overlapping path conditions"

    for fc in free_conds:
        for uc in use_conds:
            if fc.is_mutex_with(uc):
                return True, (
                    f"path mutex: free@L{fc.line_no} "
                    f"takes {fc.condition}={fc.branch_taken}, "
                    f"use@L{uc.line_no} takes {uc.condition}="
                    f"{uc.branch_taken}")

    return False, "paths not proven mutex"


_cmp_re = re.compile(
    r'(\w+)\s*(==|!=|<=|>=|<|>)\s*(\d+|0x[0-9a-fA-F]+|NULL|null|0)')

_OP_NEG = {'==': '!=', '!=': '==', '<': '>=', '>': '<=',
           '<=': '>', '>=': '<'}


def _parse_cmp(cond: str) -> Optional[Tuple[str, str, str]]:
    """解析比较条件为 (var, op, val) 三元组."""
    m = _cmp_re.match(cond.strip())
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _is_cmp_mutex(a: str, b: str,
                  a_taken: bool, b_taken: bool) -> bool:
    """两个比较条件是否互斥.

    互斥 iff 相同变量相同值但比较结果矛盾:
      a==v(T) vs a!=v(T)  -> 互斥 (==真 和 !=真 不可能同时成立)
      a==v(T) vs a==v(F) -> 已由 is_mutex_with 处理
      a<v(T) vs a>=v(T)  -> 互斥
    """
    ca = _parse_cmp(a)
    cb = _parse_cmp(b)
    if not ca or not cb:
        return False
    if ca[0] != cb[0] or ca[2] != cb[2]:
        return False
    if ca[1] == cb[1]:
        return a_taken != b_taken
    if _OP_NEG.get(ca[1]) == cb[1]:
        return a_taken == b_taken
    return False


def _is_negation(cond_a: str, cond_b: str) -> bool:
    """两个条件是否互为逻辑否定."""
    a = cond_a.strip()
    b = cond_b.strip()
    if a == f'!{b}' or b == f'!{a}':
        return True
    if a.startswith('!') and a[1:] == b:
        return True
    if b.startswith('!') and b[1:] == a:
        return True
    a_stripped = a.lstrip('!').strip()
    b_stripped = b.lstrip('!').strip()
    one_neg = (a.startswith('!') != b.startswith('!'))
    if one_neg and a_stripped == b_stripped:
        return True
    return False


__all__ = [
    'PathCondition', 'extract_path_conditions',
    'extract_free_path_conditions', 'check_path_mutex',
]
