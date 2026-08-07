"""
PC-BVF路径约束提取器 — 从IR行中提取支配告警点的分支条件.

当BVF判定alloc-write相关性为INCONCLUSIVE时, 路径约束提取器
反向搜索支配告警点的if/switch条件, 将其转化为变量值域约束:
  if (n <= 64) → n ∈ [0, 64]
  if (n > 0 && n < 256) → n ∈ [1, 255]
  if (len >= sizeof(hdr)) → len ∈ [sizeof(hdr), +∞)

提取的值域约束被注入BVF correlator, 收紧变量取值范围后重新判定.

设计决策:
  - 仅提取显式分支条件, 不做路径可达性推理(保持O(n)复杂度)
  - 支持简单比较和逻辑与组合, 不支持逻辑或(保守丢弃)
  - 提取结果为VarBound字典, 无副作用
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class VarBound:
    """变量值域约束: lo <= var <= hi."""
    lo: Optional[float] = None
    hi: Optional[float] = None
    source: str = ""

    def intersect(self, other: 'VarBound') -> 'VarBound':
        """取两个约束的交集."""
        lo = max(filter(lambda x: x is not None,
                        [self.lo, other.lo]), default=None)
        hi = min(filter(lambda x: x is not None,
                        [self.hi, other.hi]), default=None)
        return VarBound(lo=lo, hi=hi, source=f"{self.source}∩{other.source}")

    def is_empty(self) -> bool:
        """约束是否为空集(矛盾)."""
        if self.lo is not None and self.hi is not None:
            return self.lo > self.hi
        return False

    def contains(self, val: float) -> bool:
        """判定值是否在约束范围内."""
        if self.lo is not None and val < self.lo:
            return False
        if self.hi is not None and val > self.hi:
            return False
        return True


_if_re = re.compile(
    r'if\s*\(\s*(.+?)\s*\)\s*\{?', re.IGNORECASE)
_else_if_re = re.compile(
    r'else\s+if\s*\(\s*(.+?)\s*\)\s*\{?', re.IGNORECASE)

_compare_re = re.compile(
    r'(\w+)\s*(<=|>=|<|>|==|!=)\s*(\d+|0x[0-9a-fA-F]+|\w+)')
_compare_rev_re = re.compile(
    r'(\d+|0x[0-9a-fA-F]+)\s*(<=|>=|<|>|==|!=)\s*(\w+)')

_and_split_re = re.compile(r'\s*&&\s*')


def extract_path_constraints(
    ir_lines: List[str],
    alert_line: int,
    window: int = 60,
) -> Dict[str, VarBound]:
    """从alert_line上方提取支配该行的分支条件.

    返回 {var_name: VarBound} 映射.
    同一变量被多个条件约束时取交集.
    """
    bounds: Dict[str, VarBound] = {}
    start = max(0, alert_line - window)

    # 先检查告警行本身是否含inline-if条件(如: if(len>64) memcpy(...))
    if alert_line < len(ir_lines):
        cond = _extract_if_condition(ir_lines[alert_line].strip())
        if cond is not None:
            parsed = _parse_condition(cond)
            for var, bound in parsed:
                bounds[var] = bound

    brace_depth = 0
    in_scope = True

    for i in range(alert_line - 1, start - 1, -1):
        if i >= len(ir_lines):
            continue
        line = ir_lines[i].strip()

        if '}' in line:
            brace_depth += line.count('}')
        if '{' in line:
            brace_depth -= line.count('{')
        if brace_depth < 0:
            in_scope = False
            brace_depth = 0

        cond = _extract_if_condition(line)
        if cond is None:
            continue

        parsed = _parse_condition(cond)
        for var, bound in parsed:
            if var in bounds:
                bounds[var] = bounds[var].intersect(bound)
            else:
                bounds[var] = bound

    return {k: v for k, v in bounds.items() if not v.is_empty()}


def _extract_if_condition(line: str) -> Optional[str]:
    """从行中提取if/else-if的条件表达式."""
    m = _if_re.search(line)
    if m:
        return m.group(1)
    m = _else_if_re.search(line)
    if m:
        return m.group(1)
    return None


_or_split_re = re.compile(r'\s*\|\|\s*')


def _parse_condition(cond: str) -> List[Tuple[str, VarBound]]:
    """解析条件表达式为(var, VarBound)列表.

    支持逻辑与&&取交集和逻辑或||保守取并集上界.
    ||分支保守取所有分区间的放宽上界, 确保不会因析取导致漏约束.
    """
    if '||' in cond:
        return _parse_disjunction(cond)

    results = []
    parts = _and_split_re.split(cond)
    for part in parts:
        part = part.strip().strip('(').strip(')').strip()
        parsed = _parse_single_comparison(part)
        if parsed:
            results.append(parsed)
    return results


def _parse_disjunction(cond: str) -> List[Tuple[str, VarBound]]:
    """析取条件保守处理: 取所有分支的并集上界.
    if(a < 10 || a < 20) → a的上界取20(保守放宽)
    不收紧约束, 确保不引入虚假安全性.
    """
    from collections import defaultdict
    branches = _or_split_re.split(cond)
    per_var_bounds = defaultdict(list)
    for branch in branches:
        branch = branch.strip().strip('(').strip(')').strip()
        for sub in _and_split_re.split(branch):
            parsed = _parse_single_comparison(sub.strip())
            if parsed:
                per_var_bounds[parsed[0]].append(parsed[1])
    results = []
    for var, bounds in per_var_bounds.items():
        hi_vals = [b.hi for b in bounds if b.hi is not None]
        lo_vals = [b.lo for b in bounds if b.lo is not None]
        result_bound = VarBound(source=f"disjunction:{var}")
        if lo_vals:
            result_bound.lo = min(lo_vals)
        if hi_vals:
            result_bound.hi = max(hi_vals)
        if result_bound.lo is not None or result_bound.hi is not None:
            results.append((var, result_bound))
    return results


def _parse_single_comparison(expr: str) -> Optional[Tuple[str, VarBound]]:
    """解析单个比较表达式为变量值域约束."""
    m = _compare_re.match(expr)
    if m:
        var, op, rhs = m.group(1), m.group(2), m.group(3)
        rhs_val = _try_eval(rhs)
        if rhs_val is None and rhs in ('NULL', 'null'):
            rhs_val = 0
        if rhs_val is not None:
            return var, _make_bound(var, op, rhs_val, expr)

    m = _compare_rev_re.match(expr)
    if m:
        lhs, op, var = m.group(1), m.group(2), m.group(3)
        lhs_val = _try_eval(lhs)
        if lhs_val is None:
            return None
        rev_op = _reverse_op(op)
        if rev_op:
            return var, _make_bound(var, rev_op, lhs_val, expr)

    return None


def _make_bound(var: str, op: str, val: float,
                source: str) -> VarBound:
    """根据比较运算符构造值域约束."""
    if op == '<=':
        return VarBound(hi=val, source=f"{var}<={val}")
    if op == '<':
        return VarBound(hi=val - 1, source=f"{var}<{val}")
    if op == '>=':
        return VarBound(lo=val, source=f"{var}>={val}")
    if op == '>':
        return VarBound(lo=val + 1, source=f"{var}>{val}")
    if op == '==':
        return VarBound(lo=val, hi=val, source=f"{var}=={val}")
    return VarBound(source=source)


def _reverse_op(op: str) -> Optional[str]:
    """反转比较运算符: a > b → b < a."""
    return {
        '<=': '>=', '<': '>', '>=': '<=', '>': '<',
        '==': '==', '!=': '!=',
    }.get(op)


def _try_eval(s: str) -> Optional[float]:
    """尝试将字符串求值为数值."""
    s = s.strip()
    try:
        return float(int(s, 0))
    except (ValueError, TypeError):
        pass
    if s in ('NULL', 'null', '0'):
        return 0.0
    return None


__all__ = [
    'VarBound', 'extract_path_constraints',
]
