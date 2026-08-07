"""
分配前约束窄化 — GAPSBV维度7.
追踪malloc分配前变量的上界约束, 消除"分配大小已被限幅但仿射追踪器看到原始变量"的误报.

方法:
  对每个malloc(size_var)调用, 向前扫描size_var的最近约束, 提取有效上界.
  若约束上界已知且写入大小≤该上界, 则SAFE → FILTER.
  否则UNCERTAIN (保守保留).

处理的约束模式:
  1. if(var > N) var = N  — 显式限幅赋值
  2. if(var >= N) var = N
  3. var = MIN(var, N) / MIN(N, var)  — MIN宏
  4. var = (var > N) ? N : var  — 三元限幅
  5. if(var > N) return/exit  — 提前退出建立上界 (surviving path上var≤N)

设计理由: dim1仿射关系追踪用序列覆盖策略, 条件分支内的赋值无条件覆盖变量表达式,
导致限幅变量(如if(size>256)size=256后的size)被覆盖为256, 进而被后续if(size<0)size=0
再覆盖为0 → alloc=0 → 恒定溢出误报.
本模块在前端独立分析约束, 不修改var_expr, 与dim1正交.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional


@dataclass
class VarConstraint:
    """变量约束: upper_bound是有效上界, lower_bound是有效下界."""
    var: str = ""
    upper_bound: int = -1        # -1 = 未知
    upper_bound_source: str = "" # 约束来源行 (调试)
    lower_bound: int = 0         # 默认下界


class PreAllocConstraint:
    """分配前约束窄化器 — 追踪malloc前变量的有效上界."""

    # 模式1: if (var > N) var = N — 同行动态限幅
    _COND_CAP_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*([><]=?)\s*(\d+)\s*\)\s*'
        r'(\w+)\s*=\s*(\d+)\s*;',
        re.IGNORECASE)
    # 模式2: var = MIN(X, N) 或 var = MIN(N, X) — X可以是任何变量
    _MIN_MACRO_RE = re.compile(
        r'(\w+)\s*=\s*MIN\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)',
        re.IGNORECASE)
    _MIN_MACRO_REV_RE = re.compile(
        r'(\w+)\s*=\s*MIN\s*\(\s*(\d+)\s*,\s*(\w+)\s*\)',
        re.IGNORECASE)
    # 模式2b: var = MIN(X, Y) — 两个参数都是变量名, 扩展匹配
    _MIN_TWO_VAR_RE = re.compile(
        r'(\w+)\s*=\s*MIN\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
        re.IGNORECASE)
    # 模式3: var = (var > N) ? N : var
    _TERNARY_CAP_RE = re.compile(
        r'(\w+)\s*=\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)\s*\?\s*(\d+)\s*:\s*(\w+)',
        re.IGNORECASE)
    # 模式4: if (var > N) return — surviving path上界
    _GUARD_RETURN_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*>=\s*(\d+)\s*\)\s*(?:return|exit|goto)\b',
        re.IGNORECASE)
    _GUARD_RETURN_GT_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)\s*(?:return|exit|goto)\b',
        re.IGNORECASE)
    # 模式5: if (var < 0) var = 0 — 下界
    _LOWER_BOUND_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*<\s*(\d+)\s*\)\s*(\w+)\s*=\s*(\d+)\s*;',
        re.IGNORECASE)
    # malloc匹配
    _MALLOC_RE = re.compile(
        r'(?:(\w+)\s*=\s*(?:\([^)]*\)\s*)?)?(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        re.IGNORECASE)
    # memcpy写入匹配
    _MEMCPY_RE = re.compile(
        r'(memcpy|memmove|strcpy|strncpy|memset)\s*\([^,]+,\s*[^,]*,\s*(\d+)',
        re.IGNORECASE)

    def analyze(self, source: str) -> List[VarConstraint]:
        """分析源码中所有malloc前变量的上界约束. 返回约束列表."""
        lines = source.splitlines()
        constraints: List[VarConstraint] = []
        malloc_vars: Dict[str, int] = {}  # var → line

        # Phase 1: 收集所有malloc目标变量
        for i, line in enumerate(lines):
            s = line.strip()
            m = self._MALLOC_RE.search(s)
            if m:
                target = m.group(1)
                if not target:
                    continue
                malloc_vars[target] = i

        # Phase 2: 对每个malloc变量, 向前扫描约束
        for var, malloc_line in malloc_vars.items():
            constraint = VarConstraint(var=var)
            # 收集size变量: malloc(size) 或 malloc(n * sizeof(T))
            mline = lines[malloc_line].strip()
            mm = self._MALLOC_RE.search(mline)
            if not mm:
                continue
            size_str = mm.group(3).strip()
            size_vars = self._extract_vars(size_str)
            if not size_vars:
                continue

            # 对每个涉及变量向前扫描约束
            for sv in size_vars:
                self._scan_backward_constraints(
                    lines, sv, malloc_line, constraint)

            if constraint.upper_bound > 0:
                # 若有sizeof乘法因子, 放大上界
                sizeof_factor = self._extract_sizeof_factor(size_str)
                if sizeof_factor > 1:
                    constraint.upper_bound *= sizeof_factor
                constraints.append(constraint)

        return constraints

    def _extract_vars(self, expr: str) -> List[str]:
        """从malloc参数提取涉及的变量名."""
        # 去除sizeof(...)、常量、运算符
        tokens = re.findall(r'\b([a-zA-Z_]\w*)\b', expr)
        # 过滤关键字、类型名、函数名
        skip = {'malloc', 'calloc', 'realloc', 'sizeof', 'int', 'char',
                'long', 'short', 'float', 'double', 'void', 'size_t',
                'unsigned', 'signed', 'struct', 'union', 'NULL'}
        return [t for t in tokens if t not in skip]

    def _scan_backward_constraints(self, lines: List[str], var: str,
                                    malloc_line: int, c: VarConstraint):
        """向前扫描var的约束, 填充c."""
        for i in range(malloc_line - 1, max(malloc_line - 50, -1), -1):
            s = lines[i].strip()
            if not s:
                continue

            # 模式1: if(var > N) var = N  或  if(var >= N) var = N
            cm = self._COND_CAP_RE.search(s)
            if cm:
                cond_var = cm.group(1)
                op = cm.group(2)
                bound = int(cm.group(3))
                assign_var = cm.group(4)
                assign_val = int(cm.group(5))
                if cond_var == var and assign_var == var:
                    if op in ('>', '>=') and assign_val <= bound:
                        if c.upper_bound < 0 or assign_val < c.upper_bound:
                            c.upper_bound = assign_val
                            c.upper_bound_source = f'line {i+1}: cond_cap {s[:60]}'

            # 模式2a: var = MIN(X, N) — var≤N恒成立, X可以是任何变量
            mm = self._MIN_MACRO_RE.search(s)
            if mm:
                lhs = mm.group(1)
                bound = int(mm.group(3))
                if lhs == var:
                    if c.upper_bound < 0 or bound < c.upper_bound:
                        c.upper_bound = bound
                        c.upper_bound_source = f'line {i+1}: MIN({var},{bound}) caps {var}≤{bound}'

            # 模式2a_rev: var = MIN(N, X) — var≤N恒成立
            mmr = self._MIN_MACRO_REV_RE.search(s)
            if mmr:
                lhs = mmr.group(1)
                bound = int(mmr.group(2))
                if lhs == var:
                    if c.upper_bound < 0 or bound < c.upper_bound:
                        c.upper_bound = bound
                        c.upper_bound_source = f'line {i+1}: MIN({bound},{mmr.group(3)}) caps {var}≤{bound}'

            # 模式2b: var = MIN(X, Y) — 两个参数都是变量, 无常数界, 但记录别名关系
            mm2v = self._MIN_TWO_VAR_RE.search(s)
            if mm2v:
                lhs = mm2v.group(1)
                arg1 = mm2v.group(2)
                arg2 = mm2v.group(3)
                if lhs == var:
                    # X受Y约束 or Y受X约束 — 继续向前追踪这两个变量的约束
                    for alias_var in (arg1, arg2):
                        if alias_var != var:
                            self._scan_backward_constraints(
                                lines, alias_var, i, c)
                    # 最后, MIN(X,Y)本身给var一个X的约束
                    if arg1 == var:
                        self._scan_backward_constraints(lines, arg2, i, c)
                    elif arg2 == var:
                        self._scan_backward_constraints(lines, arg1, i, c)

            # 模式3: var = (var > N) ? N : var
            tm = self._TERNARY_CAP_RE.search(s)
            if tm:
                lhs = tm.group(1)
                cond_var = tm.group(2)
                bound = int(tm.group(3))
                cap = int(tm.group(4))
                else_var = tm.group(5)
                if lhs == var and cond_var == var and else_var == var:
                    if c.upper_bound < 0 or cap < c.upper_bound:
                        c.upper_bound = cap
                        c.upper_bound_source = f'line {i+1}: ternary cap N={cap}'

            # 模式4: if(var >= N) return — surviving path上 var ≤ N-1
            gm = self._GUARD_RETURN_RE.search(s)
            if gm and gm.group(1) == var:
                bound = int(gm.group(2)) - 1
                if c.upper_bound < 0 or bound < c.upper_bound:
                    c.upper_bound = bound
                    c.upper_bound_source = f'line {i+1}: guard_return {s[:60]}'

            gtm = self._GUARD_RETURN_GT_RE.search(s)
            if gtm and gtm.group(1) == var:
                bound = int(gtm.group(2))
                if c.upper_bound < 0 or bound < c.upper_bound:
                    c.upper_bound = bound
                    c.upper_bound_source = f'line {i+1}: guard_return_gt {s[:60]}'

            # 模式5: if(var < 0) var = 0 — 下界
            lm = self._LOWER_BOUND_RE.search(s)
            if lm:
                cond_var = lm.group(1)
                bound = int(lm.group(2))
                assign_var = lm.group(3)
                assign_val = int(lm.group(4))
                if cond_var == var and assign_var == var:
                    c.lower_bound = assign_val

    @staticmethod
    def _extract_sizeof_factor(expr: str) -> int:
        """从malloc参数提取sizeof乘法因子. malloc(n*sizeof(T)) → sizeof(T)."""
        sm = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
        if sm:
            type_sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8,
                          'float': 4, 'double': 8, 'void': 1}
            type_name = sm.group(1).replace('*', '').strip()
            return type_sizes.get(type_name, 1)
        return 1


def evaluate_pre_alloc_safety(source: str) -> Tuple[str, float, str]:
    """快速判定: 分配前约束能否证明写入安全.

    Returns: (verdict, confidence, reason)
      SAFE — 约束上界≥写入大小, 可过滤
      UNCERTAIN — 无法确定, 保留
    """
    pac = PreAllocConstraint()
    constraints = pac.analyze(source)
    if not constraints:
        return "UNCERTAIN", 0.0, "no constrained alloc variables"

    # 提取写入大小
    write_sizes = []
    for line in source.splitlines():
        s = line.strip()
        m = PreAllocConstraint._MEMCPY_RE.search(s)
        if m:
            try:
                write_sizes.append(int(m.group(2)))
            except ValueError:
                pass

    for c in constraints:
        if c.upper_bound <= 0:
            continue
        for ws in write_sizes:
            if ws <= c.upper_bound:
                return ("SAFE", 0.88,
                        f"alloc {c.var} ≤ {c.upper_bound} "
                        f"({c.upper_bound_source}), write={ws} ≤ {c.upper_bound}")

    return "UNCERTAIN", 0.0, f"no constraint proves write ≤ alloc_max"


__all__ = ['PreAllocConstraint', 'VarConstraint', 'evaluate_pre_alloc_safety']
