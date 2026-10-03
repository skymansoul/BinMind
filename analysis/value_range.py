"""
值范围传播引擎 (Value Range Propagation) — 在 C 源码上追踪整数变量的 [min, max] 范围。

方法论基础: Balakrishnan & Reps "WYSINWYX" 的 VSA 思想,
但针对 C 源码做了大幅简化: 只追踪 size 相关变量, 区间抽象 (而非 strided interval),
守卫条件约束传播。

设计决策:
  - 只追踪整型变量 (用于分配/写入大小), 不追踪指针
  - 区间用 [min, max] 闭区间
  - 守卫条件简化为 if (var <= N) → max = min(max, N)
  - 外部输入变量 → [0, INF] (保守)
  - 循环回边进行 widening: 外部输入做上界直接设 INF
"""
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


# 无穷大哨兵
INF = 0x7FFFFFFF


@dataclass
class Range:
    """整数区间 [lo, hi]。hi 为 INF 时表示无理论上限。"""
    lo: int = 0
    hi: int = INF

    @property
    def is_const(self) -> bool:
        return self.lo == self.hi and self.hi < INF

    @property
    def is_unknown(self) -> bool:
        return self.lo == 0 and self.hi >= INF

    def __repr__(self):
        hi_str = 'INF' if self.hi >= INF else str(self.hi)
        return f'[{self.lo}, {hi_str}]'


# 正则

_VAR_ASSIGN_RE = re.compile(
    r'(?:int|unsigned(?:\s+int)?|size_t|long|uint\w+_t|int\w+_t|ssize_t|short)\s+'
    r'(\w+)\s*=\s*([^;]+)\s*;',
)

_PLAIN_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*([^;]+)\s*;',
)

_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*(<=?|>=?)\s*(\w+)\s*\)',
)
# if (var > N) var = N; → var ≤ N (guard 上界)
_GUARD_CAP_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*[>]\s*(\w+)\s*\)\s*'
    r'(\w+)\s*=\s*(\w+)\s*;',
)
# if (var < N) var = N; → var ≥ N (guard 下界)
_GUARD_FLOOR_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*[<]\s*(\w+)\s*\)\s*'
    r'(\w+)\s*=\s*(\w+)\s*;',
)


class ValueRangeEngine:
    """值范围传播引擎: 在 C 源码上执行流敏感的范围分析。"""

    def __init__(self, source: str):
        self.source = source
        self.lines = source.splitlines()
        self.ranges: Dict[str, Range] = {}
        self.guards: List[Tuple[int, str, str, str]] = []
        self.guard_caps: List[Tuple[str, str, int]] = []  # (var, 'cap'|'floor', N)
        self.external_vars: set = set()

    def analyze(self) -> Dict[str, Range]:
        """执行值范围分析，返回每个变量的推断范围。"""
        self._find_external_vars()
        self._extract_guards()
        self._extract_guard_caps()    # if (var>N) var=N → var≤N
        self._propagate_assignments()
        self._apply_guard_cap_constraints()  # 先钳位 (后if状态)
        self._apply_guard_constraints()       # 后guard (跳过已被cap覆盖的变量)
        self._widen_loop_vars()
        return self.ranges

    def eval_expr(self, expr: str) -> Range:
        """求值表达式到范围。委托给 expr_evaluator 模块。"""
        from analysis.expr_evaluator import eval_expr_impl
        return eval_expr_impl(expr, self.ranges, self.external_vars)

    # 内部方法

    def _find_external_vars(self):
        """找出用户/外部输入变量。"""
        for m in re.finditer(
                r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul)',
                self.source, re.IGNORECASE):
            self.external_vars.add(m.group(1))
        for m in re.finditer(r'(\w+)\s*=\s*argv\[', self.source):
            self.external_vars.add(m.group(1))
        for m in re.finditer(r'(\w+)\s*=\s*getenv', self.source):
            self.external_vars.add(m.group(1))
        # scanf: scanf("..", &var)
        for m in re.finditer(r'scanf\s*\([^)]*&(\w+)', self.source):
            self.external_vars.add(m.group(1))
        # 函数参数 int size — 视为可能来自外部
        for m in re.finditer(
                r'(?:void|int)\s+\w+\s*\([^)]*\b(?:int|unsigned|size_t)\s+(\w+)[^)]*\)',
                self.source):
            param = m.group(1)
            # 只标记在 main 外部的函数中的 size 参数
            if re.search(rf'\b{param}\s*=\s*atoi|\b{param}\s*=\s*argv', self.source):
                self.external_vars.add(param)

    def _extract_guards(self):
        """提取 if (var <= N) 等守卫条件。"""
        for i, raw_line in enumerate(self.lines):
            line = raw_line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            gm = _GUARD_RE.search(line)
            if gm:
                self.guards.append((i + 1, gm.group(1), gm.group(2), gm.group(3)))

    def _extract_guard_caps(self):
        """提取 if (var > N) var = N; 和 if (var < N) var = N; 模式。

        这些模式定义了变量经过 if 语句后的有效范围:
          if (size > 128) size = 128; → size ≤ 128 (上界钳位)
          if (size < 32) size = 32;   → size ≥ 32  (下界抬升)
        """
        # 上界钳位: if (var > N) var = N;
        for m in _GUARD_CAP_RE.finditer(self.source):
            cond_var = m.group(1)
            bound_str = m.group(2)
            body_var = m.group(3)
            body_val_str = m.group(4)
            if cond_var == body_var and bound_str == body_val_str:
                bound_val = self._resolve_const(bound_str)
                if bound_val is not None:
                    self.guard_caps.append((cond_var, 'cap', bound_val))
            elif cond_var == body_var:
                bound_val_c = self._resolve_const(bound_str)
                body_val_c = self._resolve_const(body_val_str)
                if bound_val_c is not None and body_val_c is not None:
                    self.guard_caps.append((cond_var, 'cap', body_val_c))

        # 下界抬升: if (var < N) var = N;
        for m in _GUARD_FLOOR_RE.finditer(self.source):
            cond_var = m.group(1)
            bound_str = m.group(2)
            body_var = m.group(3)
            body_val_str = m.group(4)
            if cond_var == body_var and bound_str == body_val_str:
                bound_val = self._resolve_const(bound_str)
                if bound_val is not None:
                    self.guard_caps.append((cond_var, 'floor', bound_val))

    def _propagate_assignments(self):
        """流敏感赋值传播。"""
        for i, raw_line in enumerate(self.lines):
            line = raw_line.strip()
            if not line or line.startswith(('//', '/*', '#', 'if ', 'for ', 'while ')):
                continue

            vm = _VAR_ASSIGN_RE.search(line)
            if vm:
                var, expr = vm.group(1), vm.group(2).strip().rstrip(';')
                self.ranges[var] = self.eval_expr(expr)
                continue

            pm = _PLAIN_ASSIGN_RE.search(line)
            if pm:
                var, expr = pm.group(1), pm.group(2).strip().rstrip(';')
                if self._is_pointer_op(line):
                    continue
                r = self.eval_expr(expr)
                if r.is_unknown and var not in self.ranges:
                    continue
                self.ranges[var] = r

    def _apply_guard_constraints(self):
        """应用守卫条件约束。

        if (size <= N) → max(size) = min(max(size), N)
        if (size >= N) → min(size) = max(min(size), N)

        跳过已被 guard-cap 覆盖的变量: if(size>N)size=N 已由
        _apply_guard_cap_constraints 处理为 var≤N, 无需再应用 guard 约束。
        """
        cap_vars = {c[0] for c in self.guard_caps}
        for line_no, var, op, bound_str in self.guards:
            if var in cap_vars:
                continue  # 已由 guard-cap 处理
            if var not in self.ranges:
                continue
            bound_val = self._resolve_const(bound_str)
            if bound_val is None:
                continue
            cur = self.ranges[var]
            if op == '<=':
                self.ranges[var] = Range(lo=cur.lo, hi=min(cur.hi, bound_val))
            elif op == '<':
                self.ranges[var] = Range(lo=cur.lo, hi=min(cur.hi, bound_val - 1))
            elif op == '>=':
                self.ranges[var] = Range(lo=max(cur.lo, bound_val), hi=cur.hi)
            elif op == '>':
                self.ranges[var] = Range(lo=max(cur.lo, bound_val + 1), hi=cur.hi)

    def _apply_guard_cap_constraints(self):
        """应用 if (var > N) var = N 钳位约束。

        'cap': var ≤ N — 变量上界被 if-body 中的赋值钳制
        'floor': var ≥ N — 变量下界被 if-body 中的赋值抬升
        """
        for var, kind, bound_val in self.guard_caps:
            if var not in self.ranges:
                continue
            cur = self.ranges[var]
            if kind == 'cap':
                # var > N 时 var = N, 所以经过 if 后 var ≤ N
                self.ranges[var] = Range(lo=cur.lo, hi=min(cur.hi, bound_val))
            elif kind == 'floor':
                # var < N 时 var = N, 所以经过 if 后 var ≥ N
                self.ranges[var] = Range(lo=max(cur.lo, bound_val), hi=cur.hi)

    def _widen_loop_vars(self):
        """循环变量 widening: 外部输入的循环边界 → INF。"""
        for m in re.finditer(
                r'for\s*\(\s*\w+\s*=\s*\d+\s*;\s*\w+\s*[<]\s*(\w+)\s*;',
                self.source):
            bound_var = m.group(1)
            if bound_var in self.external_vars:
                self.ranges[bound_var] = Range(lo=0, hi=INF)

    def _resolve_const(self, expr: str) -> Optional[int]:
        """解析为整数常量 (含宏展开)。"""
        expr = expr.strip()
        if expr.isdigit():
            return int(expr)
        if re.match(r'^0x[0-9a-fA-F]+$', expr):
            return int(expr, 16)
        for m in re.finditer(rf'#define\s+{expr}\s+(\d+)', self.source):
            return int(m.group(1))
        return None

    def _is_pointer_op(self, line: str) -> bool:
        """判断是否为指针操作 (非 size 变量赋值)。"""
        if '=' not in line:
            return False
        rhs = line.split('=', 1)[-1]
        return bool(re.search(r'\*|->|\[', rhs))
