"""
守卫条件分析器 — 识别约束分配大小的边界守卫, 消除"已守卫但仍告警"的误报.
核心问题: if(n>MAX)n=MAX; p=malloc(n); memcpy(p,src,n) — 现有检测只看 malloc(n) 和 memcpy(n),
         忽略了守卫将 n 钳制到安全范围内, 产生误报.
方法:
  1. 扫描 malloc 前的守卫条件: if(n>MAX)n=MAX / n = min(n, MAX) / n = n>MAX ? MAX : n
  2. 约束传播: 在守卫后的代码路径上, n ∈ [原始下界, MAX]
  3. alloc/write 检查时应用守卫缩窄后的区间

与现有约束追踪的区别:
  - PathCondition 追踪分支条件 (if(n<256)), 但守卫是对变量的赋值修改, 不是条件
  - 本模块追踪变量赋值语句中的钳制模式 (n=min(n,MAX)), 补充 PathCondition 的盲区
参考: USENIX 2024 "SUTURE" guard-aware analysis, ICSE 2024 "Cross-Domain Interaction".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


# 守卫模式

# if (n > MAX) n = MAX;
_RE_IF_CLAMP = re.compile(
    r'if\s*\(\s*(\w+)\s*>\s*(\d+|\w+)\s*\)\s*(\w+)\s*=\s*(\d+|\w+)\s*;')

# n = (n > MAX) ? MAX : n;
_RE_TERNARY_CLAMP = re.compile(
    r'(\w+)\s*=\s*\(?\s*\w+\s*[><=]+\s*(\d+|\w+)\s*\)?\s*\?\s*(\d+|\w+)\s*:\s*(\w+)')

# n = min(n, MAX); n = MIN(n, MAX);
_RE_MIN_CALL = re.compile(r'(\w+)\s*=\s*(?:MIN|min)\s*\(\s*(\w+),\s*(\d+|\w+)\s*\)')

# if (__builtin_expect(n > MAX, 0)) n = MAX;
_RE_BUILTIN_CLAMP = re.compile(
    r'if\s*\(\s*__builtin_expect\s*\(\s*(\w+)\s*>\s*(\d+),\s*\d+\s*\)\s*\)\s*(\w+)\s*=\s*(\d+)')

# size = size > MAX ? MAX : size;
_RE_SELF_CLAMP = re.compile(
    r'(\w+)\s*=\s*\1\s*>\s*(\d+)\s*\?\s*\2\s*:\s*\1')

# 正向守卫: if (n <= SAFE_MAX) { malloc(n); memcpy(..., n); }
_RE_POSITIVE_GUARD = re.compile(
    r'if\s*\(\s*(\w+)\s*(<=|<)\s*(\d+)\s*\)')

# __builtin_mul_overflow / __builtin_add_overflow — 硬件溢出保护
_RE_BUILTIN_OVERFLOW = re.compile(
    r'__builtin_(mul|add|sub)_overflow\s*\(')

# safe_mul / _chk_range 封装函数
_RE_SAFE_WRAPPER = re.compile(
    r'(safe_mul|_chk_range|checked_mul|size_mul)\s*\(')


@dataclass
class GuardInfo:
    """守卫信息."""
    var: str                # 被守卫的变量
    upper_bound: int        # 钳制上界
    guard_type: str         # "clamp" | "min_call" | "ternary" | "positive_branch"
    line_no: int
    safe_max: Optional[int] = None  # 正向守卫的安全上界


class GuardAnalyzer:
    """守卫条件分析器 — 提取分配大小变量的安全边界.

    核心思想: 在 malloc(size) 之前, size 可能被守卫语句钳制.
    若钳制后的最大值 ≤ 分配器有效容量, 且写入大小 ≤ 该最大值 → SAFE.
    """

    def __init__(self):
        self._guards: List[GuardInfo] = []
        self._overflow_protection: Set[str] = set()  # 有硬件溢出保护的变量

    def clear(self):
        self._guards.clear()
        self._overflow_protection.clear()

    def scan_function(self, code: str) -> List[GuardInfo]:
        """扫描函数, 提取所有守卫条件."""
        self.clear()
        lines = code.split('\n')

        for i, raw in enumerate(lines):
            line = raw.strip()
            if not line or line.startswith('//'):
                continue

            # if (n > MAX) n = MAX;
            m = _RE_IF_CLAMP.search(line)
            if m:
                var, bound, lhs = m.group(1), m.group(2), m.group(3)
                if var == lhs:
                    try:
                        self._guards.append(GuardInfo(
                            var=var, upper_bound=int(bound),
                            guard_type='clamp', line_no=i))
                    except ValueError:
                        pass

            # n = min(n, MAX);
            m = _RE_MIN_CALL.search(line)
            if m:
                try:
                    self._guards.append(GuardInfo(
                        var=m.group(1), upper_bound=int(m.group(3)),
                        guard_type='min_call', line_no=i))
                except ValueError:
                    pass

            # n = (n > MAX) ? MAX : n;
            m = _RE_TERNARY_CLAMP.search(line)
            if m:
                try:
                    val = int(m.group(3)) if m.group(3).isdigit() else None
                    if val is not None:
                        self._guards.append(GuardInfo(
                            var=m.group(1), upper_bound=val,
                            guard_type='ternary', line_no=i))
                except ValueError:
                    pass

# builtin_mul_overflow 检测
            if _RE_BUILTIN_OVERFLOW.search(line):
                # 提取第一个参数 — 通常是结果指针
                args_match = re.search(r'__builtin_\w+_overflow\s*\(\s*([^,]+)', line)
                if args_match:
                    # 识别被保护的变量
                    for var_match in re.finditer(r'(\w+)', args_match.group(1)):
                        self._overflow_protection.add(var_match.group(1))

            # safe_mul 等封装
            if _RE_SAFE_WRAPPER.search(line):
                for var_match in re.finditer(r'(\w+)', line):
                    self._overflow_protection.add(var_match.group(1))

            # 正向守卫 if (n <= SAFE_MAX) { ... }
            pm = _RE_POSITIVE_GUARD.search(line)
            if pm:
                try:
                    self._guards.append(GuardInfo(
                        var=pm.group(1), upper_bound=int(pm.group(3)),
                        guard_type='positive_branch', line_no=i,
                        safe_max=int(pm.group(3))))
                except ValueError:
                    pass

        return self._guards

    def get_bound(self, var: str) -> Optional[int]:
        """返回变量被守卫钳制后的上界 (取最紧的)."""
        bounds = [g.upper_bound for g in self._guards if g.var == var]
        return min(bounds) if bounds else None

    def is_guarded(self, var: str) -> bool:
        """变量是否有任何守卫保护."""
        return bool([g for g in self._guards if g.var == var])

    def is_overflow_protected(self, var: str) -> bool:
        """是否有硬件溢出保护或 safe_mul 包装."""
        return var in self._overflow_protection

    def get_effective_max(self, var: str, default: int = 2**31 - 1) -> int:
        """获取变量的有效最大值 (守卫后)."""
        bound = self.get_bound(var)
        return bound if bound is not None else default


# 便捷函数

def analyze_guards(code: str) -> GuardAnalyzer:
    """便捷函数: 扫描代码返回 GuardAnalyzer."""
    ga = GuardAnalyzer()
    ga.scan_function(code)
    return ga


__all__ = ['GuardAnalyzer', 'GuardInfo', 'analyze_guards']
