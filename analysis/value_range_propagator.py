"""
区间值范围传播 —— 沿def-use链传播变量的可能取值范围。

核心问题: 堆溢出检测中, malloc(size)的size和store offset都可能来自
变量表达式而非常量。现有代码遇到非常量直接跳过(skip)或置信度极低,
导致大量漏报(无法确定大小)和误报(假设最坏情况但实际安全)。

方法: 基于Widening/Narrowing的轻量区间抽象解释。
为每个相关变量维护一个 Interval(low, high), 沿IR行正向传播:
  - 赋值 var = const → [const, const]
  - 赋值 var = other_var → 复制other_var的区间
  - 算术 var = expr + const → 区间平移
  - 条件分支 if(var < N) → 在then分支内收缩high=min(high, N-1)
  - PHI节点 (合并点) → 取区间并集

不实现完整的抽象解释器 —— 仅针对堆溢出相关的size/offset变量做传播。
O(n*m) 其中 n=IR行数, m=跟踪变量数 (通常 m<10)。

  - Cousot & Cousot, POPL 1977: Abstract Interpretation framework
  - GUEB: Static heap buffer overflow via AI
  - SVF: Sparse value-flow for C/C++
  - CSA: Cross-domain sparse abstract execution
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class Interval:
    """整数区间 [low, high]。low=-inf 或 high=+inf 表示无界。"""
    low: int = -(2**63)
    high: int = 2**63 - 1

    @property
    def is_bottom(self) -> bool:
        return self.low > self.high

    @property
    def is_constant(self) -> bool:
        return self.low == self.high and not self.is_bottom

    def intersect(self, other: 'Interval') -> 'Interval':
        return Interval(max(self.low, other.low), min(self.high, other.high))

    def union(self, other: 'Interval') -> 'Interval':
        return Interval(min(self.low, other.low), max(self.high, other.high))

    def add(self, delta: int) -> 'Interval':
        lo = self.low + delta if self.low > -(2**62) else self.low
        hi = self.high + delta if self.high < 2**62 - 1 else self.high
        return Interval(lo, hi)

    def __repr__(self) -> str:
        return f'[{self.low}, {self.high}]'

@dataclass
class VarRange:
    """变量及其在不同程序点的值域。"""
    var_name: str
    ranges: Dict[int, Interval] = field(default_factory=dict)

    def at(self, pc: int) -> Interval:
        """查询变量在pc处的值域。若pc无记录, 返回最近的定义。"""
        if pc in self.ranges:
            return self.ranges[pc]
        prev_pcs = sorted([p for p in self.ranges if p <= pc])
        return self.ranges[prev_pcs[-1]] if prev_pcs else Interval()

    def set(self, pc: int, iv: Interval) -> None:
        self.ranges[pc] = iv

class ValueRangePropagator:
    """轻量区间值域传播器。

    不构建完整CFG, 而是沿IR行顺序扫描, 在关键控制流点(pragma/条件判断)
    注入区间约束。这种近似对于堆溢出检测足够 —— 因为要回答的问题是
    "store offset 是否必然 > alloc size", 只需要下界信息。
    """

    _ASSIGN_RE = re.compile(r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*|[+\-]?\d+)\s*([+\-*/])\s*(\w[\w\d_]*|[+\-]?\d+)')
    _CMP_RE = re.compile(r'(?:if|while)\s*\(\s*(\w[\w\d_]*)\s*(<|<=|>|>=|==|!=)\s*(\w[\w\d_]*|[+\-]?\d+)\s*\)')

    def __init__(self):
        self.ranges: Dict[str, VarRange] = {}

    def propagate(self, ir_lines: List[str],
                  track_vars: Optional[Set[str]] = None) -> Dict[str, VarRange]:
        """正向传播值域。

        track_vars 缺省时自动发现所有赋值目标;
        返回 {var_name: VarRange(各程序点的区间)}。
        """
        discovered = set(track_vars) if track_vars else set()
        if not track_vars:
            for line in ir_lines:
                m = re.match(r'(\w[\w\d_]*)\s*=', line)
                if m:
                    discovered.add(m.group(1))

        self.ranges = {v: VarRange(var_name=v) for v in discovered}

        for pc, line in enumerate(ir_lines):
            stripped = line.strip()
            self._process_line(stripped, pc, discovered)

        return self.ranges

    def _process_line(self, line: str, pc: int, track_vars: Set[str]) -> None:
        # 简单赋值: var = const
        m = re.match(r'(\w[\w\d_]*)\s*=\s*([+\-]?\d+)\s*;?$', line)
        if m and m.group(1) in track_vars:
            v = int(m.group(2))
            self.ranges[m.group(1)].set(pc, Interval(v, v))
            return

        # 算术赋值: var = other +/- const
        m = re.match(
            r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*([+\-])\s*(\d+)\s*;?$', line)
        if m and m.group(1) in track_vars:
            src = m.group(2)
            op = m.group(3)
            delta = int(m.group(4))
            if src in self.ranges:
                src_iv = self.ranges[src].at(pc)
                if not src_iv.is_bottom:
                    d = delta if op == '+' else -delta
                    self.ranges[m.group(1)].set(pc, src_iv.add(d))
            return

        # 变量复制: var = other_var
        m = re.match(r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*;?$', line)
        if m and m.group(1) in track_vars:
            src = m.group(2)
            if src in self.ranges:
                self.ranges[m.group(1)].set(pc, self.ranges[src].at(pc))
            return

        # 条件约束: if(var < N) 或 if(var <= N)
        m = re.search(
            r'(?:if|while)\s*[\(\s]*(\w[\w\d_]*)\s*(<|<=|>|>=|==)\s*(\w[\w\d_]*|[+\-]?\d+)\s*[\)\s]',
            line)
        if m:
            var = m.group(1)
            op = m.group(2)
            rhs = m.group(3)
            if var not in track_vars or var not in self.ranges:
                return
            try:
                n = int(rhs)
            except ValueError:
                if rhs in self.ranges:
                    rhs_iv = self.ranges[rhs].at(pc)
                    if rhs_iv.is_constant:
                        n = rhs_iv.low
                    else:
                        return
                else:
                    return
            cur = self.ranges[var].at(pc)
            if op == '<':
                narrowed = cur.intersect(Interval(-(2**63), n - 1))
            elif op == '<=':
                narrowed = cur.intersect(Interval(-(2**63), n))
            elif op == '>':
                narrowed = cur.intersect(Interval(n + 1, 2**63 - 1))
            elif op == '>=':
                narrowed = cur.intersect(Interval(n, 2**63 - 1))
            else:
                narrowed = cur.intersect(Interval(n, n))
            if not narrowed.is_bottom:
                self.ranges[var].set(pc, narrowed)

    def query(self, var: str, pc: int) -> Interval:
        """查询变量在pc处的值域。"""
        if var not in self.ranges:
            return Interval()
        return self.ranges[var].at(pc)

def extract_size_constraints_from_ir(
    ir_lines: List[str],
    alloc_var: str,
) -> Tuple[Interval, float]:
    """从IR中提取分配变量的值域约束。

    返回 (interval, confidence)。
    confidence表示区间推断的可靠程度 —— 常量>常量传播>推测。
    """
    prop = ValueRangePropagator()
    prop.propagate(ir_lines, {alloc_var})

    iv = prop.query(alloc_var, len(ir_lines) - 1)

    if iv.is_constant:
        return iv, 0.95
    if iv.low > -(2**63) or iv.high < 2**63 - 1:
        return iv, 0.65
    return iv, 0.20
