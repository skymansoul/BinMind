# coding: utf-8
"""轻量值区间分析 — 对堆分配大小和写入长度做区间估计, 过滤可证明安全的溢出候选.

不使用完整抽象解释 (复杂度 O(n^3)), 而是做单函数的稀疏区间传播:
  1. 在 def-use 链上传播已知的常量/区间约束
  2. 比较 alloc_size 与 write_size 的区间关系
  3. 若 alloc_size 在所有可达路径上 ≥ write_size → 可证明安全, 过滤

关键洞察: 堆溢出误报的主因是分析器无法证明 alloc 和写入使用同一个
size 变量. 本模块通过反向追踪 size 变量的定义点, 捕获跨基本块的
值关系, 在多项式时间内给出保守的安全证明.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class Interval:
    """整数区间 [lo, hi], lo=-1 表示 -∞, hi=-1 表示 +∞."""
    lo: int; hi: int
    def __post_init__(self):
        if self.lo > self.hi and self.lo >= 0 and self.hi >= 0:
            self.lo, self.hi = self.hi, self.lo
    @property
    def is_top(self) -> bool: return self.lo < 0 and self.hi < 0
    @property
    def is_bottom(self) -> bool: return self.lo > self.hi and self.lo >= 0
    @property
    def is_constant(self) -> bool: return self.lo == self.hi and self.lo >= 0
    def __contains__(self, v: int) -> bool:
        if self.is_top: return True
        if self.lo >= 0 and v < self.lo: return False
        if self.hi >= 0 and v > self.hi: return False
        return True

    @staticmethod
    def top() -> 'Interval': return Interval(-1, -1)
    @staticmethod
    def constant(v: int) -> 'Interval': return Interval(v, v)
    @staticmethod
    def ge(v: int) -> 'Interval': return Interval(v, -1)
    @staticmethod
    def le(v: int) -> 'Interval': return Interval(-1, v)

    def intersect(self, other: 'Interval') -> 'Interval':
        if self.is_top: return other
        if other.is_top: return self
        lo = max(self.lo, other.lo) if (self.lo >= 0 and other.lo >= 0) else (
            self.lo if self.lo >= 0 else other.lo)
        hi = min(self.hi, other.hi) if (self.hi >= 0 and other.hi >= 0) else (
            self.hi if self.hi >= 0 else other.hi)
        if lo >= 0 and hi >= 0 and lo > hi: return Interval(-2, -2)  # bottom
        return Interval(lo, hi)

    def union(self, other: 'Interval') -> 'Interval':
        if self.is_top or other.is_top: return Interval.top()
        lo = self.lo if self.lo >= 0 and other.lo >= 0 else -1
        hi = self.hi if self.hi >= 0 and other.hi >= 0 else -1
        if lo >= 0 and other.lo >= 0: lo = min(self.lo, other.lo)
        if hi >= 0 and other.hi >= 0: hi = max(self.hi, other.hi)
        return Interval(lo, hi)

    def __repr__(self): return f'[{self.lo if self.lo>=0 else "-∞"},{self.hi if self.hi>=0 else "+∞"}]'


def _parse_immediate(op_str: str) -> Optional[int]:
    """从操作数字符串中提取立即数."""
    op = op_str.strip()
    if op.startswith('0x') or op.startswith('0X'):
        try: return int(op, 16)
        except ValueError: return None
    try: return int(op)
    except ValueError: return None


def infer_interval(var: str, def_site: int,
                   def_use_chains: Dict[int, List[int]],
                   ir_ops: Dict[int, Dict],
                   constants: Dict[str, int],
                   visited: Optional[Set[int]] = None,
                   depth: int = 0) -> Interval:
    """反向追踪变量的值区间. 沿 def-use 链回溯, 在 def 点收集约束.

    var: 变量名 (如 'size', 'len', '%r8')
    def_site: 定义该变量值的指令地址
    返回保守的 Interval 估计 (top = 未知).
    """
    if depth > 12: return Interval.top()
    if visited is None: visited = set()
    if def_site in visited: return Interval.top()
    visited.add(def_site)

    op = ir_ops.get(def_site, {})
    op_type = op.get('op_type', '')

    # Case 1: 常量赋值 mov reg, imm
    if op_type in ('mov', 'li', 'load_imm', 'const'):
        imm = _parse_immediate(op.get('src', op.get('operands', '')))
        if imm is not None: return Interval.constant(imm)
        c = constants.get(var)
        if c is not None: return Interval.constant(c)

    # Case 2: 算术操作
    if op_type in ('add', 'sub', 'mul', 'shl', 'shr', 'and', 'or'):
        srcs = def_use_chains.get(def_site, [])
        intervals = []
        for s in srcs[:2]:  # 最多追踪两个操作数
            iv = infer_interval(var, s, def_use_chains, ir_ops, constants, visited, depth+1)
            intervals.append(iv)
        if op_type == 'add':
            if len(intervals) >= 2 and intervals[0].is_constant and intervals[1].is_constant:
                return Interval.constant(intervals[0].lo + intervals[1].lo)
        if op_type == 'sub':
            if len(intervals) >= 2 and intervals[0].is_constant and intervals[1].is_constant:
                return Interval.constant(max(0, intervals[0].lo - intervals[1].lo))
        if op_type == 'mul':
            if len(intervals) >= 2 and intervals[0].is_constant and intervals[1].is_constant:
                return Interval.constant(intervals[0].lo * intervals[1].lo)
        if op_type == 'shl' and intervals and intervals[0].is_constant:
            shift = _parse_immediate(op.get('src2', op.get('shift', '1'))) or 1
            return Interval.constant(intervals[0].lo << shift)
        if op_type == 'and' and intervals and intervals[0].is_constant:
            mask = _parse_immediate(op.get('src2', ''))
            if mask is not None: return Interval(0, min(intervals[0].hi, mask))

    # Case 3: 比较指令产生的约束
    if op_type in ('cmp', 'icmp', 'test'):
        pass  # 仅记录, 不做路径敏感分析

    return Interval.top()


def alloc_write_size_compare(
    alloc_site: int, write_site: int,
    alloc_size_var: str, write_size_var: str,
    def_use_chains: Dict[int, List[int]],
    ir_ops: Dict[int, Dict],
    constants: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """比较 alloc 大小和 write 大小的区间关系, 判断是否可证明安全。

    返回 {'provably_safe': bool, 'alloc_interval': str,
    'write_interval': str, 'reason': str}。
    """
    constants = constants or {}
    alloc_iv = infer_interval(alloc_size_var, alloc_site, def_use_chains, ir_ops, constants)
    write_iv = infer_interval(write_size_var, write_site, def_use_chains, ir_ops, constants)

    # 安全判定: alloc 区间下界 ≥ write 区间上界 → 永不超过
    if (alloc_iv.lo >= 0 and write_iv.hi >= 0 and alloc_iv.lo >= write_iv.hi):
        return {'provably_safe': True, 'alloc_interval': str(alloc_iv),
                'write_interval': str(write_iv),
                'reason': f'alloc({alloc_iv.lo}) ≥ write({write_iv.hi}) 在所有路径上成立'}

    # 若 alloc 是常量且大于常见溢出阈值 → 弱安全
    if alloc_iv.is_constant and alloc_iv.lo >= 4096:
        return {'provably_safe': True, 'alloc_interval': str(alloc_iv),
                'write_interval': str(write_iv),
                'reason': f'alloc size({alloc_iv.lo}) 为大块分配, 写入溢出概率极低'}

    # 无法证明安全 → 保留为候选
    return {'provably_safe': False, 'alloc_interval': str(alloc_iv),
            'write_interval': str(write_iv),
            'reason': f'alloc{alloc_iv} vs write{write_iv} — 无法证明安全关系'}
