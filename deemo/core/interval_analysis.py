# interval_analysis.py - 区间抽象分析: 追踪缓冲区大小相关变量的数值区间。
# 若溢出条件在区间内可证明不可满足, 则排除该候选; 实现最简子集: 函数内区间分析 O(n*k)。

from typing import Dict, Tuple, Optional
import re

class Interval:
    """区间 [lo, hi], 特殊值: bottom(矛盾), top(无界)。"""
    __slots__ = ("lo", "hi", "is_top", "is_bottom")
    def __init__(self, lo=None, hi=None):
        if lo is None: self.lo = float("-inf"); self.hi = float("inf"); self.is_top = True; self.is_bottom = False
        else: self.lo = float(lo); self.hi = float(hi); self.is_top = False; self.is_bottom = False
    @staticmethod
    def top(): return Interval(None, None)
    @staticmethod
    def bottom(): i = Interval(0, -1); i.is_bottom = True; i.is_top = False; return i
    @staticmethod
    def const(v): return Interval(v, v)
    def __add__(self, other):
        if self.is_bottom or other.is_bottom: return Interval.bottom()
        if self.is_top or other.is_top: return Interval.top()
        return Interval(self.lo + other.lo, self.hi + other.hi)
    def __mul__(self, other):
        if self.is_bottom or other.is_bottom: return Interval.bottom()
        if self.is_top or other.is_top: return Interval.top()
        prods = [self.lo*other.lo, self.lo*other.hi, self.hi*other.lo, self.hi*other.hi]
        return Interval(min(prods), max(prods))
    def widen(self, other):
        """宽化算子 - 保证不动点迭代收敛。"""
        if self.is_top or other.is_top: return Interval.top()
        if self.is_bottom: return other
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))
    def contains(self, value: float) -> bool:
        return self.lo <= value <= self.hi
    def __repr__(self):
        if self.is_top: return "T"
        if self.is_bottom: return r"_|_"
        return f"[{self.lo},{self.hi}]"

class BufferSizeAnalyzer:
    """追踪栈缓冲区大小的区间分析器。"""
    def __init__(self):
        self._vars: Dict[str, Interval] = {}
    def set_range(self, var, lo, hi):
        self._vars[var] = Interval(lo, hi)
    def analyze_write(self, buffer_var, write_count) -> bool:
        """返回是否可能溢出: write_count > 缓冲区大小。"""
        buf = self._vars.get(buffer_var, Interval.top())
        if buf.is_top: return True  # unknown -> conservative: keep candidate
        if buf.is_bottom: return False
        return write_count > buf.hi
    def is_safe(self, buffer_var, max_write) -> bool:
        buf = self._vars.get(buffer_var, Interval.top())
        if buf.is_top: return False
        if buf.is_bottom: return True
        return max_write <= buf.hi


class IntervalAnalyzer:
    """区间抽象分析器：跟踪缓冲区容量与写入索引区间，判定越界写入。

    输入为逐行 IR 文本，识别三类语句：
      - 缓冲区声明: char buf[32] / int arr[16]
      - 变量赋值:   i = <expr>
      - 数组写入:   buf[i] = v

    写入索引以 Interval 表示，与缓冲区容量比较判定越界；索引不可解析或
    越出已知区间时保守处理，不做无依据判定。
    """

    def __init__(self) -> None:
        self._buffers: Dict[str, int] = {}
        self._ranges: Dict[str, Interval] = {}
        self._violations = []

    def analyze(self, lines, func_name: str = ''):
        """逐行处理 IR，更新缓冲区/区间状态，记录越界写入。"""
        for line in (lines or []):
            self._process_line(line)
        return self

    def _process_line(self, line: str) -> None:
        decl = re.match(
            r'\s*(?:char|int|unsigned\s+int|long|short|size_t|void)\s+(\w+)\s*\[\s*(\d+)\s*\]',
            line)
        if decl:
            self._buffers[decl.group(1)] = int(decl.group(2))
            return

        assign = re.match(r'\s*(\w+)\s*=\s*(.+)', line)
        if assign:
            var, expr = assign.group(1), assign.group(2).strip()
            self._ranges[var] = self._eval_expr(expr)
            return

        write = re.match(r'\s*(\w+)\s*\[\s*([^\]]+)\s*\]\s*=', line)
        if write:
            self._check_write(write.group(1), write.group(2).strip())

    def _eval_expr(self, expr: str) -> Interval:
        """解析表达式为区间：常量、变量、变量±常量偏移；其余返回 top。"""
        expr = expr.split('//')[0].strip()
        if re.fullmatch(r'-?\d+', expr):
            return Interval.const(int(expr))
        if expr in self._ranges:
            return self._ranges[expr]
        m = re.fullmatch(r'(\w+)\s*([+-])\s*(\d+)', expr)
        if m:
            base = self._ranges.get(m.group(1))
            if base is not None and not base.is_top:
                off = int(m.group(3))
                if m.group(2) == '+':
                    return Interval(base.lo + off, base.hi + off)
                return Interval(base.lo - off, base.hi - off)
        return Interval.top()

    def _check_write(self, buf: str, idx_expr: str) -> None:
        """将写入索引区间与缓冲区容量比较，越界则记录违规。"""
        size = self._buffers.get(buf)
        if size is None:
            return
        idx = self._eval_expr(idx_expr)
        if idx.is_top or idx.is_bottom:
            return
        if idx.lo < 0 or idx.hi >= size:
            self._violations.append({
                'buffer': buf,
                'index': idx_expr,
                'index_range': [idx.lo, idx.hi],
                'buffer_size': size,
            })

    def summary(self) -> Dict[str, object]:
        """输出分析摘要：违规数、缓冲区容量表与变量区间表。"""
        return {
            'violations': len(self._violations),
            'buffers': dict(self._buffers),
            'ranges': {k: str(v) for k, v in self._ranges.items()},
        }