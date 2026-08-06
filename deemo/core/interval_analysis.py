# Interval abstraction analysis: tracks numerical ranges for buffer sizes.
#
# For each candidate vulnerability, tracks variable ranges via interval abstraction.
# If overflow conditions are provably unsatisfiable within the interval, the
# candidate is ruled out. Reference: Crab (SRI 2024).
#
# This module implements the simplest subset: intraprocedural interval analysis
# with O(n*k) complexity.

from __future__ import annotations
from typing import Dict, Tuple, Optional

class Interval:
    """Interval [lo, hi] with special values: empty (contradiction), top (unbounded)."""
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
        """Widening operator: ensures termination of fixed-point iteration."""
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
    """Interval analyzer for tracking stack buffer sizes."""
    def __init__(self):
        self._vars: Dict[str, Interval] = {}
    def set_range(self, var, lo, hi):
        self._vars[var] = Interval(lo, hi)
    def analyze_write(self, buffer_var, write_count) -> bool:
        """Return True if overflow is possible: write_count > buffer_size."""
        buf = self._vars.get(buffer_var, Interval.top())
        if buf.is_top: return True  # unknown -> conservative: keep candidate
        if buf.is_bottom: return False
        return write_count > buf.hi
    def is_safe(self, buffer_var, max_write) -> bool:
        buf = self._vars.get(buffer_var, Interval.top())
        if buf.is_top: return False
        if buf.is_bottom: return True
        return max_write <= buf.hi