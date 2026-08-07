"""
Forward interval propagation — interval domain + IR parsing + convenience API.

This module defines the Interval abstract domain, IR parsing regexes,
dataclasses, and the standalone eval_rhs_interval() function.

The ForwardIntervalPropagator class has been extracted to
core/interval_propagator.py for modularity (≤300-line constraint).

  - Cousot & Cousot, "Abstract Interpretation: A Unified Lattice Model"
  - Guo et al., "Heap Disjointness" — value-range reasoning for heap
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# interval domain ──────────────────────────────────────────────────

@dataclass
class Interval:
    """Integer interval [lo, hi]. lo=-1 means -inf; hi=2**63-1 means +inf."""
    lo: int
    hi: int

    @staticmethod
    def unknown() -> "Interval":
        return Interval(-1, 2**63 - 1)

    @staticmethod
    def exact(v: int) -> "Interval":
        return Interval(v, v)

    @staticmethod
    def range_(lo: int, hi: int) -> "Interval":
        return Interval(lo, hi)

    @property
    def is_top(self) -> bool:
        return self.lo == -1 and self.hi >= 2**63 - 1

    @property
    def is_bottom(self) -> bool:
        return self.lo > self.hi

    @property
    def is_constant(self) -> bool:
        return self.lo == self.hi and self.lo >= 0

    def __add__(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval(1, 0)
        lo = self.lo + other.lo if (self.lo >= 0 and other.lo >= 0) else -1
        hi = (self.hi + other.hi if (self.hi < 2**63 - 1 and other.hi < 2**63 - 1)
              else 2**63 - 1)
        return Interval(lo, min(hi, 2**63 - 1))

    def __sub__(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval(1, 0)
        lo = (self.lo - other.hi if (self.lo >= 0 and other.hi < 2**63 - 1)
              else -1)
        hi = (self.hi - other.lo if (self.hi < 2**63 - 1 and other.lo >= 0)
              else 2**63 - 1)
        return Interval(max(-1, lo), min(hi, 2**63 - 1))

    def __mul__(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval(1, 0)
        if self.lo < 0 or other.lo < 0:
            return Interval.unknown()
        cand = [self.lo * other.lo, self.lo * other.hi,
                self.hi * other.lo, self.hi * other.hi]
        return Interval(min(cand), min(max(cand), 2**63 - 1))

    def widen(self, other: "Interval") -> "Interval":
        lo = -1 if (other.lo < self.lo or self.lo == -1) else self.lo
        hi = 2**63 - 1 if (other.hi > self.hi or self.hi >= 2**63 - 1) else self.hi
        return Interval(lo, hi)

    def union(self, other: "Interval") -> "Interval":
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        lo = self.lo if self.lo <= other.lo or other.lo < 0 else other.lo
        if self.lo < 0 or other.lo < 0:
            lo = -1
        hi = self.hi if self.hi >= other.hi else other.hi
        if self.hi >= 2**63 - 1 or other.hi >= 2**63 - 1:
            hi = 2**63 - 1
        return Interval(lo, hi)

    def intersect(self, other: "Interval") -> "Interval":
        lo = max(self.lo, other.lo) if (self.lo >= 0 and other.lo >= 0) \
            else max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        if lo > hi:
            return Interval(1, 0)
        return Interval(lo, hi)

    def contains(self, v: int) -> bool:
        return (self.lo < 0 or v >= self.lo) and \
               (self.hi >= 2**63 - 1 or v <= self.hi)

    def __repr__(self) -> str:
        lo_s = str(self.lo) if self.lo >= 0 else "-inf"
        hi_s = str(self.hi) if self.hi < 2**63 - 1 else "+inf"
        return f"[{lo_s}, {hi_s}]"

# IR parsing regexes (shared) ──────────────────────────────────────

_C_TYPE_KEYWORDS = {
    'int', 'char', 'short', 'long', 'float', 'double', 'void',
    'unsigned', 'signed', 'size_t', 'ssize_t', 'BOOL', 'BYTE',
    'WORD', 'DWORD', 'QWORD', 'uint8_t', 'uint16_t', 'uint32_t',
    'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'const', 'static', 'volatile', 'extern', 'register',
    'struct', 'union', 'enum',
}

_ASSIGN_RE = re.compile(r'(\w[\w.]*)\s*=\s*(.+)')
_MALLOC_RE = re.compile(
    r'malloc\s*\(\s*(\d+|\w[\w.]*(?:\s*[+\-*/]\s*(?:\d+|\w[\w.]*))*)\s*\)')
_CALLOC_RE = re.compile(
    r'calloc\s*\(\s*(\d+|\w[\w.]*)\s*,\s*(\d+|\w[\w.]*)\s*\)')
_REALLOC_RE = re.compile(
    r'realloc\s*\(\s*\w[\w.]*\s*,\s*(\d+|\w[\w.]*(?:\s*[+\-*/]\s*(?:\d+|\w[\w.]*))*)\s*\)')
_MEMCPY_RE = re.compile(
    r'(?:memcpy|__memcpy_chk|strncpy|memmove)\s*\(\s*'
    r'(\w[\w.\->]*)\s*,\s*[^,]*\s*,\s*((?:[^()]|\([^)]*\))+)\s*\)')
_STRCPY_RE = re.compile(
    r'(?:strcpy|strcat|sprintf|wcscpy)\s*\(\s*(\w[\w.\->]*)\s*,')
_CMP_RE = re.compile(r'(?:cmp|if)\s*\(?\s*(\w[\w.]*)\s*(<|<=|>|>=|==)\s*(\d+|\w[\w.]*)')
_INCR_RE = re.compile(r'(\w[\w.]*)\s*=\s*\1\s*([+-])\s*(\d+)')

# dataclasses ───────────────────────────────────────────────────────

@dataclass
class IRStatement:
    """One analyzed IR statement."""
    idx: int
    var: str = ""
    rhs: str = ""
    is_malloc: bool = False
    is_write: bool = False
    alloc_size_var: str = ""
    write_dst_var: str = ""
    write_size_var: str = ""

@dataclass
class AllocSite:
    loc: int
    var_name: str
    size_interval: Interval

@dataclass
class WriteSite:
    loc: int
    dst_var: str
    size_interval: Interval

# standalone expression evaluator ──────────────────────────────────

def eval_rhs_interval(rhs: str, state: Dict[str, Interval]) -> Interval:
    """Evaluate RHS expression to an interval, given current variable state.

    Extracted from ForwardIntervalPropagator._eval_rhs to make it reusable
    without requiring a class instance. Uses only `rhs` and `state` params.
    """
    rhs = rhs.strip()

    # Integer literal
    try:
        v = int(rhs, 0)
        return Interval.exact(v)
    except (ValueError, TypeError):
        pass

    # Variable reference
    if re.match(r'^[a-zA-Z_]\w*$', rhs) and rhs in state:
        return state[rhs]

    # 常量*常量 (calloc count*size, masked+1)
    m_cc = re.match(r'^(\d+)\s*([+\-*])\s*(\d+)$', rhs)
    if m_cc:
        a, op, b = int(m_cc.group(1)), m_cc.group(2), int(m_cc.group(3))
        if op == '+':   return Interval.exact(a + b)
        elif op == '-': return Interval.exact(a - b)
        elif op == '*': return Interval.exact(a * b)

    # var op const
    m = re.match(r'(\w[\w.]*)\s*([+\-*])\s*(\d+)$', rhs)
    if m:
        base_var, op, const = m.group(1), m.group(2), int(m.group(3))
        base = state.get(base_var, Interval.unknown())
        if op == '+':   return base + Interval.exact(const)
        elif op == '-': return base - Interval.exact(const)
        elif op == '*': return base * Interval.exact(const)

    # const op var
    m_cv = re.match(r'^(\d+)\s*([+\-*])\s*(\w[\w.]*)$', rhs)
    if m_cv:
        const, op, var = int(m_cv.group(1)), m_cv.group(2), m_cv.group(3)
        base = state.get(var, Interval.unknown())
        if op == '+':   return Interval.exact(const) + base
        elif op == '*': return Interval.exact(const) * base

    # Bitwise AND: var & mask → [0, mask] (sound over-approximation)
    m_and = re.match(r'^(\w[\w.]*)\s*&\s*(0x[0-9a-fA-F]+|\d+)$', rhs)
    if m_and:
        return Interval.range_(0, int(m_and.group(2), 0))

    # var + const (const as numeric literal)
    m_add_id = re.match(r'^(\w[\w.]*)\s*\+\s*(\d+)$', rhs)
    if m_add_id:
        base = state.get(m_add_id.group(1), Interval.unknown())
        return base + Interval.exact(int(m_add_id.group(2)))

    return Interval.unknown()

# convenience API ──────────────────────────────────────────────────

def analyze_heap_bounds_forward(ir_lines: List[str]) -> Dict:
    """Convenience wrapper: forward interval analysis for heap bounds.

    Returns dict with alloc_sites, write_sites, and overflow candidates.
    """
    from core.interval_propagator import ForwardIntervalPropagator

    engine = ForwardIntervalPropagator()
    allocs, writes = engine.analyze(ir_lines)

    overflow_candidates = []
    for alloc in allocs:
        if alloc.size_interval.is_top:
            continue
        alloc_hi = alloc.size_interval.hi
        for write in writes:
            # 支持struct字段访问: c->payload → c (字段写入即base分配写入)
            write_base = write.dst_var.split('->')[0].split('.')[0]
            if write_base != alloc.var_name:
                continue
            if write.size_interval.is_top:
                continue
            write_lo = write.size_interval.lo
            if write_lo >= 0 and write_lo > alloc_hi:
                overflow_candidates.append({
                    'alloc_var': alloc.var_name,
                    'alloc_size_range': str(alloc.size_interval),
                    'write_size_range': str(write.size_interval),
                    'overflow_min': write_lo - alloc_hi,
                    'confidence': 0.85,
                    'alloc_loc': alloc.loc,
                    'write_loc': write.loc,
                })

    return {
        'alloc_sites': allocs,
        'write_sites': writes,
        'overflow_candidates': overflow_candidates,
    }

__all__ = [
    'Interval', 'IRStatement', 'AllocSite', 'WriteSite',
    'eval_rhs_interval', 'analyze_heap_bounds_forward',
    # Re-exported regexes for interval_propagator.py
    '_C_TYPE_KEYWORDS', '_ASSIGN_RE', '_MALLOC_RE', '_CALLOC_RE',
    '_REALLOC_RE', '_MEMCPY_RE', '_STRCPY_RE', '_CMP_RE', '_INCR_RE',
]
