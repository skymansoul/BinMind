"""
Affine relation analyzer — computes affine state at each IR program point.

Forward abstract interpretation over the affine relation domain. At each
assignment, updates the AffineDomain; at malloc/memcpy, records the
affine state for later overflow verification.

This is Stage 2.5 in the GAPSBV pipeline: sits between constraint
collection (Stage 2) and loop inference (Stage 3). Feeds affine-proven
overflow/safety results into the verifier to resolve candidates that
the interval domain alone cannot decide.

Key patterns detected:
  - Multiplicative: m = n * 2; malloc(n); memcpy(p, src, m) → overflow
  - Additive: buf = malloc(n); memcpy(buf+8, src, n) → overflow (offset)
  - Safety: buf = malloc(n+8); memcpy(buf, src, n) → safe (with slack)
  - Chain: a = b+1; c = a*2 → c = 2*b + 2

  - Karr 1976, Müller-Olm & Seidl 2004
  - Our own AffineDomain in core/affine_relation.py
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from core.affine_relation import AffineDomain

# pattern recognizers ──────────────────────────────────────────────

# Assignment: var = const
_CONST_ASSIGN_RE = re.compile(r'^(\w[\w.]*)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)\s*;?$')

# Assignment: var = other_var
_ALIAS_ASSIGN_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*;?$')

# Assignment: var = other_var + const
_ADD_CONST_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*\+\s*(-?\d+)\s*;?$')

# Assignment: var = other_var * const
_MUL_CONST_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*\*\s*(\d+)\s*;?$')

# Assignment: var = const * other_var
_CONST_MUL_RE = re.compile(r'^(\w[\w.]*)\s*=\s*(\d+)\s*\*\s*([a-zA-Z_]\w*)\s*;?$')

# Assignment: var = other_var - const
_SUB_CONST_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*-\s*(\d+)\s*;?$')

# malloc: var = malloc(size_var)
_MALLOC_ASSIGN_RE = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*(?:malloc|realloc)\s*'
    r'\(\s*(\w[\w.]*)\s*')

# calloc: var = calloc(count, elem_size) — 取非数字参数作为size_var
_CALLOC_ASSIGN_RE = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*calloc\s*'
    r'\(\s*(\w[\w.]*)\s*,\s*(\w[\w.]*)\s*\)')

# memcpy: memcpy(dst, src, size_var)
_MEMCPY_ASSIGN_RE = re.compile(
    r'(?:memcpy|memmove|strncpy)\s*\(\s*(\w[\w.]*)\s*,\s*[^,]*,\s*'
    r'(\w[\w.]*)\s*\)')

class AffineAnalyzer:
    """Forward affine relation analyzer for heap overflow variables.

    Tracks affine relations across IR lines. At malloc and memcpy sites,
    records the current affine state for later overflow verification.

    Usage:
      analyzer = AffineAnalyzer()
      malloc_sites, memcpy_sites, final_state = analyzer.analyze(ir_lines)
      for ms in malloc_sites:
          proven, reason = final_state.can_prove_overflow(
              ms['write_size_var'], ms['alloc_size_var'])
    """

    def __init__(self):
        self._domain = AffineDomain()
        # Collected sites: {var_name: {'size_var': str, 'line': int, 'affine_state': copy}}
        self._malloc_sites: List[Dict] = []
        self._memcpy_sites: List[Dict] = []
        # Track which variables are heap pointers (from malloc result)
        self._heap_ptrs: Set[str] = set()

    def analyze(self, ir_lines: List[str]) -> Tuple[
        List[Dict], List[Dict], AffineDomain
    ]:
        """Run forward affine analysis over IR lines.

        Returns (malloc_sites, memcpy_sites, final_domain).

        Each malloc_site: {'var': str, 'size_var': str, 'line': int,
                           'affine_state': AffineDomain}
        Each memcpy_site: {'dst_var': str, 'size_var': str, 'line': int,
                           'affine_state': AffineDomain}
        """
        self._domain = AffineDomain()
        self._malloc_sites = []
        self._memcpy_sites = []
        self._heap_ptrs = set()

        for i, line in enumerate(ir_lines):
            stripped = line.strip().rstrip(';')

            # Constant assignment: var = 123
            cm = _CONST_ASSIGN_RE.match(stripped)
            if cm:
                var, val = cm.group(1), int(cm.group(2), 0)
                # Only track if this is a size-related variable (not a pointer)
                if not self._is_keyword(var) and not self._is_heap_func(val):
                    self._domain.assign_constant(var, val)
                continue

            # Alias: var = other
            am = _ALIAS_ASSIGN_RE.match(stripped)
            if am:
                lhs, rhs = am.group(1), am.group(2)
                if not self._is_keyword(lhs) and not self._is_keyword(rhs):
                    self._domain.assign_alias(lhs, rhs)
                continue

            # Add: var = other + const
            acm = _ADD_CONST_RE.match(stripped)
            if acm:
                lhs, rhs, const = acm.group(1), acm.group(2), int(acm.group(3))
                if not self._is_keyword(lhs):
                    self._domain.assign_add(lhs, rhs, const)
                continue

            # Sub: var = other - const
            scm = _SUB_CONST_RE.match(stripped)
            if scm:
                lhs, rhs, const = scm.group(1), scm.group(2), int(scm.group(3))
                if not self._is_keyword(lhs):
                    self._domain.assign_add(lhs, rhs, -const)
                continue

            # Mul: var = other * const
            mcm = _MUL_CONST_RE.match(stripped)
            if mcm:
                lhs, rhs, factor = mcm.group(1), mcm.group(2), int(mcm.group(3))
                if not self._is_keyword(lhs):
                    self._domain.assign_mul(lhs, rhs, factor)
                continue

            # Mul: var = const * other
            ccm = _CONST_MUL_RE.match(stripped)
            if ccm:
                lhs, factor, rhs = ccm.group(1), int(ccm.group(2)), ccm.group(3)
                if not self._is_keyword(lhs):
                    self._domain.assign_mul(lhs, rhs, factor)
                continue

            # Calloc: var = calloc(count, elem_size)
            # 取非数字参数作为size_var (affine分析需要符号变量)
            cm = _CALLOC_ASSIGN_RE.search(stripped)
            if cm:
                ptr_var = cm.group(1)
                arg1, arg2 = cm.group(2), cm.group(3)
                size_var = arg2 if arg1.isdigit() else (
                    arg1 if arg2.isdigit() else arg2)
                self._heap_ptrs.add(ptr_var)
                self._malloc_sites.append({
                    'var': ptr_var, 'size_var': size_var,
                    'line': i,
                    'affine_state': self._domain.copy(),
                })
                continue

            # Malloc: var = malloc(size_expr)
            mm = _MALLOC_ASSIGN_RE.search(stripped)
            if mm:
                ptr_var = mm.group(1)
                size_var = mm.group(2)
                self._heap_ptrs.add(ptr_var)
                # Record the affine state at this malloc
                self._malloc_sites.append({
                    'var': ptr_var, 'size_var': size_var,
                    'line': i,
                    'affine_state': self._domain.copy(),
                })
                continue

            # Memcpy: memcpy(dst, src, size)
            wm = _MEMCPY_ASSIGN_RE.search(stripped)
            if wm:
                dst_var = wm.group(1)
                size_var = wm.group(2)
                self._memcpy_sites.append({
                    'dst_var': dst_var, 'size_var': size_var,
                    'line': i,
                    'affine_state': self._domain.copy(),
                })
                continue

            # realloc: var = realloc(ptr, size)
            # Already handled by MALLOC_ASSIGN_RE (realloc in pattern)
            # free(var): remove from heap ptrs
            if 'free(' in stripped:
                fm = re.search(r'free\s*\(\s*(\w[\w.]*)\s*\)', stripped)
                if fm:
                    ptr = fm.group(1)
                    self._heap_ptrs.discard(ptr)

        return self._malloc_sites, self._memcpy_sites, self._domain

    def resolve_overflow_candidates(
        self,
        alloc_var: str,
        alloc_size_var: str,
        write_size_var: str,
        affine_state: Optional[AffineDomain] = None,
    ) -> Tuple[Optional[bool], str]:
        """Try to prove overflow or safety using affine relations.

        Returns (is_overflow, reason).
        is_overflow: True=overflow proven, False=safe proven, None=undecided
        """
        dom = affine_state or self._domain

        # Try to prove overflow: write_size > alloc_size
        proven, reason = dom.can_prove_overflow(
            write_size_var, alloc_size_var)
        if proven:
            return True, reason

        # Try to prove safety: write_size <= alloc_size + slack
        proven, reason = dom.can_prove_safe(
            write_size_var, alloc_size_var)
        if proven:
            return False, reason

        return None, 'affine-undecided'

    @staticmethod
    def _is_keyword(name: str) -> bool:
        return name in {'if', 'else', 'for', 'while', 'return',
                        'goto', 'break', 'continue', 'sizeof'}

    @staticmethod
    def _is_heap_func(val: int) -> bool:
        return False  # constants are never heap function results

    def get_state_at(self, line: int) -> AffineDomain:
        """Return the affine domain state at a given line."""
        return self._domain

def analyze_affine_relations(
    ir_lines: List[str],
) -> Tuple[List[Dict], List[Dict], AffineDomain]:
    """Convenience: run affine analysis on IR lines.

    Returns (malloc_sites, memcpy_sites, final_domain).
    """
    analyzer = AffineAnalyzer()
    return analyzer.analyze(ir_lines)

__all__ = ['AffineAnalyzer', 'analyze_affine_relations']
