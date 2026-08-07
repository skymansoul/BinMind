"""
Alias-aware pointer analysis for heap access disambiguation.

Rationale:
  A major FP source in heap overflow detection is pointer aliasing:
    buf = malloc(64);
    ptr = buf + 40;    // ptr aliases buf+40
    memcpy(ptr, src, 32);  // writes at buf+40..buf+72, overflow by 8

  Without alias analysis, the memcpy target 'ptr' is not linked to 'buf',
  and the overflow is missed (false negative). With alias analysis:
    - ptr → {buf + 40}
    - effective write range: [40, 72)
    - allocation: 64 bytes
    - verdict: overflow by 8

  This module implements a lightweight Andersen-style inclusion-based pointer
  analysis restricted to the heap domain. It tracks pointer assignments and
  arithmetic, computing a points-to set for each pointer variable.

Design decisions:
  - Field-insensitive: aggregates don't distinguish struct fields
  - Flow-insensitive: assignment order doesn't affect points-to sets
  - Intra-procedural: callee effects summarized as 'may-alias everything'
  - Restricted to heap pointers: stack/global pointers treated as ⊤

  This is much lighter than full Andersen analysis (O(N³)) and targets
  specifically the heap overflow disambiguation problem.

  - Andersen, L.O., "Program Analysis and Specialization for the C
    Programming Language"
  - Hardekopf & Lin, "The Ant and the Grasshopper" —
    fast inclusion-based pointer analysis
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# points-to data structures ────────────────────────────────────────

@dataclass
class HeapObject:
    """An abstract heap object — created at one allocation site."""
    obj_id: int
    alloc_site_line: int
    alloc_func: str        # malloc / calloc / realloc
    base_name: str         # variable name receiving the pointer

@dataclass
class PointsToSet:
    """Points-to set for a pointer variable: base object + integer offset interval."""
    base: str              # base variable name (or '' for ⊤)
    offset_min: int        # lower bound of offset from base
    offset_max: int        # upper bound of offset from base

    @staticmethod
    def unknown() -> "PointsToSet":
        return PointsToSet(base='', offset_min=0, offset_max=2**63 - 1)

    @staticmethod
    def exact(base: str, offset: int = 0) -> "PointsToSet":
        return PointsToSet(base=base, offset_min=offset, offset_max=offset)

    @property
    def is_unknown(self) -> bool:
        return self.base == ''

    def offset_by(self, delta: int) -> "PointsToSet":
        if self.is_unknown:
            return self
        return PointsToSet(
            base=self.base,
            offset_min=self.offset_min + delta,
            offset_max=self.offset_max + delta)

    def may_same_base(self, other: "PointsToSet") -> bool:
        return (not self.is_unknown and not other.is_unknown
                and self.base == other.base)

    def effective_write_range(self, write_size: int) -> Tuple[int, int]:
        """Return [start_byte, end_byte) of a write through this pointer."""
        if self.is_unknown:
            return (0, 2**63 - 1)
        return (self.offset_min, self.offset_max + write_size)

    def __repr__(self) -> str:
        if self.is_unknown:
            return "⊤"
        off = (f"+{self.offset_min}" if self.offset_min == self.offset_max
               else f"+[{self.offset_min},{self.offset_max}]")
        return f"{self.base}{off}"

# pattern matching macros ──────────────────────────────────────────

# var = malloc(N)  →  HeapObject
_PTR_ALLOC_RE = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(')

# var = base + offset  →  pointer arithmetic
_PTR_ADD_RE = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*\+\s*(\d+)')

# var = &base[offset]  →  array element address
_PTR_IDX_RE = re.compile(r'(\w[\w.]*)\s*=\s*&(\w[\w.]*)\[(\d+)\]')

# var = base  →  simple pointer copy
_PTR_COPY_RE = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*$')

# Store to pointer: *var = val / var[idx] = val
_PTR_STORE_RE = re.compile(
    r'(?:memcpy|strcpy|strncpy|__memcpy_chk)\s*\(\s*(\w[\w.]*)\s*,'
    r'|(\w[\w.]*)\[(\d+)\]\s*=')

@dataclass
class AliasResult:
    """Result of alias analysis for one pointer variable."""
    var_name: str
    points_to: PointsToSet
    definition_line: int
    is_heap_derived: bool   # ultimately derived from malloc/calloc/realloc

class HeapAliasAnalyzer:
    """Lightweight intra-procedural heap pointer alias analysis."""

    def __init__(self):
        self._heap_objects: Dict[str, HeapObject] = {}
        self._points_to: Dict[str, PointsToSet] = {}
        self._obj_counter: int = 0

    def analyze(self, ir_lines: List[str]) -> Dict[str, PointsToSet]:
        """Single-pass analysis: extract heap objects and track pointer flow.

        Returns {var_name → PointsToSet} for all tracked heap-derived pointers.
        """
        self._heap_objects = {}
        self._points_to = {}
        self._obj_counter = 0

        for i, line in enumerate(ir_lines):
            stripped = line.strip()

            # Allocation: ptr = malloc(N)
            m = _PTR_ALLOC_RE.search(stripped)
            if m:
                ptr_var = m.group(1)
                alloc_func = m.group(2)
                self._obj_counter += 1
                obj = HeapObject(
                    obj_id=self._obj_counter,
                    alloc_site_line=i,
                    alloc_func=alloc_func,
                    base_name=ptr_var,
                )
                self._heap_objects[ptr_var] = obj
                self._points_to[ptr_var] = PointsToSet.exact(ptr_var, 0)
                continue

            # Pointer arithmetic: dst = base + offset
            m = _PTR_ADD_RE.search(stripped)
            if m:
                dst = m.group(1)
                base = m.group(2)
                delta = int(m.group(3))
                if base in self._points_to:
                    pt = self._points_to[base]
                    self._points_to[dst] = pt.offset_by(delta)
                continue

            # Array indexing: dst = &base[idx]
            m = _PTR_IDX_RE.search(stripped)
            if m:
                dst = m.group(1)
                base = m.group(2)
                idx = int(m.group(3))
                if base in self._points_to:
                    pt = self._points_to[base]
                    # Conservative: idx is a constant offset in this line
                    self._points_to[dst] = pt.offset_by(idx)
                continue

            # Pointer copy: dst = base
            m = _PTR_COPY_RE.match(stripped)
            if m:
                dst = m.group(1)
                base = m.group(2)
                if base in self._points_to and base != dst:
                    self._points_to[dst] = self._points_to[base]
                continue

        return self._points_to

    def resolve(self, var_name: str) -> PointsToSet:
        """Resolve a variable to its points-to set."""
        return self._points_to.get(var_name, PointsToSet.unknown())

    def get_aliases(self, var_name: str) -> List[str]:
        """Find all variables that may alias var_name."""
        target = self.resolve(var_name)
        if target.is_unknown:
            return []

        aliases = []
        for v, pt in self._points_to.items():
            if v != var_name and pt.base == target.base:
                aliases.append(v)
        return aliases

    def compute_write_range(
        self, var_name: str, write_size: int,
    ) -> Tuple[int, int]:
        """Compute the byte range [start, end) of a write through var_name."""
        pt = self.resolve(var_name)
        return pt.effective_write_range(write_size)

    def stats(self) -> Dict:
        return {
            'heap_objects': len(self._heap_objects),
            'tracked_pointers': len(self._points_to),
            'obj_counter': self._obj_counter,
        }

def analyze_heap_aliases(
    ir_lines: List[str],
) -> Tuple[Dict[str, PointsToSet], Dict[int, HeapObject]]:
    """Convenience: full alias analysis on IR lines.

    Returns (points_to_map, heap_objects_by_line)
    """
    analyzer = HeapAliasAnalyzer()
    pt_map = analyzer.analyze(ir_lines)
    obj_map = {obj.alloc_site_line: obj
               for obj in analyzer._heap_objects.values()}
    return pt_map, obj_map

__all__ = ['HeapObject', 'PointsToSet', 'AliasResult',
           'HeapAliasAnalyzer', 'analyze_heap_aliases']
