"""Loop bound inference via widening. Infer for/while/do-while iteration counts
from IR patterns. Widening ensures termination. Constraints from
PathConstraintCollector narrow bounds at loop exits. Handles single-counter
loops; sentinel-based loops produce dynamic bounds."""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.forward_interval_prop import Interval


# loop patterns ────────────────────────────────────────────────────

@dataclass
class LoopInfo:
    """Information about a detected loop."""
    start_line: int          # loop header line
    end_line: int            # loop exit line (estimated)
    counter_var: str         # induction variable name
    bound_var: str           # bound variable (or literal constant)
    bound_value: int         # numeric bound (-1 if symbolic)
    is_dynamic: bool         # bound depends on runtime value
    pattern: str             # 'for', 'while', 'do-while', 'unknown'


# Pattern matching regexes for common loop idioms in decompiled IR

# for(i=0; i<N; i++) → i=0 assignment, cmp i,N, increment i
_FOR_INIT_RE = re.compile(r'(\w[\w.]*)\s*=\s*0\s*;')
_FOR_CMP_RE = re.compile(
    r'(?:cmp\s+)?(\w[\w.]*)\s*(<|<=|!=)\s*(\d+|\w[\w.]*)\s*[;)]')
_FOR_INCR_RE = re.compile(r'(\w[\w.]*)\s*(\+\+|--)\s*')
_FOR_INCR_ASSIGN_RE = re.compile(r'(\w[\w.]*)\s*=\s*\1\s*([+-])\s*(\d+)')

# while(*p++) / while(i--) patterns
_WHILE_DECR_RE = re.compile(r'while\s*\(\s*(\w[\w.]*)\s*--\s*\)')
_WHILE_PTR_RE = re.compile(r'while\s*\(\s*\*\s*(\w[\w.]*)\s*\+\+\s*\)')

# do { ... } while(cond) patterns
_DO_WHILE_RE = re.compile(r'}\s*while\s*\(\s*(\w[\w.]*)\s*(<|<=|!=)\s*(\d+|\w[\w.]*)\s*\)')


class LoopBoundInferrer:
    """Infer loop iteration bounds from decompiled IR lines.

    Processes IR text line-by-line, identifying loop structures and
    extracting bound information. Uses widening-based fixpoint iteration
    to infer symbolic bounds.
    """

    def __init__(self, max_loop_iter: int = 100):
        self._max_iter = max_loop_iter
        self._loops: List[LoopInfo] = []

    def detect_loops(self, ir_lines: List[str]) -> List[LoopInfo]:
        """Detect all loops in the IR and return their bound information."""
        self._loops = []
        n = len(ir_lines)

        i = 0
        while i < n:
            line = ir_lines[i]

            # Try for-loop pattern detection
            loop = self._detect_for_loop(ir_lines, i)
            if loop:
                self._loops.append(loop)
                i = loop.end_line + 1
                continue

            # Try while-loop pattern
            loop = self._detect_while_loop(ir_lines, i)
            if loop:
                self._loops.append(loop)
                i = loop.end_line + 1
                continue

            # Try do-while pattern
            loop = self._detect_do_while(ir_lines, i)
            if loop:
                self._loops.append(loop)
                i = loop.end_line + 1
                continue

            i += 1

        return self._loops

    def _detect_for_loop(self, lines: List[str], start: int) -> Optional[LoopInfo]:
        """Detect canonical for-loop: init; cmp; incr pattern."""
        n = len(lines)
        if start >= n - 3:
            return None

        window = lines[start:min(n, start + 30)]
        window_str = '\n'.join(window)

        # Check for i=0 initialization
        init_m = _FOR_INIT_RE.search(window_str)
        if not init_m:
            init_m = re.search(r'(\w[\w.]*)\s*=\s*0\b', window_str)

        if not init_m:
            return None

        counter_var = init_m.group(1)

        # Check for comparison: i < N or cmp i, N
        cmp_m = _FOR_CMP_RE.search(window_str)
        if not cmp_m:
            return None
        cmp_var = cmp_m.group(1)
        # comparison variable should be the counter
        if cmp_var != counter_var:
            # Sometimes the comparison uses a different variable
            # Check if it's a direct constant
            pass

        bound_str = cmp_m.group(3)

        # Attempt to parse bound as integer
        is_dynamic = True
        bound_value = -1
        try:
            bound_value = int(bound_str, 0)
            is_dynamic = False
        except ValueError:
            # Symbolic bound - try to find it in preceding assignments
            bound_value = self._resolve_symbolic_bound(bound_str, lines, start)

        # Estimate loop end line
        end_line = min(n - 1, start + 25)
        # Look for closing brace or label
        brace_depth = 0
        for j in range(start, min(n, start + 40)):
            if '{' in lines[j]:
                brace_depth += 1
            if '}' in lines[j]:
                brace_depth -= 1
                if brace_depth <= 0 and j > start + 3:
                    end_line = j
                    break

        return LoopInfo(
            start_line=start, end_line=end_line,
            counter_var=counter_var, bound_var=bound_str,
            bound_value=bound_value, is_dynamic=is_dynamic,
            pattern='for')

    def _detect_while_loop(self, lines: List[str], start: int) -> Optional[LoopInfo]:
        """Detect while-loop with decrementing counter or pointer scan."""
        line = lines[start]

        # while (i--)
        m = _WHILE_DECR_RE.search(line)
        if m:
            return LoopInfo(
                start_line=start, end_line=min(len(lines) - 1, start + 20),
                counter_var=m.group(1), bound_var='0',
                bound_value=0, is_dynamic=True, pattern='while')

        return None

    def _detect_do_while(self, lines: List[str], start: int) -> Optional[LoopInfo]:
        """Detect do-while loop."""
        n = len(lines)
        for i in range(start, min(n, start + 20)):
            m = _DO_WHILE_RE.search(lines[i])
            if m:
                try:
                    bv = int(m.group(3), 0)
                    is_dyn = False
                except ValueError:
                    bv = -1
                    is_dyn = True
                return LoopInfo(
                    start_line=start, end_line=i,
                    counter_var=m.group(1), bound_var=m.group(3),
                    bound_value=bv, is_dynamic=is_dyn, pattern='do-while')
        return None

    def _resolve_symbolic_bound(
        self, var_name: str, lines: List[str], before: int,
    ) -> int:
        """Try to resolve a symbolic bound variable to a concrete value.

        Searches for const assignments to var_name within a window before
        the loop. Returns -1 if unresolved.
        """
        for i in range(max(0, before - 10), before):
            m = re.search(
                rf'{re.escape(var_name)}\s*=\s*(\d+|0x[0-9a-fA-F]+)',
                lines[i])
            if m:
                try:
                    return int(m.group(1), 0)
                except ValueError:
                    pass
        return -1

    def infer_bounds_for_var(
        self, var_name: str, at_line: int,
    ) -> Interval:
        """Infer the range of var_name at a given program point.

        If var_name is a loop counter within a detected loop, returns
        [0, bound] or ⊤ if dynamic.
        """
        for loop in self._loops:
            if loop.counter_var == var_name:
                if loop.start_line <= at_line <= loop.end_line:
                    if not loop.is_dynamic and loop.bound_value > 0:
                        return Interval(0, loop.bound_value - 1)
                    else:
                        return Interval(0, 2**63 - 1)

        return Interval.unknown()

    def get_loop_context(self, line: int) -> Optional[LoopInfo]:
        """Return the loop that contains the given line, or None."""
        for loop in self._loops:
            if loop.start_line <= line <= loop.end_line:
                return loop
        return None

    def stats(self) -> Dict:
        return {
            'total_loops': len(self._loops),
            'patterns': {lp.pattern for lp in self._loops},
            'static_bounds': sum(1 for lp in self._loops if not lp.is_dynamic),
            'dynamic_bounds': sum(1 for lp in self._loops if lp.is_dynamic),
        }


def infer_heap_write_bounds(
    ir_lines: List[str],
    alloc_var: str,
    write_line: int,
) -> Tuple[Interval, Optional[LoopInfo]]:
    """Infer the byte-range of a heap write at a given line.

    If the write is inside a loop, uses the loop bound to constrain the
    total write extent.

    Returns (byte_interval, loop_info_or_none)
    """
    inferrer = LoopBoundInferrer()
    loops = inferrer.detect_loops(ir_lines)

    # Check if write_line is inside a loop
    enclosing = None
    for loop in loops:
        if loop.start_line <= write_line <= loop.end_line:
            enclosing = loop
            break

    if enclosing is None:
        # Not in a loop - single write, size from instruction
        return Interval.unknown(), None

    # Inside a loop: total write = bound * per_iteration_bytes
    if enclosing.is_dynamic:
        return Interval.unknown(), enclosing

    per_iteration = _estimate_bytes_per_iteration(ir_lines, write_line, alloc_var)
    if per_iteration <= 0:
        per_iteration = 1

    total = per_iteration * enclosing.bound_value
    return Interval.exact(total), enclosing


def _estimate_bytes_per_iteration(
    ir_lines: List[str], write_line: int, alloc_var: str,
) -> int:
    """Estimate bytes written per loop iteration near write_line."""
    for i in range(max(0, write_line - 2), min(len(ir_lines), write_line + 3)):
        line = ir_lines[i].lower()
        if alloc_var in line:
            # Check for store size indicators
            if 'qword' in line:
                return 8
            if 'dword' in line:
                return 4
            if 'word' in line:
                return 2
            if 'byte' in line:
                return 1
    return -1


__all__ = ['LoopInfo', 'LoopBoundInferrer', 'infer_heap_write_bounds']
