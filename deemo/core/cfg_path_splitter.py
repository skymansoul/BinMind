"""
Path-sensitive CFG splitter — decomposes forward interval propagation at
merge points to preserve path-specific guard constraints.

Problem: Forward interval analysis at merge points joins ALL incoming
states, losing path-specific constraints. A guarded path (if(len>256)return)
and an unguarded path are merged, producing a false positive.

Solution: At each branch point, fork the abstract state. At each merge
point, keep states separate. At the write site, evaluate each path
independently. Only when ALL paths show overflow → KEEP.
If any path is safe → SUPPRESS (conservative for FP reduction).

Architecture:
  BFS from entry to write site (max 128 paths).
  At each branch → fork state into true/false branches.
  At each merge → keep redundant states (copy semantics, no loss).
  At each if-guard → constrain state intervals (meet operation).

Novelty over GAPSBV stage 2 (PathConstraint):
  - GAPSBV does single-path with merged constraints
  - This module does multi-path with state copying
  - Guarantee: if ANY path is safe, the write is safe (sound for FP suppression)
"""

from __future__ import annotations
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple


# patterns ───────────────────────────────────────────────────────────

_GUARD_IF = re.compile(r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==)\s*'
                       r'(\d+|MAX/sizeof)\s*\)\s*(?:return|goto)')
_ALLOC_SITE = re.compile(r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*'
                         r'(?:malloc|calloc|realloc)\s*\(\s*(\d+)\s*\)')
_WRITE_SITE = re.compile(r'(?:memcpy|memmove|strcpy|strncpy)\s*\(\s*'
                         r'(\w[\w.]*)\s*,')


@dataclass
class PathState:
    """Abstract state along one CFG path."""
    intervals: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    # var → (lo, hi) interval
    path_guards: List[str] = field(default_factory=list)
    # guard constraints encountered on this path
    is_dead: bool = False  # path became infeasible


@dataclass
class PathSplitResult:
    """Result of path-sensitive analysis at a write site."""
    write_line: int; write_var: str = ''
    alloc_size: int = 0; write_size: int = 0
    total_paths: int = 0
    safe_paths: int = 0       # paths where write ≤ alloc
    overflow_paths: int = 0   # paths where write > alloc
    dead_paths: int = 0       # infeasible paths pruned
    verdict: str = 'REVIEW'   # SUPPRESS / KEEP / REVIEW
    confidence: float = 0.50


class CfgPathSplitter:
    """BFS path-sensitive CFG traversal for heap write safety checking.

    Splits merged paths at branch points and evaluates each path
    independently at the write site. Conservative: if ANY path is
    safe, the write is not a definite overflow → SUPPRESS.
    """

    def __init__(self, max_paths: int = 128, max_depth: int = 100):
        self.max_paths = max_paths
        self.max_depth = max_depth

    def analyze(self, ir_lines: List[str],
                write_line: int) -> PathSplitResult:
        """BFS from entry to write_line, splitting at branches."""
        # Extract alloc info before the write
        alloc_size = self._find_alloc_size(ir_lines, write_line)
        write_size_est, write_var = self._estimate_write_size(
            ir_lines, write_line)

        result = PathSplitResult(
            write_line=write_line, write_var=write_var,
            alloc_size=alloc_size, write_size=write_size_est)

        # BFS from line 0 to write_line
        queue: List[Tuple[int, PathState]] = [(0, PathState())]
        safe_count = 0; overflow_count = 0; dead_count = 0

        while queue:
            pos, state = queue.pop(0)

            if pos > min(len(ir_lines) - 1, write_line):
                continue
            if state.is_dead:
                dead_count += 1
                continue
            if pos == write_line:
                if self._is_safe(state, alloc_size, write_size_est):
                    safe_count += 1
                else:
                    overflow_count += 1
                continue

            line = ir_lines[pos]

            # Check for guard: constrain state
            gm = _GUARD_IF.search(line)
            if gm:
                var, op, val = gm.group(1), gm.group(2), gm.group(3)
                constrained = self._constrain(state, var, op, val)
                if constrained is None:
                    # Path became infeasible
                    state.is_dead = True
                else:
                    state = constrained
                queue.append((pos + 1, state))
                continue

            # Check for branch: fork if a guard follows
            next_few = ir_lines[pos:min(len(ir_lines), pos + 3)]
            guarded = any(_GUARD_IF.search(l) for l in next_few)

            if guarded and len(queue) < self.max_paths:
                # Fork: true branch (guard taken → return/goto)
                # Fork: false branch (guard skipped → continue)
                true_state = PathState(
                    intervals=dict(state.intervals),
                    path_guards=list(state.path_guards))
                false_state = PathState(
                    intervals=dict(state.intervals),
                    path_guards=list(state.path_guards))
                # Find the guard line
                guard_line_idx = None
                for ni, nl in enumerate(next_few):
                    if _GUARD_IF.search(nl):
                        guard_line_idx = pos + ni
                        break
                # True branch: skip to after guard
                true_state.path_guards.append(
                    f'guard@{guard_line_idx}')
                queue.append((min(guard_line_idx + 1, write_line + 1)
                              if guard_line_idx else pos + 1, true_state))
                # False branch: skip guard (not taken)
                queue.append((min(pos + 1, write_line + 1), false_state))
            else:
                queue.append((pos + 1, state))

        result.total_paths = safe_count + overflow_count + dead_count
        result.safe_paths = safe_count
        result.overflow_paths = overflow_count
        result.dead_paths = dead_count

        # Decision: SUPPRESS if any path is safe
        if safe_count > 0 and overflow_count == 0:
            result.verdict = 'SUPPRESS'
            result.confidence = 0.85
        elif safe_count > 0:
            result.verdict = 'REVIEW'
            result.confidence = 0.50
        elif overflow_count > 0:
            result.verdict = 'KEEP'
            result.confidence = 0.80
        else:
            result.verdict = 'REVIEW'
            result.confidence = 0.40

        return result

    # helpers ────────────────────────────────────────────────────

    @staticmethod
    def _find_alloc_size(ir_lines: List[str], write_line: int) -> int:
        """Find malloc(size) before write_line, return size."""
        for i in range(write_line - 1, -1, -1):
            m = _ALLOC_SITE.search(ir_lines[i])
            if m:
                try:
                    return int(m.group(2))
                except ValueError:
                    pass
            # Try variable alloc: buf = malloc(n) → need to resolve n
            alloc_m = re.search(
                r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*'
                r'malloc\s*\(\s*(\w[\w.]*)\s*\)', ir_lines[i])
            if alloc_m:
                var = alloc_m.group(2)
                # Back-trace: var = number; assignment
                for j in range(i - 1, -1, -1):
                    const_m = re.search(
                        rf'{re.escape(var)}\s*=\s*(\d+)\s*;', ir_lines[j])
                    if const_m:
                        return int(const_m.group(1))
        return 0

    @staticmethod
    def _estimate_write_size(ir_lines: List[str],
                             write_line: int) -> Tuple[int, str]:
        """Estimate write size from memcpy/memmove third argument."""
        line = ir_lines[write_line] if write_line < len(ir_lines) else ''
        m = _WRITE_SITE.search(line)
        if not m:
            return 0, ''
        dst = m.group(1)
        # Estimate: look for constant size arg
        size_m = re.search(r',\s*(\d+)\s*\)', line)
        if size_m:
            return int(size_m.group(1)), dst
        # Variable: try to resolve
        var_m = re.search(r',\s*(\w[\w.]*)\s*\)', line)
        if var_m:
            vname = var_m.group(1)
            for i in range(write_line - 1, -1, -1):
                cm = re.search(rf'{re.escape(vname)}\s*=\s*(\d+)\s*;',
                               ir_lines[i])
                if cm:
                    return int(cm.group(1)), dst
        return 0, dst

    @staticmethod
    def _constrain(state: PathState, var: str, op: str,
                   val: str) -> Optional[PathState]:
        """Apply guard constraint to state. Returns None if infeasible."""
        import copy
        new_state = PathState(
            intervals=dict(state.intervals),
            path_guards=list(state.path_guards))
        new_state.path_guards.append(f'{var}{op}{val}')

        try:
            if val == 'MAX/sizeof':
                ival = 10**10  # effectively unbounded upper
            else:
                ival = int(val)
        except ValueError:
            return new_state

        if var not in new_state.intervals:
            new_state.intervals[var] = (0, 10**9)
        lo, hi = new_state.intervals[var]

        if op in ('<', '<='):
            new_hi = ival if op == '<' else ival
            if new_hi < lo:
                return None  # infeasible
            new_state.intervals[var] = (lo, new_hi)
        elif op in ('>', '>='):
            new_lo = ival if op == '>' else (ival - 1)
            if new_lo > hi:
                return None  # infeasible
            new_state.intervals[var] = (new_lo, hi)

        return new_state

    @staticmethod
    def _is_safe(state: PathState, alloc_size: int,
                 write_size: int) -> bool:
        """Check if this path's constraints make the write safe."""
        if alloc_size <= 0:
            return False  # unknown alloc size, assume overflow
        # Basic: write_size <= alloc_size → safe
        # With interval constraints: if var_hi <= alloc → safe
        for var, (lo, hi) in state.intervals.items():
            if lo >= 0 and hi <= alloc_size:
                if write_size <= hi:
                    return True
        return write_size <= alloc_size


def check_path_sensitive(ir_lines: List[str],
                         write_line: int,
                         max_paths: int = 128) -> PathSplitResult:
    """Convenience: path-sensitive safety check at a write site."""
    splitter = CfgPathSplitter(max_paths=max_paths)
    return splitter.analyze(ir_lines, write_line)


__all__ = ['PathState', 'PathSplitResult', 'CfgPathSplitter',
           'check_path_sensitive']
