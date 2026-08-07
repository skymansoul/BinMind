"""
Guard condition correlator — matches upstream if-guards to downstream heap writes
for false positive suppression.

Rationale:
  Many FP cases follow the pattern:
    if (len > bufsize) return;
    memcpy(buf, src, len);   // safe: len <= bufsize on this path

  Existing GAPSBV pipeline collects path constraints but merges them at join
  points, losing the guard-to-write correlation. This module performs a
  structure-aware scope analysis: for each heap write, it identifies which
  guards dominate the write and what range they constrain the write operands to.

Algorithm (Guard Correlation):
  1. Scan IR for guard sites: if (var <op> const) / if (var <op> var2)
  2. For each guard, compute the constrained interval of the guarded variable
  3. For each heap write, check if its size/offset variable is dominated by
     any guard — if so, the write is constrained and likely safe
  4. Compute a guard strength score: strong (size < 256) → likely FP,
     weak (size > 4096) → still suspicious

Novelty over path_constraint_collector.py:
  - Scope-aware: only applies guards that textually dominate the write
  - Variable correlation: matches guard variable with write-size variable
  - Strength scoring: distinguishes weak vs strong guards for FP assessment

  - Ball & Rajamani, "The SLAM Project" — predicate abstraction
    for boolean program verification
  - Gulwani et al., "Join Algorithms for the Theory of Uninterpreted Functions"

"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.forward_interval_prop import Interval

@dataclass
class CorrelatedGuard:
    """A guard that has been correlated with a heap write."""
    guard_line: int; write_line: int
    guard_var: str; write_var: str     # may differ if alias
    op: str; bound_value: int
    constrains_size: bool              # guard limits write SIZE (not just alloc)
    scope_match: bool                  # guard scope contains write
    strength: float                    # 0-1, how strongly this suggests FP filtering
    detail: str = ''

@dataclass
class GuardCorrelationResult:
    """Result of correlating guards with one heap write candidate."""
    write_line: int; dst_var: str
    alloc_size: int; write_size_range: Tuple[int, int]
    guards: List[CorrelatedGuard] = field(default_factory=list)
    dominant_guard: Optional[CorrelatedGuard] = None
    safe_confidence: float = 0.0       # 0→likely overflow, 1→likely safe (FP)

# patterns ──────────────────────────────────────────────────────────

_GUARD_IF = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+|0x[0-9a-fA-F]+|\w[\w.]*)\s*\)')

_GUARD_CMP = re.compile(
    r'(?:cmp|if)\s+(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+)')

_ASSIGN = re.compile(r'(\w[\w.]*)\s*=\s*(.+)')

# 堆写入模式
_WRITE_PAT = re.compile(
    r'(memcpy|memmove|strncpy|strcpy|sprintf)\s*\(\s*'
    r'(\w[\w.]*)\s*(?:[+]\s*(\d+|\w[\w.]*))?\s*,\s*[^,]*,\s*([^)]+)\s*\)')

# 变量别名: ptr = buf; q = p; 等
_ALIAS_PAT = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;?')

# engine ────────────────────────────────────────────────────────────

class GuardCorrelator:
    """Match upstream guards to heap writes for FP filtering."""

    def __init__(self, max_lookback: int = 50):
        self._lookback = max_lookback

    def extract_guards(self, ir_lines: List[str]) -> List[CorrelatedGuard]:
        """Phase 1: extract all guard sites from IR."""
        raw: List[Tuple[int, str, str, int]] = []
        for i, line in enumerate(ir_lines):
            m = _GUARD_IF.search(line)
            if m:
                try:
                    bound = int(m.group(3), 0)
                    raw.append((i, m.group(1), m.group(2), bound))
                except ValueError:
                    pass  # symbolic bound — skip for now
        return []  # populated during correlate()

    def correlate(
        self, ir_lines: List[str], write_line: int,
        size_var: str, alloc_var: str, alloc_size: int,
    ) -> GuardCorrelationResult:
        """Phase 2-3: correlate guards with a specific heap write.

        Returns a result with all correlated guards and safe_confidence.
        """
        wr_size_lo, wr_size_hi = 0, 2**30
        # Try to parse write size from the line
        line = ir_lines[write_line] if write_line < len(ir_lines) else ''
        wm = _WRITE_PAT.search(line)
        if wm:
            size_expr = wm.group(4).strip()
            try:
                wr_size_lo = wr_size_hi = int(size_expr, 0)
            except ValueError:
                pass

        result = GuardCorrelationResult(
            write_line=write_line, dst_var=alloc_var,
            alloc_size=alloc_size, write_size_range=(wr_size_lo, wr_size_hi))

        # Build alias map: var → canonical name
        aliases = self._build_alias_map(ir_lines, write_line)

        # Resolve size_var to canonical
        canon_size = aliases.get(size_var, size_var)
        canon_alloc = aliases.get(alloc_var, alloc_var)

        # Scan for guards
        for i in range(max(0, write_line - self._lookback), write_line):
            m = _GUARD_IF.search(ir_lines[i])
            if not m:
                continue
            try:
                bound = int(m.group(3), 0)
            except ValueError:
                continue

            gvar = m.group(1); gop = m.group(2)
            canon_gvar = aliases.get(gvar, gvar)

            # Check if guard constrains the size variable or alloc variable
            constrains_size = (canon_gvar == canon_size)
            constrains_alloc = (canon_gvar == canon_alloc)
            if not constrains_size and not constrains_alloc:
                continue

            # Check scope dominance
            scope_ok = self._scope_contains(ir_lines, i, write_line)

            # Strength scoring
            strength = self._guard_strength(gop, bound, alloc_size)

            cg = CorrelatedGuard(
                guard_line=i, write_line=write_line,
                guard_var=gvar, write_var=size_var,
                op=gop, bound_value=bound,
                constrains_size=constrains_size,
                scope_match=scope_ok,
                strength=strength,
                detail=f'if({gvar}{gop}{bound}) → write at L{write_line}'
            )
            result.guards.append(cg)

            # Track strongest guard
            if scope_ok and (result.dominant_guard is None
                             or strength > result.dominant_guard.strength):
                result.dominant_guard = cg

        # Compute safe confidence
        result.safe_confidence = self._compute_safety(result, alloc_size)
        return result

    def _build_alias_map(self, ir: List[str], before: int) -> Dict[str, str]:
        """Build var→canonical alias map from assignments within window."""
        aliases: Dict[str, str] = {}
        for i in range(max(0, before - 30), before):
            m = _ALIAS_PAT.match(ir[i].strip())
            if m:
                lhs, rhs = m.group(1), m.group(2)
                # Follow existing aliases
                canon = aliases.get(rhs, rhs)
                aliases[lhs] = canon
        # Transitive closure (single pass)
        for var in list(aliases.keys()):
            chain = aliases[var]
            while chain in aliases and aliases[chain] != chain:
                chain = aliases[chain]
            aliases[var] = chain
        return aliases

    @staticmethod
    def _scope_contains(ir: List[str], guard: int, target: int) -> bool:
        """Check if the guard's scope contains target line.
        Handles: braced blocks, single-line ifs, and early-return patterns."""
        if target <= guard:
            return False
        gline = ir[guard].strip()
        # Single-line if without braces: if (cond) stmt;
        if not gline.endswith('{') and '{' not in ir[guard + 1] if guard + 1 < len(ir) else True:
            # Check if the next line is a return/goto/exit — then fall-through continues
            if guard + 1 < len(ir):
                nxt = ir[guard + 1].strip()
                if re.match(r'^(?:return|goto|exit|break|continue)\b', nxt):
                    # Early-return: fall-through path inherits NEGATED guard
                    return target > guard + 1
                else:
                    # Single-line if without early return: only next line dominated
                    return target == guard + 1
            return False
        # Braced scope
        d, s = 0, False
        for i in range(guard, min(len(ir), target + 1)):
            if '{' in ir[i]: d += 1; s = True
            if '}' in ir[i]:
                d -= 1
                if d <= 0 and s and i < target:
                    return False
        return s and d > 0

    @staticmethod
    def _guard_strength(op: str, bound: int, alloc: int) -> float:
        """Score guard strength for FP filtering: 0=weak, 1=strong."""
        # Alloc未知时, 用guard bound做保守估计: 合理上限(~4096)视为有效约束
        effective_alloc = alloc if alloc > 0 else bound if bound <= 4096 else 4096
        if op in ('<', '<='):
            if bound <= effective_alloc:
                return 0.85
            elif bound <= effective_alloc * 2:
                return 0.40
            else:
                return 0.10
        elif op in ('>', '>='):
            # 早退模式: if(var > X) return → 走到底的路径上 var <= X
            if bound <= effective_alloc:
                return 0.80
            elif bound <= effective_alloc * 2:
                return 0.35
            return 0.05
        elif op == '==':
            if bound <= effective_alloc:
                return 0.70
            return 0.20
        return 0.30

    def _compute_safety(
        self, result: GuardCorrelationResult, alloc_size: int,
    ) -> float:
        """Compute overall safe_confidence from correlated guards."""
        if not result.guards:
            return 0.0

        # Dominant guard with scope match → highest weight
        if result.dominant_guard and result.dominant_guard.scope_match:
            base = result.dominant_guard.strength
        else:
            # No guard dominates this write → apply scope penalty (0.45x)
            # Prevents over-suppression in multi-path code where a guard
            # on one branch shouldn't suppress writes on other branches.
            raw = max((g.strength for g in result.guards), default=0.0)
            base = raw * 0.45

        # Boost if multiple independent guards
        scope_guards = [g for g in result.guards if g.scope_match]
        if len(scope_guards) >= 2:
            base = min(0.95, base + 0.10)

        # Size-constraining guard is stronger than alloc-constraining
        if result.dominant_guard and result.dominant_guard.constrains_size:
            base = min(0.95, base + 0.05)

        return base

def correlate_write(
    ir_lines: List[str], write_line: int,
    size_var: str = 'len', alloc_var: str = 'buf', alloc_size: int = 0,
) -> GuardCorrelationResult:
    """Convenience: correlate guards for one heap write."""
    gc = GuardCorrelator()
    return gc.correlate(ir_lines, write_line, size_var, alloc_var, alloc_size)

__all__ = ['CorrelatedGuard', 'GuardCorrelationResult',
           'GuardCorrelator', 'correlate_write']
