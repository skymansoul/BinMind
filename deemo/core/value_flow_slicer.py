"""
Demand-driven value-flow slicer (VFS) — backward slicing from heap write sites
toward definitions, resolving write-size/offset ranges and correlating upstream
guard conditions. Complements GAPSBV forward interval propagation; handles
symbolic allocation sizes where forward intervals degrade to TOP.

Algorithm (VFS):
  Phase A — Identify write operands (dst offset / size)
  Phase B — Backward slice each operand through def-use chain (≤8 hops)
  Phase C — Correlate guard conditions (if-constraints) on the sliced path
  Phase D — Resolve concrete ranges when operands trace to constants
  Phase E — Score FP likelihood: guarded+small → high FP; unguarded+tainted → low

Ref: Sridharan et al. OOPSLA 2011 (demand-driven pts); Livshits & Lam USENIX 05
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.forward_interval_prop import Interval

# datatypes ─────────────────────────────────────────────────────────

@dataclass
class ValueSlice:
    """Value-flow slice from a write operand back to its origin."""
    var: str; definition_line: int = -1; definition_expr: str = ''
    origin_type: str = 'unknown'  # constant | user_input | derived | unknown
    interval: Interval = field(default_factory=Interval.unknown)
    resolved_const: int = -1; hops: int = 0
    guarded_by: List[str] = field(default_factory=list)

@dataclass
class GuardSite:
    """Guard (if-condition) bounding a variable."""
    line: int; var: str; op: str; bound: int
    dominates: bool = False

@dataclass
class SlicedWrite:
    """Result of slicing one heap write."""
    write_line: int = -1; dst_var: str = ''
    offset_slice: Optional[ValueSlice] = None
    size_slice: Optional[ValueSlice] = None
    guards: List[GuardSite] = field(default_factory=list)
    is_user_controlled: bool = False; fp_likelihood: float = 0.50

# patterns ──────────────────────────────────────────────────────────

_A = re.compile(r'(\w[\w.]*)\s*=\s*(.+)')   # assignment
_C = re.compile(r'^\s*(\d+|0x[0-9a-fA-F]+)\s*$')  # constant literal
_G = re.compile(r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==)\s*(\d+|0x[0-9a-fA-F]+)\s*\)')
_R = re.compile(r'(\w[\w.]*)\s*([+\-*])\s*(\d+)\s*$')  # var op const
_U = {'fgets','gets','scanf','fscanf','recv','recvfrom','read','getenv','atoi','strtol','strtoul'}
_H = {'malloc','calloc','realloc','free','memcpy','strcpy','memmove','strncpy','memset','sprintf','snprintf'}
_WRITE_FN = re.compile(r'(?:memcpy|memmove|strncpy|strcpy|sprintf)\s*\(([^)]+)\)')

# slicer ────────────────────────────────────────────────────────────

class ValueFlowSlicer:
    """Demand-driven backward slicer for heap write operands."""

    def __init__(self, max_hops: int = 8):
        self._max_hops = max_hops

    def slice_operand(self, ir: List[str], op: str, from_line: int) -> ValueSlice:
        """Slice one operand backward to constant / user_input / unknown."""
        cm = _C.match(op.strip())
        if cm:
            v = int(cm.group(1), 0)
            return ValueSlice(var=op.strip(), definition_expr=str(v),
                            origin_type='constant', interval=Interval.exact(v),
                            resolved_const=v)

        base, extra = op.strip(), 0
        am = _R.match(op.strip())
        if am:
            base, extra = am.group(1), int(am.group(3))

        vs = ValueSlice(var=base, interval=Interval.unknown())
        cur, visited = base, set()

        for _ in range(self._max_hops):
            if cur in visited:
                break
            visited.add(cur)
            dl, dr = self._find_def(ir, cur, from_line)
            if dl < 0:
                vs.origin_type = 'user_input'
                vs.definition_expr = f'{cur}:no_def'
                break
            vs.definition_line, vs.definition_expr = dl, dr
            vs.hops += 1
            vs.guarded_by.extend(self._guards_for_var(ir, cur, dl))
            rhs = dr.strip().rstrip(';')

            cm2 = _C.match(rhs)
            if cm2:
                v = int(cm2.group(1), 0) + extra
                vs.origin_type = 'constant'; vs.resolved_const = v
                vs.interval = Interval.exact(v); return vs

            fm = re.match(r'(\w+)\s*\(', rhs)
            if fm:
                if fm.group(1) in _U:
                    vs.origin_type = 'user_input'; return vs
                if fm.group(1) in _H:
                    vs.origin_type = 'derived'
                    arg_m = re.search(r'\((.*?)\)', rhs)
                    if arg_m:
                        cv = self._try_const(arg_m.group(1), ir, dl)
                        if cv >= 0:
                            vs.interval = Interval.exact(cv); vs.resolved_const = cv
                    return vs

            vm = re.match(r'^(\w[\w.]*)$', rhs)
            if vm:
                cur = vm.group(1); from_line = dl; continue

            am2 = _R.match(rhs)
            if am2:
                cur = am2.group(1)
                extra += int(am2.group(3)) * (1 if am2.group(2) == '+' else -1)
                from_line = dl; continue

            vs.origin_type = 'derived'; break
        return vs

    def slice_write(self, ir: List[str], wl: int, dst: str) -> SlicedWrite:
        """Full write slice: extract operands, find guards, score FP."""
        line = ir[wl] if wl < len(ir) else ''
        sw = SlicedWrite(write_line=wl, dst_var=dst)
        mc = _WRITE_FN.search(line)
        if mc:
            args = self._split_args(mc.group(1))
            if len(args) >= 3:
                sw.size_slice = self.slice_operand(ir, args[2].strip(), wl)
        sw.guards = self._dominating_guards(ir, wl)
        if sw.size_slice and sw.size_slice.origin_type == 'user_input':
            sw.is_user_controlled = True
        sw.fp_likelihood = self._score_fp(sw)
        return sw

    # internal helpers ───────────────────────────────────────────

    def _find_def(self, ir: List[str], var: str, before: int) -> Tuple[int, str]:
        for i in range(before - 1, max(0, before - 60), -1):
            m = _A.match(ir[i].strip())
            if m and m.group(1) == var:
                return i, m.group(2)
        return -1, ''

    def _guards_for_var(self, ir: List[str], var: str, at: int) -> List[str]:
        out = []
        for i in range(max(0, at - 10), min(len(ir), at + 10)):
            m = _G.search(ir[i])
            if m and m.group(1) == var:
                out.append(f'{m.group(2)} {m.group(3)}')
        return out

    def _dominating_guards(self, ir: List[str], wl: int) -> List[GuardSite]:
        sites = []
        for i in range(max(0, wl - 30), wl):
            m = _G.search(ir[i])
            if m:
                try:
                    sites.append(GuardSite(line=i, var=m.group(1),
                        op=m.group(2), bound=int(m.group(3), 0),
                        dominates=self._scope_has(ir, i, wl)))
                except ValueError: pass
        return sites

    @staticmethod
    def _scope_has(ir: List[str], gl: int, tl: int) -> bool:
        d, s = 0, False
        for i in range(gl, min(len(ir), tl + 1)):
            if '{' in ir[i]: d += 1; s = True
            if '}' in ir[i]:
                d -= 1
                if d <= 0 and s and i < tl: return False
        return s and d > 0

    @staticmethod
    def _split_args(s: str) -> List[str]:
        parts, d, cur = [], 0, []
        for ch in s:
            if ch == '(': d += 1; cur.append(ch)
            elif ch == ')': d -= 1; cur.append(ch)
            elif ch == ',' and d == 0: parts.append(''.join(cur)); cur = []
            else: cur.append(ch)
        if cur: parts.append(''.join(cur))
        return parts

    def _try_const(self, expr: str, ir: List[str], at: int) -> int:
        cm = _C.match(expr.strip())
        if cm: return int(cm.group(1), 0)
        vm = re.match(r'^(\w[\w.]*)$', expr.strip())
        if vm:
            _, rhs = self._find_def(ir, vm.group(1), at)
            cm2 = _C.match(rhs.strip()) if rhs else None
            if cm2: return int(cm2.group(1), 0)
        return -1

    def _score_fp(self, sw: SlicedWrite) -> float:
        s = 0.50
        dom = [g for g in sw.guards if g.dominates]
        if dom: s -= 0.25 * min(len(dom), 2)
        if sw.is_user_controlled and not sw.guards: s = 0.10
        if sw.size_slice:
            if sw.size_slice.origin_type == 'constant':
                if sw.size_slice.resolved_const <= 256: s -= 0.15
                else: s -= 0.05
            elif sw.size_slice.origin_type == 'user_input': s = 0.05
        return max(0.0, min(0.95, s))


__all__ = ['ValueSlice', 'GuardSite', 'SlicedWrite', 'ValueFlowSlicer']
