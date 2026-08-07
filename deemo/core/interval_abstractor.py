# Interval abstract interpreter: conservative [min,max] analysis for heap access
# offsets, filtering infeasible overflow paths.
#
# Abstract interpretation of store instruction offset expressions:
# Constant offset: [c, c] exact
# Register + constant: back-trace register definition -> [def_min+c, def_max+c]
# Loop variable: extract upper bound from cmp/jl -> [0, loop_bound]
# Cannot infer: [None, None] (deferred to other passes)
#
# Based on Cousot & Cousot abstract interpretation, interval domain.
# Tracks single-variable intervals only (no relational constraints). This is
# sufficient for heap overflow: we only need "could max offset exceed allocation size?"
# erence: Mine "Weakly Relational Numerical Abstract Domains"

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Interval:
    """Integer interval [low, high]; None means +/-inf."""
    low: Optional[int] = None
    high: Optional[int] = None

    def is_finite(self) -> bool:
        return self.low is not None and self.high is not None

    def max_possible(self) -> Optional[int]:
        return self.high

    def __repr__(self):
        lo = str(self.low) if self.low is not None else '-inf'
        hi = str(self.high) if self.high is not None else '+inf'
        return f'[{lo}, {hi}]'


def infer_offset_interval(
    disasm_lines: List[str],
    store_line_idx: int,
) -> Interval:
    """Infer the offset interval for a store instruction by back-tracing the
    offset calculation chain.

    Returns: Interval [min_offset, max_offset]; None means unbounded.
    """
    if store_line_idx < 0 or store_line_idx >= len(disasm_lines):
        return Interval(None, None)

    line = disasm_lines[store_line_idx].strip()
    const_off = _extract_store_constant(line)
    idx_reg = _extract_index_register(line)

    if const_off is not None and idx_reg is None:
        return Interval(const_off, const_off + 8)

    if idx_reg:
        reg_iv = _trace_register_range(disasm_lines, store_line_idx, idx_reg)
        if const_off is not None and reg_iv.is_finite():
            return Interval(reg_iv.low + const_off, reg_iv.high + const_off + 8)
        elif const_off is not None:
            return Interval(const_off, None)

    loop_bound = _extract_loop_bound(disasm_lines, store_line_idx)
    if loop_bound is not None:
        return Interval(0, loop_bound + 8)

    return Interval(None, None)


def _extract_store_constant(line: str) -> Optional[int]:
    m = re.search(r'[\[].*?[+\s]((?:0x)?[0-9a-fA-F]+)[\]\s]', line, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    m = re.search(r'\w+\[(\d+)\]', line)
    if m:
        return int(m.group(1))
    return None


def _extract_index_register(line: str) -> Optional[str]:
    m = re.search(r'\[.*?[+]\s*(\w{2,3})\s*[*\]\s]', line)
    return m.group(1) if m else None


def _trace_register_range(
    disasm_lines: List[str], from_idx: int, reg: str, max_back: int = 30
) -> Interval:
    """Back-trace the value range of a register."""
    for i in range(from_idx - 1, max(-1, from_idx - max_back), -1):
        line = disasm_lines[i].strip().lower()
        if not line or line.startswith(';'):
            continue
        if 'xor' in line and reg in line:
            return Interval(0, 0)
        if 'mov' in line and reg in line.split(',')[0]:
            imm = _extract_imm(line)
            if imm is not None:
                return Interval(imm, imm)
        if 'cmp' in line and reg in line:
            imm = _extract_imm(line)
            if imm is not None:
                return Interval(0, imm)
    return Interval(None, None)


def _extract_loop_bound(disasm_lines: List[str], around_idx: int) -> Optional[int]:
    for i in range(max(0, around_idx - 20), min(len(disasm_lines), around_idx + 5)):
        line = disasm_lines[i].strip().lower()
        m = re.search(r'cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)', line)
        if m:
            try:
                bound = int(m.group(1), 0)
                for j in range(i + 1, min(len(disasm_lines), i + 5)):
                    if any(kw in disasm_lines[j].lower() for kw in ('jl', 'jle', 'jb', 'jbe')):
                        if 0 < bound < 100000:
                            return bound
            except ValueError:
                pass
    return None


def _extract_imm(line_lower: str) -> Optional[int]:
    m = re.search(r'(0x[0-9a-fA-F]+|\d+)\s*(?:$|[,\s\]])', line_lower)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    return None


__all__ = ["Interval", "infer_offset_interval"]
# Does NOT solve SMT - interval arithmetic only, trading precision for speed.
import re
from typing import Dict, Tuple

Interval = Tuple[float, float]

class IntervalAbstractor:
    def __init__(self):
        self._vars: Dict[str, Interval] = {}
    def set_var(self, name: str, low: float, high: float) -> None:
        self._vars[name] = (low, high)
    def set_from_comparison(self, var: str, op: str, val: float) -> bool:
        cur = self._vars.get(var, (float('-inf'), float('inf')))
        if op in ('>', '>='):
            nl = val if op == '>' else val
            ni = (max(cur[0], nl), cur[1])
        elif op in ('<', '<='):
            nh = val if op == '<' else val
            ni = (cur[0], min(cur[1], nh))
        elif op == '==':
            ni = (max(cur[0], val), min(cur[1], val))
        else:
            return True
        if ni[0] > ni[1]:
            return False
        self._vars[var] = ni
        return True
    def is_feasible(self, cond: str) -> bool:
        m = re.match(r'(\w+)\s*(>=?|<=?|==|!=)\s*(-?\d+(?:\.\d+)?)', cond.strip())
        if not m: return True
        try:
            return self.set_from_comparison(m.group(1), m.group(2), float(m.group(3)))
        except ValueError:
            return True
    def get_interval(self, name: str) -> Interval:
        return self._vars.get(name, (float('-inf'), float('inf')))

__all__ = ['IntervalAbstractor']
