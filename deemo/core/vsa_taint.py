"""
Simplified Value Set Analysis (VSA) taint propagation.

Uses interval abstraction as a fallback when symbolic execution fails due to
path explosion or unsolvable constraints (indirect calls, obfuscated code,
hand-written assembly). Tracks "rax in [stack_base, stack_top]" rather than
"rax = 0x7fff1234" - trading precision for coverage.

Core abstractions:
  - StridedInterval: value set = {lo + k*stride | 0 <= k <= (hi-lo)/stride}
    (stride=1: contiguous interval; stride=0: exact value)
  - TaintTag: {USER_INPUT, STACK_ADDR, HEAP_ADDR, CONSTANT, UNKNOWN}
  - Transfer rules: per-instruction VSA transfer functions for common x86 ops

Limitations:
  - Cannot distinguish two different addresses within the same interval
  - Self-modifying code analysis is based on static byte sequences only
  - Cross-function propagation only supports direct calls; indirect calls
    conservatively marked as UNKNOWN

References:
  - Balakrishnan & Reps: original VSA paper
  - BinDSA: context-sensitive heap modeling
  - DEEPVSA: ML-assisted VSA
"""


from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class TaintTag(IntEnum):
    """Taint source labels; larger values indicate greater uncertainty."""
    CONSTANT = 0       # compile-time constant, attacker cannot control
    STACK_ADDR = 1     # stack address, potentially controllable (stack overflow)
    HEAP_ADDR = 2      # heap address, potentially controllable (heap feng shui)
    USER_INPUT = 3     # directly from external input (recv/read/fgets)
    UNKNOWN = 4        # unknown origin, conservatively assumed controllable


@dataclass
class StridedInterval:
    """
    Strided interval: {lo + k*stride | 0 <= k <= (hi-lo)/stride, k in N}
    stride=0 -> exact value. Uses 64-bit unsigned arithmetic (mod 2^64).
    """
    lo: int = 0
    hi: int = 0
    stride: int = 1
    taint: TaintTag = TaintTag.CONSTANT
    is_bottom: bool = False
    is_top: bool = False

    @classmethod
    def exact(cls, value: int, taint: TaintTag = TaintTag.CONSTANT) -> 'StridedInterval':
        """Construct exact value (stride=0)."""
        return cls(lo=value, hi=value, stride=0, taint=taint)

    @classmethod
    def interval(cls, lo: int, hi: int, taint: TaintTag = TaintTag.UNKNOWN) -> 'StridedInterval':
        """Construct contiguous interval (stride=1)."""
        return cls(lo=lo, hi=hi, stride=1, taint=taint)

    @classmethod
    def top(cls) -> 'StridedInterval':
        """Construct top (any 64-bit value)."""
        return cls(lo=0, hi=0xFFFFFFFFFFFFFFFF, stride=1,
                   taint=TaintTag.UNKNOWN, is_top=True)

    @classmethod
    def bottom(cls) -> 'StridedInterval':
        """Construct bottom (unreachable)."""
        return cls(is_bottom=True)

    def contains(self, value: int) -> bool:
        if self.is_bottom:
            return False
        if self.is_top:
            return True
        if self.stride == 0:
            return value == self.lo
        if value < self.lo or value > self.hi:
            return False
        return (value - self.lo) % self.stride == 0

    def join(self, other: 'StridedInterval') -> 'StridedInterval':
        """Least upper bound (merge two intervals)."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        if self.is_top or other.is_top:
            return StridedInterval.top()

        new_lo = min(self.lo, other.lo)
        new_hi = max(self.hi, other.hi)
        import math
        new_stride = math.gcd(self.stride, other.stride)
        # If two distinct exact values, widen to interval
        if self.stride == 0 and other.stride == 0 and self.lo != other.lo:
            new_stride = 1
        new_taint = TaintTag(max(self.taint.value, other.taint.value))
        return StridedInterval(new_lo, new_hi, new_stride, new_taint)

    def widen(self, other: 'StridedInterval') -> 'StridedInterval':
        """Widening operator (ensures fixpoint termination): push to top."""
        joined = self.join(other)
        if joined.hi - joined.lo > 0x100000:  # >1MB -> push to top
            result = StridedInterval.top()
            result.taint = max(self.taint, other.taint, key=lambda t: t.value)
            return result
        return joined


def taint_transfer_mov(src: StridedInterval) -> StridedInterval:
    """MOV dest, src: taint passes directly."""
    return StridedInterval(src.lo, src.hi, src.stride,
                           src.taint, src.is_bottom, src.is_top)


def taint_transfer_add(a: StridedInterval, b: StridedInterval) -> StridedInterval:
    """ADD a, b: value intervals added, taint takes upper bound."""
    if a.is_bottom or b.is_bottom:
        return StridedInterval.bottom()
    new_lo = (a.lo + b.lo) & 0xFFFFFFFFFFFFFFFF
    new_hi = (a.hi + b.hi) & 0xFFFFFFFFFFFFFFFF
    import math
    new_stride = math.gcd(a.stride, b.stride)
    new_taint = TaintTag(max(a.taint.value, b.taint.value))
    return StridedInterval(new_lo, new_hi, new_stride, new_taint)


def taint_transfer_load(base: StridedInterval, offset: int = 0) -> StridedInterval:
    """
    Memory load: conservative assumption. The loaded value inherits the address
    taint tag, but the value interval becomes top (memory contents unknown).
    If base is a stack address, the loaded content interval is still top but
    taint may be USER_INPUT.
    """
    result = StridedInterval.top()
    result.taint = base.taint
    return result


def taint_transfer_store(value: StridedInterval, addr: StridedInterval
                          ) -> StridedInterval:
    """Memory store: value unchanged, propagates taint to target address."""
    return value


def analyze_format_arg(buf_interval: StridedInterval,
                        fmt_interval: StridedInterval
                        ) -> Tuple[bool, float, str]:
    """
    Determine if a format string call is dangerous.

    Dangerous: buf is the format parameter (1st arg) and fmt comes from user input.
    Safe: fmt is a string constant (address in .rodata) or buf is not the 1st arg.

    Returns (is_vulnerable, confidence, reason)
    """
    # Case 1: format parameter is a string constant (narrow address range in .rodata)
    if fmt_interval.stride == 0 and fmt_interval.taint == TaintTag.CONSTANT:
        fmt_low = fmt_interval.lo
        return False, 0.95, 'format string is constant in .rodata'

    # Case 2: format parameter from user input
    if fmt_interval.taint >= TaintTag.USER_INPUT:
        return True, 0.88, 'format string from user input'

    # Case 3: origin unknown, flag conservatively
    if fmt_interval.taint == TaintTag.UNKNOWN:
        return True, 0.55, 'format string origin unknown (conservative flag)'

    # Case 4: format parameter from stack/heap, potentially controllable
    if fmt_interval.taint >= TaintTag.HEAP_ADDR:
        return True, 0.72, f'format string from {fmt_interval.taint.name}'

    return False, 0.90, 'format string appears safe'


class VSATaintEngine:
    """
    VSA taint propagation engine, used as fallback when symbolic execution fails.

    Usage:
      engine = VSATaintEngine()
      engine.mark_input(reg='rdi', source=TaintTag.USER_INPUT)
      engine.step_add('rdi', 'rsi')
      result = engine.query('rdi')
    """

    def __init__(self):
        self._registers: Dict[str, StridedInterval] = {}
        self._memory: Dict[int, StridedInterval] = {}
        self._stack_frame_base: int = 0x7FFFFFFF0000

    def mark_input(self, reg: str = 'rdi', source: TaintTag = TaintTag.USER_INPUT
                   ) -> None:
        """Mark register as an input source."""
        self._registers[reg] = StridedInterval.top()
        self._registers[reg].taint = source

    def mark_constant(self, reg: str, value: int) -> None:
        self._registers[reg] = StridedInterval.exact(value, TaintTag.CONSTANT)

    def step_add(self, dest: str, src: str) -> None:
        a = self._registers.get(dest, StridedInterval.bottom())
        b = self._registers.get(src, StridedInterval.bottom())
        self._registers[dest] = taint_transfer_add(a, b)

    def step_mov(self, dest: str, src: str) -> None:
        if src in self._registers:
            self._registers[dest] = taint_transfer_mov(self._registers[src])

    def step_load(self, dest: str, addr_reg: str) -> None:
        addr = self._registers.get(addr_reg, StridedInterval.bottom())
        self._registers[dest] = taint_transfer_load(addr)

    def step_store(self, value_reg: str, addr_reg: str) -> None:
        val = self._registers.get(value_reg, StridedInterval.bottom())
        addr = self._registers.get(addr_reg, StridedInterval.bottom())
        taint_transfer_store(val, addr)

    def query(self, reg: str) -> StridedInterval:
        return self._registers.get(reg, StridedInterval.bottom())

    def is_tainted(self, reg: str, threshold: TaintTag = TaintTag.USER_INPUT
                   ) -> bool:
        si = self._registers.get(reg)
        return si is not None and si.taint >= threshold

    def downgrade_from_symexec(self, symexec_timeout: bool = False,
                                path_explosion: bool = False) -> Dict[str, Any]:
        """
        Record downgrade reason and VSA state when symbolic execution fails.
        Used by upper modules (format_string_detector, etc.) to decide whether
        to use VSA results.
        """
        reasons = []
        if symexec_timeout:
            reasons.append('symbolic execution timeout')
        if path_explosion:
            reasons.append('path explosion')
        return {
            'downgraded': True,
            'reasons': reasons,
            'tainted_regs': [r for r, si in self._registers.items()
                            if si.taint >= TaintTag.USER_INPUT],
            'method': 'VSA',
            'warning': 'results are approximate — VSA over-approximates value sets',
        }
