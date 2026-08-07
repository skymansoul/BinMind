"""INT-RANGE 区间传播引擎 — 寄存器+栈槽区间追踪 + IO2BO链检测.

逐指令分析objdump: imul/add/sub/shl→区间算术, mov/lea→传播, [rbp+off]→栈槽,
malloc/calloc→溢出判定, IO2BO链检测. 创建: 2026-08-07.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

try:
    from .interval_domain import (
        Interval, BitWidth, Signedness,
        abstract_add_const, abstract_mul, abstract_shl_const,
        abstract_imul_const)
except ImportError:
    from interval_domain import (Interval, BitWidth, Signedness,  # type: ignore
        abstract_add_const, abstract_mul, abstract_shl_const,
        abstract_imul_const)

_REG_32_TO_64 = {
    'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi',
    'r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11','r12d':'r12',
    'r13d':'r13','r14d':'r14','r15d':'r15'}
_REG_32 = set(_REG_32_TO_64.keys())
_ALLOC_FNS = {'malloc','calloc','realloc','_malloc','HeapAlloc','HeapReAlloc'}
_IO_SINKS = {'memcpy','memmove','strcpy','strcat','sprintf','snprintf',
             'read','fread','recv'}
_ADDR_RE = re.compile(r'\s*([0-9a-f]+):\s+')

def _canon64(r: str) -> str:
    return _REG_32_TO_64.get(r.lower(), r.lower())

@dataclass
class RegState:
    intervals: Dict[str, Interval] = field(default_factory=dict)
    stack_slots: Dict[int, Interval] = field(default_factory=dict)

    def get(self, reg: str) -> Interval:
        r = _canon64(reg)
        if r in self.intervals:
            return self.intervals[r]
        # 未初始化的寄存器 → TOP (不假设 [0,0xFFFFFFFF], 会掩蔽函数参数溢出)
        return Interval.make_top()

    def set(self, reg: str, iv: Interval):
        self.intervals[_canon64(reg)] = iv

    def kill(self, reg: str):
        self.intervals[_canon64(reg)] = Interval.make_top()

@dataclass
class OverflowSite:
    insn_addr: int
    overflow_type: str  # MUL_WRAP, ADD_WRAP, TRUNCATION, IO2BO
    result_interval: Interval
    sink_func: str = ""
    sink_addr: int = 0
    dest_width: BitWidth = BitWidth.BIT32
    signedness: Signedness = Signedness.UNSIGNED
    confidence: float = 0.5
    reason: str = ""
    io2bo: bool = False
    alloc_interval: Interval = field(default_factory=Interval)
    buffer_overflow_offset: int = 0

@dataclass
class RangeReport:
    overflow_sites: List[OverflowSite]
    total_instructions: int
    alloc_sites_found: int
    io2bo_chains: List[OverflowSite]
    safe_allocations: int

class RangePropagationEngine:
    """逐指令区间传播+溢出检测+IO2BO链追踪."""

    _MUL_PAT = re.compile(
        r'(imul|mul)\s+(\w+),?\s*(\w+)?,?\s*(0x[0-9a-f]+|\d+)?', re.I)
    _ADD_PAT = re.compile(r'add\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _SUB_PAT = re.compile(r'sub\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _SHL_PAT = re.compile(r'shl\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _SHL_CL_PAT = re.compile(r'shl\s+(\w+),\s*cl\b', re.I)
    _MOV_RR_PAT = re.compile(r'mov\s+(\w+),\s*(\w+)\s*$', re.I)
    _MOV_RI_PAT = re.compile(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', re.I)
    _MOV_MEM_PAT = re.compile(
        r'mov\s+(\w+),\s*(?:qword|dword|word|byte)\s+ptr\s+'
        r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', re.I)
    _MOV_TO_MEM_PAT = re.compile(
        r'mov\s+(?:qword|dword|word|byte)\s+ptr\s+'
        r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\],\s*(\w+)', re.I)
    _LEA_PAT = re.compile(
        r'lea\s+(\w+),\s*\[(\w+)\s*(?:\+\s*(\w+)\s*\*\s*(\d+))?\s*'
        r'(?:([+\-])\s*(0x[0-9a-f]+|\d+))?\]', re.I)
    _XOR_PAT = re.compile(r'xor\s+(\w+),\s*\1\b', re.I)
    _CALL_PAT = re.compile(
        r'call\s+(?:[0-9a-f]+\s+<)?([^>\s]+)(?:@plt)?>?', re.I)

    def __init__(self):
        self._state = RegState()
        self._buffer_regs: Dict[str, Tuple[Interval, int]] = {}

    def analyze(self, objdump_lines: List[str]) -> RangeReport:
        self._state = RegState()
        self._buffer_regs.clear()
        overflow_sites: List[OverflowSite] = []
        alloc_count, safe_allocs = 0, 0
        for i, line in enumerate(objdump_lines):
            il = line.strip().lower()
            if not il:
                continue
            addr_m = _ADDR_RE.match(line)
            insn_addr = int(addr_m.group(1), 16) if addr_m else i
            if 'call' in il:
                sites, is_alloc, is_safe = self._handle_call(il, insn_addr)
                overflow_sites.extend(sites)
                if is_alloc:
                    alloc_count += 1
                    if is_safe:
                        safe_allocs += 1
                continue
            if 'ret' in il:
                continue
            self._propagate_instruction(il)
        return RangeReport(
            overflow_sites=sorted(overflow_sites, key=lambda s: -s.confidence),
            total_instructions=len(objdump_lines),
            alloc_sites_found=alloc_count,
            io2bo_chains=[s for s in overflow_sites if s.io2bo],
            safe_allocations=safe_allocs)

    def _propagate_instruction(self, il: str):
        m = self._MOV_RI_PAT.search(il)
        if m:
            v = int(m.group(2), 0)
            self._state.set(m.group(1), Interval(lo=v, hi=v)); return
        m = self._MOV_RR_PAT.search(il)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in ('rbp','rsp','rip'):
                self._state.kill(dst); return
            iv = self._state.get(src)
            if dst in _REG_32 and iv.is_finite():
                iv = Interval(lo=iv.lo & 0xFFFFFFFF,
                    hi=iv.hi & 0xFFFFFFFF if iv.hi < Interval.TOP else Interval.TOP)
            self._state.set(dst, iv); return
        m = self._XOR_PAT.search(il)
        if m:
            self._state.set(m.group(1), Interval(lo=0, hi=0)); return
        m = self._LEA_PAT.search(il)
        if m:
            self._handle_lea(m); return
        m = self._MOV_MEM_PAT.search(il)
        if m:
            sign = -1 if m.group(3)=='-' else 1
            off = sign * int(m.group(4), 0)
            iv = self._state.stack_slots.get(off, Interval.make_top()) \
                if m.group(2) == 'rbp' else Interval.make_top()
            self._state.set(m.group(1), iv); return
        m = self._MOV_TO_MEM_PAT.search(il)
        if m:
            sign = -1 if m.group(2)=='-' else 1
            off = sign * int(m.group(3), 0)
            self._state.stack_slots[off] = self._state.get(m.group(4)); return
        m = self._ADD_PAT.search(il)
        if m:
            iv = self._state.get(m.group(1))
            self._state.set(m.group(1),
                abstract_add_const(iv, int(m.group(2), 0))); return
        m = self._SUB_PAT.search(il)
        if m:
            iv = self._state.get(m.group(1)); imm = int(m.group(2), 0)
            self._state.set(m.group(1),
                iv.sub(Interval(lo=imm, hi=imm))); return
        m = self._SHL_PAT.search(il)
        if m:
            iv = self._state.get(m.group(1))
            self._state.set(m.group(1),
                abstract_shl_const(iv, int(m.group(2), 0))); return
        m = self._SHL_CL_PAT.search(il)
        if m:
            dst = m.group(1)
            val = self._state.get(dst)
            cl_iv = self._state.get('cl')
            if cl_iv.is_finite():
                lo_shift = max(0, cl_iv.lo) & 0x3F
                hi_shift = min(63, cl_iv.hi) & 0x3F
                lo = val.lo << lo_shift if val.lo >= 0 else val.lo
                hi = val.hi << hi_shift if val.hi >= 0 and val.hi < (1 << 60) else Interval.TOP
            else:
                lo, hi = val.lo if val.lo >= 0 else 0, Interval.TOP
            self._state.set(dst, Interval(lo=lo, hi=hi)); return
        m = self._MUL_PAT.search(il)
        if m:
            self._handle_mul(m)

    @staticmethod
    def _is_reg64(r: str) -> bool:
        return r in {'rax','rbx','rcx','rdx','rsi','rdi',
                     'r8','r9','r10','r11','r12','r13','r14','r15'}

    def _handle_lea(self, m):
        dst = m.group(1); base = m.group(2)
        scale = int(m.group(4)) if m.group(4) else 1
        sgn = -1 if m.group(5)=='-' else 1
        disp = int(m.group(6), 0) if m.group(6) else 0
        result = Interval(lo=disp, hi=disp)
        if base and base not in ('rbp','rsp','rip'):
            result = result.add(self._state.get(base))
        if m.group(3):
            w = BitWidth.BIT64 if self._is_reg64(m.group(3)) else BitWidth.BIT32
            result = result.add(
                abstract_imul_const(self._state.get(m.group(3)), scale, w))
        self._state.set(dst, result)

    def _handle_mul(self, m):
        g = m.groups()
        dst = g[1] if g[1] else 'rax'
        w = BitWidth.BIT64 if self._is_reg64(dst) else BitWidth.BIT32
        if g[3]:  # imul dst, src, imm
            self._state.set(dst,
                abstract_imul_const(self._state.get(g[2]), int(g[3], 0), w))
        elif g[2]:  # imul dst, src
            r = abstract_mul(self._state.get(g[1]), self._state.get(g[2]))
            self._state.set(dst, r)
            if g[0]=='mul' and dst=='rax':
                self._state.set('rdx', Interval.make_top())
        else:  # mul src
            r = abstract_mul(self._state.get('rax'), self._state.get(g[1]))
            self._state.set('rax', r)
            if g[0]=='mul':
                self._state.set('rdx', Interval.make_top())

    def _handle_call(self, il: str, addr: int,
                     ) -> Tuple[List[OverflowSite], bool, bool]:
        m = self._CALL_PAT.search(il)
        if not m:
            return [], False, False
        func = m.group(1).lower()
        for af in _ALLOC_FNS:
            if af not in func:
                continue
            sites = (self._check_calloc_overflow(func, addr)
                     if af == 'calloc'
                     else self._check_alloc_overflow(func, addr))
            if sites:
                self._buffer_regs['rax'] = (Interval(
                    lo=0, hi=0xFFFFFFFF), addr)
                return sites, True, False
            else:
                sz = self._state.get('rcx')
                if sz.is_finite():
                    self._buffer_regs['rax'] = (sz, addr)
                return [], True, True
        for sf in _IO_SINKS:
            if sf in func:
                return self._check_io2bo_overflow(func, addr), False, False
        for r in ['rax','rcx','rdx','r8','r9','r10','r11']:
            self._state.kill(r)
        return [], False, False

    def _check_alloc_overflow(self, func: str, addr: int) -> List[OverflowSite]:
        iv = self._state.get('rcx')
        if iv.is_top():
            conf, reason = 0.35, 'malloc(unknown) → overflow possible'
        else:
            may32, r32 = iv.can_overflow(BitWidth.BIT32)
            may64, _ = iv.can_overflow(BitWidth.BIT64)
            if may32 and not may64:
                conf, reason = 0.70, f'malloc([{iv}]) may overflow uint32: {r32}'
            elif may64:
                conf, reason = 0.85, f'malloc([{iv}]) may overflow uint64'
            else:
                return []
        return [OverflowSite(insn_addr=addr, overflow_type='MUL_WRAP',
            result_interval=iv, sink_func=func, sink_addr=addr,
            confidence=conf, reason=reason, alloc_interval=iv)]

    def _check_calloc_overflow(self, func: str, addr: int) -> List[OverflowSite]:
        prod = abstract_mul(self._state.get('rcx'), self._state.get('rdx'))
        if prod.is_top():
            conf, reason = 0.35, 'calloc unknown operands'
        else:
            may32, r32 = prod.can_overflow(BitWidth.BIT32)
            may64, _ = prod.can_overflow(BitWidth.BIT64)
            if may32 and not may64:
                conf, reason = 0.75, f'calloc([{prod}]) may overflow uint32'
            elif may64:
                conf, reason = 0.85, f'calloc([{prod}]) may overflow uint64'
            else:
                return []
        return [OverflowSite(insn_addr=addr, overflow_type='MUL_WRAP',
            result_interval=prod, sink_func=func, sink_addr=addr,
            confidence=conf, reason=reason, alloc_interval=prod)]

    def _check_io2bo_overflow(self, func: str, addr: int) -> List[OverflowSite]:
        n_iv = self._state.get('r8')
        return [OverflowSite(insn_addr=addr, overflow_type='IO2BO',
            result_interval=n_iv, sink_func=func, sink_addr=addr,
            confidence=0.75, io2bo=True, alloc_interval=aiv,
            reason=f'{func} size={n_iv} into buf[{aiv}] → overflow',
            buffer_overflow_offset=n_iv.hi - aiv.lo)
            for _, (aiv, _) in self._buffer_regs.items()
            if n_iv.is_finite() and aiv.is_finite() and n_iv.hi > aiv.hi]

# smoke
def _check():
    eng = RangePropagationEngine()
    r = eng.analyze(["  401000:\tmov    ecx,0x400",
        "  401005:\tmov    edx,0x300", "  40100a:\timul   ecx,edx",
        "  40100d:\tmov    edx,ecx", "  40100f:\tcall   401100 <malloc>"])
    for s in r.overflow_sites: print(f"  OVERFLOW: {s.reason}")
    print(f"  Alloc: {r.alloc_sites_found}, Safe: {r.safe_allocations}")
    r2 = RangePropagationEngine().analyze([
        "  402000:\tmov    ecx,0x40000000",
        "  402005:\tmov    edx,0x10",
        "  40200a:\tcall   402100 <calloc>"])
    for s in r2.overflow_sites:
        print(f"  CALLOC OVERFLOW: {s.reason}")
    print("[OK] range_propagation tests passed")

if __name__ == "__main__":
    _check()
