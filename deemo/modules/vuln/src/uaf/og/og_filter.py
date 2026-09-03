"""UAF-OG 集成过滤 — 代际判决与压缩.

free→use 三态判决: SAME_GEN 同代际确认, DIFF_GEN 指针已指向新对象
压制, UNKNOWN 保守保留. 判决支持位置敏感 use 代际 (重放指令流到
use 点, 规避最终态被后续指令覆盖). 跨函数参数槽↔实参寄存器代际
绑定内置于本模块.
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .gen_state import GenState, SlotGen, GEN_UNKNOWN
from .gen_flow import GenFlowTracker, slot_name
from .gen_verify import GenVerifier, GenVerdict, GenProof

_WIN64 = ('rcx', 'rdx', 'r8', 'r9')
_SYSV = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')

@dataclass
class ParamBinding:
    """一条参数绑定: callee 参数槽 ↔ caller 实参代际."""
    callee_slot: str
    caller_reg: str
    gen: int
    source: str
    call_idx: int
    func_idx: int


def _func_headers(instructions: List[str],
                  addrs: Optional[List[int]]) -> List[int]:
    """函数入口索引: 符号标签后紧跟 push rbp 的指令位置.

    线性流中函数边界由 '<sym>:' 标签行标记, 但指令列表已剥离标签,
    以 'push rbp' 起始的连续块近似."""
    headers = []
    prev_push = False
    for i, line in enumerate(instructions):
        s = line.strip()
        if s.startswith('push') and 'rbp' in s:
            if not prev_push:
                headers.append(i)
            prev_push = True
        else:
            prev_push = False
    return headers


def _param_slots(instructions: List[str], header: int,
                 window: int = 12) -> Dict[str, str]:
    """函数入口处参数槽映射: 参数寄存器 → 栈槽.

    匹配 'mov [rbp+0x10], rcx' 形式 (Win64 前 4 参数 rbp+0x10..0x28).
    返回 {slot: reg}."""
    mapping = {}
    for i in range(header, min(header + window, len(instructions))):
        line = instructions[i].strip()
        parts = line.split(None, 1)
        if len(parts) < 2 or parts[0].lower() != 'mov':
            continue
        dst, src = (x.strip() for x in parts[1].split(',', 1))
        sl = slot_name(dst)
        if sl and sl.startswith('rbp+'):
            reg = src.split()[0].strip('*')
            mapping[sl] = reg
    return mapping


class CallGenPropagator:
    """调用边界代际传播器."""

    def __init__(self, abi: str = 'win64'):
        self._abi = abi
        self._bindings: List[ParamBinding] = []

    def run(self, instructions: List[str], tracker: GenFlowTracker,
            addrs: Optional[List[int]] = None) -> None:
        """绑定全部调用点的参数槽代际."""
        headers = _func_headers(instructions, addrs)
        calls = tracker.calls()
        if not calls:
            return
        # 为每个 call 找到它所在的函数 (call 索引前的最近 header)
        for c in calls:
            params = c.args.get('params', {})
            if not params:
                continue
            callee_header = None
            for h in reversed(headers):
                if h < c.idx:
                    callee_header = h
                    break
            if callee_header is None:
                continue
            slot_map = _param_slots(instructions, callee_header)
            regs = _WIN64 if self._abi == 'win64' else _SYSV
            for slot, reg in slot_map.items():
                if reg in params:
                    gen, source = params[reg]
                    self._bindings.append(ParamBinding(
                        callee_slot=slot, caller_reg=reg,
                        gen=gen, source=source,
                        call_idx=c.idx, func_idx=callee_header))

    def resolve(self, slot: str, def_idx: int) -> Optional[ParamBinding]:
        """查询参数槽的最近绑定 (按 call 位置)."""
        best = None
        for b in self._bindings:
            if b.callee_slot == slot and b.call_idx < def_idx:
                if best is None or b.call_idx > best.call_idx:
                    best = b
        return best

    def bindings(self) -> List[ParamBinding]:
        return self._bindings


@dataclass
class OgStats:
    total: int = 0
    same_gen: int = 0
    diff_gen: int = 0
    unknown: int = 0
    reasons: Dict[str, int] = field(default_factory=dict)


@dataclass
class OgResult:
    kept: List = field(default_factory=list)
    suppressed: List = field(default_factory=list)
    stats: OgStats = field(default_factory=OgStats)


def _get(f: dict, *keys, default=None):
    for k in keys:
        if k in f and f[k] is not None:
            return f[k]
    return default


def _base_reg(op: str) -> Optional[str]:
    m = re.search(r'\[([a-z0-9]+)', op, re.I)
    return m.group(1) if m else None


class OgFilter:
    """UAF 对象代际误报压缩器."""

    def __init__(self, abi: str = 'win64'):
        self._abi = abi

    def _use_carrier(self, line: str):
        """use 行载体: ('reg', reg) / ('slot', slot) / (None, None)."""
        if '[' in line and ']' in line:
            inner = line[line.index('[') + 1:line.index(']')]
            sl = slot_name(f'[{inner}]')
            if sl:
                return 'slot', sl
            reg = _base_reg(line)
            return ('reg', reg) if reg else (None, None)
        parts = line.split(None, 1)
        if len(parts) < 2:
            return None, None
        dst = parts[1].split(',', 1)[0].strip().split()[0]
        if dst in ('rax', 'eax', 'rcx', 'ecx', 'rdx', 'edx', 'r8', 'r8d',
                   'r9', 'r9d', 'rsi', 'esi', 'rdi', 'edi', 'rbx', 'ebx'):
            return 'reg', dst
        return None, None

    def _free_gen_of(self, ev, free_reg: str) -> int:
        params = ev.args.get('params', {})
        if free_reg and free_reg in params:
            return params[free_reg][0]
        for reg in ('rcx', 'rdi'):
            if reg in params:
                return params[reg][0]
        return GEN_UNKNOWN

    # TODO: 预计算 use 行位置快照, 避免逐 finding 全量重放
    def _use_gen(self, instructions: List[str], use_line: int,
                 carrier: Tuple[Optional[str], Optional[str]],
                 addrs: Optional[List[int]]) -> int:
        """重放到 use_line-1, 取载体代际."""
        t = GenFlowTracker()
        t.run(instructions[:use_line], addrs[:use_line] if addrs else None)
        kind, val = carrier
        if kind == 'slot':
            return t.state.slot(val).gen
        if kind == 'reg':
            return t.state.reg(val).gen
        return GEN_UNKNOWN

    def compress(self, instructions: List[str], findings: List,
                 addrs: Optional[List[int]] = None,
                 import_map: Optional[Dict[int, str]] = None) -> OgResult:
        tracker = GenFlowTracker()
        if import_map:
            tracker.set_import_map(import_map)
        tracker.run(instructions, addrs)
        verifier = GenVerifier(tracker.state)
        free_events = tracker.free_events()

        result = OgResult()
        free_by_line: Dict[int, list] = {}
        for ev in free_events:
            free_by_line.setdefault(ev.idx, []).append(ev)

        for f in findings:
            if not isinstance(f, dict):
                result.kept.append(f)
                continue
            result.stats.total += 1
            free_line = _get(f, 'free_line', 'free_idx', default=-1)
            use_line = _get(f, 'use_line', 'use_idx', default=-1)
            if not isinstance(free_line, int) or not isinstance(use_line, int) \
                    or free_line < 0 or use_line < 0:
                result.kept.append(f)
                result.stats.unknown += 1
                continue

            ev = None
            for d in range(4):
                if free_line + d in free_by_line:
                    ev = free_by_line[free_line + d][0]
                    break
                if free_line - d in free_by_line:
                    ev = free_by_line[free_line - d][0]
                    break
            if ev is None:
                result.kept.append(f)
                result.stats.unknown += 1
                continue

            use_reg = _get(f, 'use_reg', 'use_ptr_reg', default=None)
            use_slot = _get(f, 'use_slot', default=None)
            if use_reg is None and use_slot is None:
                if 0 <= use_line < len(instructions):
                    kind, val = self._use_carrier(instructions[use_line])
                    if kind == 'reg':
                        use_reg = val
                    elif kind == 'slot':
                        use_slot = val
            if use_reg is None and use_slot is None:
                result.kept.append(f)
                result.stats.unknown += 1
                continue

            free_reg = ev.args.get('free_reg', '')
            fg = self._free_gen_of(ev, free_reg)
            ug = GEN_UNKNOWN
            if use_slot is not None:
                ug = self._use_gen(instructions, use_line,
                                   ('slot', use_slot), addrs)
                proof = verifier.verify_slot_pair(use_slot, fg, use_slot,
                                                  use_gen=ug)
            else:
                ug = self._use_gen(instructions, use_line,
                                   ('reg', use_reg), addrs)
                proof = verifier.verify_free_event(ev, use_reg,
                                                   use_gen=ug)

            if proof.verdict == GenVerdict.SAME_GEN:
                result.stats.same_gen += 1
                f['confidence'] = max(f.get('confidence', 0.5), 0.85)
                f['og_verdict'] = 'SAME_GEN'
                result.kept.append(f)
            elif proof.verdict == GenVerdict.DIFF_GEN:
                result.stats.diff_gen += 1
                result.stats.reasons['diff_gen'] = \
                    result.stats.reasons.get('diff_gen', 0) + 1
                f['og_verdict'] = 'DIFF_GEN'
                f['og_reason'] = proof.reason
                result.suppressed.append(f)
            else:
                result.stats.unknown += 1
                result.kept.append(f)
        return result
