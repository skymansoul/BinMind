"""Fmt-OG 集成压缩 — printf 族调用点三态判决.

对每个 printf 族调用按证据优先级求值:
  常量串 (%n 检查 → 参数契约) > 输入源身份 > 包装透传溯源.
包装透传: vprintf 族 fmt 为参数透传时, 沿函数标签定位 caller 实参
定义链, 常量实参 → 压制, 输入源实参 → 确认.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ...heap.acfpc.def_chain import DefChainTracker, DefKind, DefNode
from .spec_counter import count_specs, required_args
from .verdict import FmtSynthesizer, FmtVerdict, FmtVerdictKind
from .fmt_contract import (FmtCallExtractor, FmtCall, INPUT_SOURCES,
                           PRINTF_FAMILY)

VPRINTF_FAMILY = ('vprintf', 'vsprintf', 'vsnprintf', 'vfwprintf',
                  'vswprintf', '__mingw_vfprintf', '__mingw_vprintf')


@dataclass
class FmtStats:
    total: int = 0
    in_range: int = 0        # 用户区间内调用数 (base 口径)
    suppressed: int = 0
    confirmed: int = 0
    unchanged: int = 0
    reasons: Dict[str, int] = field(default_factory=dict)


@dataclass
class FmtResult:
    kept: List = field(default_factory=list)
    suppressed: List = field(default_factory=list)
    stats: FmtStats = field(default_factory=FmtStats)


class FmtCompressor:
    """格式化字符串误报压缩器."""

    def __init__(self):
        self._synth = FmtSynthesizer()

    def compress(self, instructions: List[str],
                 addrs: Optional[List[int]] = None,
                 labels: Optional[List[Tuple[str, int]]] = None,
                 rdata: Optional[Dict[int, str]] = None,
                 user_range: Optional[Tuple[int, int]] = None,
                 import_map: Optional[Dict[int, str]] = None) -> FmtResult:
        tracker = DefChainTracker()
        if import_map:
            tracker.set_import_map(import_map)
        tracker.scan(instructions, addrs)
        extractor = FmtCallExtractor(tracker, rdata)
        calls = extractor.extract(instructions, addrs)

        result = FmtResult()
        result.stats.total = len(calls)
        # stripped 无 main 标签时按地址阈值划用户代码区
        crt_hi = 0x140003000 if user_range is None else None
        for c in calls:
            if crt_hi is not None and c.addr >= crt_hi:
                continue
            if user_range is not None:
                in_main = user_range[0] <= c.insn_idx < user_range[1]
                if not in_main and c.func not in VPRINTF_FAMILY:
                    # 区间外仅保留 vprintf 族 (wrapper 漏洞载体),
                    # CRT 内部 printf 调用一律跳过
                    continue
            result.stats.in_range += 1
            verdict = self._judge(tracker, instructions, addrs, labels, c)
            if verdict.kind == FmtVerdictKind.SUPPRESS:
                result.stats.suppressed += 1
                result.stats.reasons['suppress'] = \
                    result.stats.reasons.get('suppress', 0) + 1
                result.suppressed.append({
                    'insn_idx': c.insn_idx, 'addr': c.addr,
                    'func': c.func, 'verdict': 'SUPPRESS',
                    'reason': verdict.reason,
                })
            elif verdict.kind == FmtVerdictKind.CONFIRM:
                result.stats.confirmed += 1
                result.stats.reasons['confirm'] = \
                    result.stats.reasons.get('confirm', 0) + 1
                result.kept.append({
                    'insn_idx': c.insn_idx, 'addr': c.addr,
                    'func': c.func, 'verdict': 'CONFIRM',
                    'reason': verdict.reason,
                    'confidence': 0.85,
                })
            else:
                result.stats.unchanged += 1
                result.kept.append({
                    'insn_idx': c.insn_idx, 'addr': c.addr,
                    'func': c.func, 'verdict': 'UNCHANGED',
                    'reason': verdict.reason,
                    'confidence': 0.5,
                })
        return result

    def _judge(self, tracker: DefChainTracker, instructions: List[str],
               addrs: Optional[List[int]], labels: Optional[List],
               c: FmtCall) -> FmtVerdict:
        if c.fmt_const:
            specs = count_specs(c.fmt_const)
            if specs.n_count > 0:
                return self._synth.const_safe(c.fmt_const,
                                              specs.n_count)
            req = required_args(c.fmt_const)
            return self._synth.args_match(c.fmt_const, req,
                                          c.args_available)
        if c.return_src in INPUT_SOURCES:
            return self._synth.input_sink(f'ret:{c.return_src}')
        if c.fmt_identity.startswith('ret:'):
            src = c.fmt_identity[4:]
            if src in INPUT_SOURCES:
                return self._synth.input_sink(c.fmt_identity)
            return self._synth.unchanged(f'返回值 {src} 非输入源')
        if c.func in VPRINTF_FAMILY and (
                c.fmt_kind == DefKind.ARG or
                c.fmt_identity.startswith('slot:rbp+')):
            return self._wrapper_trace(tracker, instructions, labels, c)
        if c.fmt_identity.startswith('slot:') or \
                c.fmt_kind in (DefKind.SLOT, DefKind.MEM, DefKind.ARG):
            return self._synth.user_fmt()
        return self._synth.unchanged()

    def _wrapper_trace(self, tracker, instructions, labels, c) -> FmtVerdict:
        """vprintf 透传: 沿函数标签定位 caller 实参定义链."""
        if not labels:
            return self._synth.unchanged('无函数标签, 无法溯源')
        func_name = self._func_at(labels, c.insn_idx)
        if not func_name:
            return self._synth.unchanged('vprintf 所在函数未知')
        for snap in tracker.calls():
            if snap.callee != func_name:
                continue
            if snap.insn_idx <= c.insn_idx:
                continue
            arg = snap.args.get('rcx')
            if arg is None:
                continue
            root = tracker.resolve(arg)
            if root.kind == DefKind.IMM and root.imm:
                return self._synth.const_safe(
                    f'caller 常量实参 {root.imm:#x}', 0)
            if root.kind == DefKind.DERIVED and \
                    '[rip' in root.derived_op.lower():
                return self._synth.const_safe('caller lea 常量实参', 0)
            ident = tracker.identity(arg)
            if ident.startswith('ret:'):
                src = ident[4:]
                if src in INPUT_SOURCES:
                    return self._synth.input_sink(ident)
            return self._synth.unchanged('caller 实参非常量')
        return self._synth.unchanged('未找到 caller 调用点')

    def _func_at(self, labels: List[Tuple[str, int]],
                 insn_idx: int) -> str:
        name = ''
        for fname, idx in labels:
            if idx <= insn_idx:
                name = fname
            else:
                break
        return name
